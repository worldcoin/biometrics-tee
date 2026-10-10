// Real browser/WASM tests against adversarial WebSocket events. No attestation bypass.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium, webkit} = require('playwright');
const bindings = path.resolve(process.env.ENROLLMENT_BINDINGS || 'target/enrollment-web');
const config = {endpoint:'ws://127.0.0.1:8000/v1/embeddings',releases:[
  {pcr0:'1'.repeat(96),pcr1:'2'.repeat(96),pcr2:'3'.repeat(96),worker_sha384:'4'.repeat(96)}]};
async function main() {
  const server=http.createServer(async (request,response)=>{
    if(request.url==='/'){response.end('<!doctype html><title>Enrollment transport tests</title>');return}
    const filename=request.url.slice(1);
    if(!['selfie_enrollment_client.js','selfie_enrollment_client_bg.wasm'].includes(filename)){response.writeHead(404).end();return}
    try{const bytes=await fs.readFile(path.join(bindings,filename));response.setHeader('Content-Type',filename.endsWith('.wasm')?'application/wasm':'text/javascript');response.end(bytes)}
    catch{response.writeHead(404).end()}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    for(const [name,engine] of [['chromium',chromium],['webkit',webkit]]) {
      const browser=await engine.launch({headless:true, ...(name==='chromium'?{channel:'chromium'}:{})});
      try {
        for(const mode of ['untrusted','abort-assignment','already-aborted','oversized','flood','invalid-policy']) {
          const page=await browser.newPage();
          try {
            await page.addInitScript(({mode})=>{
              window.transport={created:0,closed:0,sent:[]};
              window.WebSocket=class {
                static OPEN=1;
                readyState=1;bufferedAmount=0;
                constructor(){window.transport.created++;setTimeout(()=>this.onopen?.(new Event('open')),0)}
                send(data){
                  window.transport.sent.push(typeof data==='string'?JSON.parse(data).type:'image');
                  if(mode==='abort-assignment') return;
                  setTimeout(()=>{
                    const assignment=JSON.stringify({type:'assignment',attestation:'AQ==',public_key:'Ag=='});
                    if(mode==='oversized') this.onmessage?.(new MessageEvent('message',{data:'x'.repeat(32769)}));
                    else if(mode==='flood') for(let i=0;i<20;i++) this.onmessage?.(new MessageEvent('message',{data:assignment}));
                    else this.onmessage?.(new MessageEvent('message',{data:assignment}));
                  },0);
                }
                close(){this.readyState=3;window.transport.closed++}
              };
            },{mode});
            await page.goto(`http://127.0.0.1:${server.address().port}/`);
            const result=await page.evaluate(async ({config,mode})=>{
              const module=await import('/selfie_enrollment_client.js');await module.default();
              const controller=new AbortController();
              if(mode==='already-aborted')controller.abort();
              if(mode==='invalid-policy')config.releases[0].pcr0='0'.repeat(96);
              const started=performance.now();
              let error;
              if(mode==='abort-assignment')setTimeout(()=>controller.abort(),30);
              try{await module.extractEmbedding(JSON.stringify(config),new Uint8Array([1,2,3]),controller.signal)}catch(e){error=String(e)}
              return {...window.transport,error,elapsed:performance.now()-started};
            },{config,mode});
            assert.ok(result.error,`${name}/${mode} must fail`);
            assert.equal(result.sent.includes('image'),false,`${name}/${mode} must withhold image`);
            if(['already-aborted','invalid-policy'].includes(mode))assert.equal(result.created,0);
            else assert.ok(result.closed>0,`${name}/${mode} socket cleanup`);
            if(mode==='untrusted')assert.match(result.error,/attestation rejected/);
            if(mode==='abort-assignment'){assert.deepEqual(result.sent,['assignment_request']);assert.ok(result.elapsed<1000,`cancellation took ${result.elapsed}ms`)}
            console.log(`PASS ${name}: ${mode}`);
          } finally {await page.close()}
        }
      } finally {await browser.close()}
    }
  } finally {await new Promise(resolve=>server.close(resolve))}
}
main().catch(error=>{console.error(error);process.exitCode=1});
