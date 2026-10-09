//! Browser WebSocket adapter with a bounded incoming queue, deadlines and cancellation.
use crate::{Config, Error, Frame, Transport};
use futures_channel::mpsc;
use futures_util::{
    FutureExt, StreamExt,
    future::{Either, select},
};
use selfie_enrollment_api_types::{MAX_CONTROL_BYTES, MAX_RESPONSE_BYTES};
use std::time::Duration;
use wasm_bindgen::{JsCast, prelude::*};
use web_sys::{AbortSignal, Event, MessageEvent, WebSocket};

enum EventFrame {
    Open,
    Data(Frame),
    Failed,
}
pub struct BrowserTransport {
    socket: WebSocket,
    incoming: mpsc::Receiver<EventFrame>,
    _open: Closure<dyn FnMut(Event)>,
    _message: Closure<dyn FnMut(MessageEvent)>,
    _error: Closure<dyn FnMut(Event)>,
    _close: Closure<dyn FnMut(Event)>,
    abort: Option<(AbortSignal, Closure<dyn FnMut(Event)>)>,
}
impl BrowserTransport {
    pub async fn connect(config: &Config, signal: Option<AbortSignal>) -> Result<Self, Error> {
        config.validate()?;
        if signal.as_ref().is_some_and(AbortSignal::aborted) {
            return Err(Error::Timeout);
        }
        let socket = WebSocket::new(&config.endpoint).map_err(|_| Error::Transport)?;
        socket.set_binary_type(web_sys::BinaryType::Arraybuffer);
        let (sender, incoming) = mpsc::channel(1);
        let mut open_sender = sender.clone();
        let open = Closure::wrap(Box::new(move |_: Event| {
            let _ = open_sender.try_send(EventFrame::Open);
        }) as Box<dyn FnMut(Event)>);
        let mut data_sender = sender.clone();
        let data_socket = socket.clone();
        let message = Closure::wrap(Box::new(move |event: MessageEvent| {
            let data = event.data();
            let frame = if data.is_string() {
                let js_string = js_sys::JsString::from(data);
                if js_string.length() as usize > MAX_CONTROL_BYTES {
                    None
                } else {
                    js_string.as_string().map(Frame::Text)
                }
            } else if let Ok(buffer) = data.dyn_into::<js_sys::ArrayBuffer>() {
                if buffer.byte_length() as usize > MAX_RESPONSE_BYTES {
                    None
                } else {
                    Some(Frame::Binary(js_sys::Uint8Array::new(&buffer).to_vec()))
                }
            } else {
                None
            };
            let event = frame.map(EventFrame::Data).unwrap_or(EventFrame::Failed);
            if data_sender.try_send(event).is_err() {
                let _ = data_socket.close();
            }
        }) as Box<dyn FnMut(MessageEvent)>);
        let mut error_sender = sender.clone();
        let error = Closure::wrap(Box::new(move |_: Event| {
            let _ = error_sender.try_send(EventFrame::Failed);
        }) as Box<dyn FnMut(Event)>);
        let mut close_sender = sender.clone();
        let close = Closure::wrap(Box::new(move |_: Event| {
            let _ = close_sender.try_send(EventFrame::Failed);
        }) as Box<dyn FnMut(Event)>);
        socket.set_onopen(Some(open.as_ref().unchecked_ref()));
        socket.set_onmessage(Some(message.as_ref().unchecked_ref()));
        socket.set_onerror(Some(error.as_ref().unchecked_ref()));
        socket.set_onclose(Some(close.as_ref().unchecked_ref()));
        let abort = if let Some(signal) = signal {
            let abort_socket = socket.clone();
            let mut abort_sender = sender;
            let callback = Closure::wrap(Box::new(move |_: Event| {
                let _ = abort_sender.try_send(EventFrame::Failed);
                let _ = abort_socket.close();
            }) as Box<dyn FnMut(Event)>);
            signal
                .add_event_listener_with_callback("abort", callback.as_ref().unchecked_ref())
                .map_err(|_| Error::Transport)?;
            Some((signal, callback))
        } else {
            None
        };
        let mut transport = Self {
            socket,
            incoming,
            _open: open,
            _message: message,
            _error: error,
            _close: close,
            abort,
        };
        match transport.next(Duration::from_secs(5)).await? {
            EventFrame::Open => Ok(transport),
            _ => Err(Error::Transport),
        }
    }
    async fn next(&mut self, duration: Duration) -> Result<EventFrame, Error> {
        let read = self.incoming.next().boxed_local();
        let timer = gloo_timers::future::TimeoutFuture::new(
            duration.as_millis().min(u32::MAX as u128) as u32,
        )
        .boxed_local();
        match select(read, timer).await {
            Either::Left((Some(event), _)) => Ok(event),
            _ => Err(Error::Timeout),
        }
    }
}
impl Transport for BrowserTransport {
    async fn send(&mut self, frame: Frame, _: Duration) -> Result<(), Error> {
        if self.socket.ready_state() != WebSocket::OPEN || self.socket.buffered_amount() != 0 {
            return Err(Error::Transport);
        }
        match frame {
            Frame::Text(s) => self.socket.send_with_str(&s),
            Frame::Binary(b) => self.socket.send_with_u8_array(&b),
        }
        .map_err(|_| Error::Transport)
    }
    async fn receive(&mut self, duration: Duration) -> Result<Frame, Error> {
        match self.next(duration).await? {
            EventFrame::Data(frame) => Ok(frame),
            _ => Err(Error::Transport),
        }
    }
}
impl Drop for BrowserTransport {
    fn drop(&mut self) {
        self.socket.set_onopen(None);
        self.socket.set_onmessage(None);
        self.socket.set_onerror(None);
        self.socket.set_onclose(None);
        if let Some((signal, callback)) = &self.abort {
            let _ = signal
                .remove_event_listener_with_callback("abort", callback.as_ref().unchecked_ref());
        }
        let _ = self.socket.close();
    }
}

/// `issueTicket(challenge)` calls a trusted test issuer; it must not embed a signing key.
#[wasm_bindgen(js_name=extractEmbedding)]
pub async fn extract_embedding(
    config_json: String,
    image: Vec<u8>,
    issue_ticket: js_sys::Function,
    signal: Option<AbortSignal>,
) -> Result<JsValue, JsValue> {
    let result = async {
        let config: Config = serde_json::from_str(&config_json).map_err(|_| Error::Config)?;
        let mut socket = BrowserTransport::connect(&config, signal).await?;
        let exchange = crate::exchange(&mut socket, &config, image, move |challenge| async move {
            let arg = serde_wasm_bindgen::to_value(&challenge).map_err(|_| Error::Admission)?;
            let value = issue_ticket
                .call1(&JsValue::NULL, &arg)
                .map_err(|_| Error::Admission)?;
            let value = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::resolve(&value))
                .await
                .map_err(|_| Error::Admission)?;
            serde_wasm_bindgen::from_value(value).map_err(|_| Error::Admission)
        })
        .boxed_local();
        let timer = gloo_timers::future::TimeoutFuture::new(100_000).boxed_local();
        let result = match select(exchange, timer).await {
            Either::Left((result, _)) => result?,
            _ => return Err(Error::Timeout),
        };
        serde_wasm_bindgen::to_value(&result).map_err(|_| Error::Protocol)
    }
    .await;
    result.map_err(|e: Error| JsValue::from_str(&e.to_string()))
}
