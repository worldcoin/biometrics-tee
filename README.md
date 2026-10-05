## Deep Identifier Migration 
This repo contains the implementation of the TEE-based migration from iris code-based PCPs to DeepIdentifier-based ones

## PCP mapping

[`di-migration-pcp`](migration/pcp) maps opened legacy PCPs and prepared
biometric outputs into migrated PCPs, using the shared `orb-pcp` builder and
protobuf definitions.

## Migration API

Run `cargo run -p migration-api`. `HTTP_ADDR` defaults to `0.0.0.0:8080`.
Set `DYNAMODB_TABLE_NAME` and configure an AWS region and credentials using the AWS SDK's standard environment or profile settings. The credentials need `dynamodb:DescribeTable` permission on the table.
Set `SQS_QUEUE_URL` to the queue URL. The credentials also need `sqs:GetQueueAttributes` permission on the queue.
Set `PCP_BUCKET` to the bucket PCPs are uploaded to. The credentials need `s3:ListBucket` on the bucket and `s3:PutObject` on its objects. `PRESIGNED_URL_TTL_SECS` defaults to 900, and `S3_FORCE_PATH_STYLE=true` is required for S3-compatible endpoints such as LocalStack.
Set `ENCLAVE_ID` to the enclave the migration runs in. The enclave cannot attest yet, so the API refuses to start unless `STUB_ATTESTATION=true` opts in to an empty attestation — never set it in production.

`GET /healtz` checks the API process. `GET /readyz` describes the configured DynamoDB table, reads the SQS queue attributes and heads the PCP bucket, returning 503 if any request fails or times out.

`POST /v1/init-migration` takes `{"sub": "...", "proof": "...", "challenge_id": "..."}`, records the migration in DynamoDB and returns the enclave id, its attestation and a presigned S3 URL to `PUT` the PCP to. `proof` is the standard-base64 ownership proof, and `challenge_id` is the challenge that proof was built for.

### Testing `/v1/init-migration` locally

Start LocalStack with the bucket, table and queue already created:

```sh
cd migration/api && docker compose up -d
```

Run the API against it in another shell:

```sh
migration/api/scripts/run-local.sh
```

Then call the endpoint through the CLI:

```sh
cargo run -p migration-cli -- init-migration --sub local-test-sub --proof cHJvb2Y= --challenge-id 0b7f6c1e-6d3a-4f77-9c0d-2a1b9d5e4c31
```

It prints the response as JSON. Pass `--upload <FILE>` to also `PUT` that file to the presigned URL, which exercises the whole round trip. `--proof` and `--challenge-id` can also be set with `PROOF` and `CHALLENGE_ID`. `--api-url` (or `API_URL`) points the CLI at another host; it defaults to `http://127.0.0.1:8080`.
