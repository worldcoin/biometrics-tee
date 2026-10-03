#!/usr/bin/env bash
# Runs the migration API against the LocalStack stack from docker-compose.yml.
set -euo pipefail

cd "$(dirname "$0")/.."

export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_ENDPOINT_URL=http://localhost:4566

export HTTP_ADDR=127.0.0.1:8080
# 8081 is taken by the local proof-verification stand-in.
export INTERNAL_HTTP_ADDR=127.0.0.1:8082
export DYNAMODB_TABLE_NAME=di-migration
export PCP_BUCKET=di-migration-pcp
# A locally running di-migration-host on its default port.
export HOST_SERVICE="${HOST_SERVICE:-localhost}"
export HOST_PORT="${HOST_PORT:-8000}"
export S3_FORCE_PATH_STYLE=true
export ENCLAVE_ID=local-stub-enclave
# LocalStack has no Nitro enclave to attest; never set this outside local runs.
export STUB_ATTESTATION=true
# LocalStack alias created by scripts/localstack-init.sh. KMS Sign accepts an alias as a key id.
export PROOF_JWT_KMS_KEY_ID=alias/di-migration-proof
# nginx service in docker-compose.yml. It accepts every POST /api/v4/verify.
export PROOF_VERIFICATION_HOST="${PROOF_VERIFICATION_HOST:-http://127.0.0.1:8081}"

exec cargo run -p migration-api "$@"
