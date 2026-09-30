#!/usr/bin/env bash
# Runs inside the LocalStack container once it is ready.
set -euo pipefail

awslocal s3api create-bucket --bucket di-migration-pcp

awslocal dynamodb create-table \
  --table-name di-migration \
  --attribute-definitions AttributeName=migration_id,AttributeType=S \
  --key-schema AttributeName=migration_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST

awslocal sqs create-queue --queue-name di-migration

key_id="$(awslocal kms create-key \
  --key-spec ECC_NIST_P256 \
  --key-usage SIGN_VERIFY \
  --description "Signs local proof-verification JWTs" \
  --query KeyMetadata.KeyId \
  --output text)"
awslocal kms create-alias \
  --alias-name alias/di-migration-proof \
  --target-key-id "$key_id"
