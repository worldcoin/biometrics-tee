# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl@sha256:3f1010eb48311dfde5d51f011163451940af34bd317355c4a8652ce6b4b61051 AS builder
USER root
WORKDIR /app

COPY . .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package migration-api \
 && mv target/x86_64-unknown-linux-musl/release/migration-api /app/host-bin

# The common-app chart's preStop hook requires /bin/sh and sleep.
FROM busybox:1.37.0-musl@sha256:f6a95d611e0a8780fabdb2aec43e31275b2720dfefa3e41b16835bfc42454478 AS runtime
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/host-bin /usr/local/bin/migration-api

USER 65532

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/migration-api"]
