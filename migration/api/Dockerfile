# syntax=docker/dockerfile:1

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder
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
FROM busybox:1.37.0-musl AS runtime
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/host-bin /usr/local/bin/migration-api

USER 65532

EXPOSE 8080 8081

ENTRYPOINT ["/usr/local/bin/migration-api"]
