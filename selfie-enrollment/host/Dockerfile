# syntax=docker/dockerfile:1

FROM ghcr.io/rust-cross/rust-musl-cross:x86_64-musl AS builder
USER root
WORKDIR /app

COPY . .
RUN rustup show \
 && rustup target add x86_64-unknown-linux-musl
RUN cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package selfie-enrollment-host \
 && mv target/x86_64-unknown-linux-musl/release/selfie-enrollment-host /app/host-bin

FROM scratch AS runtime
WORKDIR /app

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/host-bin /usr/local/bin/selfie-enrollment-host

USER 65532

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/selfie-enrollment-host"]
