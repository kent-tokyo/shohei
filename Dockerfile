FROM rust:1.85-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin shohei-mcp

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/shohei-mcp /usr/local/bin/shohei-mcp
ENTRYPOINT ["/usr/local/bin/shohei-mcp"]
