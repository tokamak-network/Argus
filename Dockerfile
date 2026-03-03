FROM rust:1.85-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml ./
COPY src/ src/
COPY examples/ examples/

RUN cargo build --release --examples

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/examples/sentinel_realtime_demo /usr/local/bin/
COPY --from=builder /app/target/release/examples/reentrancy_demo /usr/local/bin/
COPY --from=builder /app/target/release/examples/sentinel_dashboard_demo /usr/local/bin/

ENTRYPOINT ["sentinel_realtime_demo"]
