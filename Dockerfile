FROM rust:latest AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml ./
COPY src/ src/
COPY examples/ examples/

RUN cargo build --release --examples && \
    cargo build --release --features cli --bin argus

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/argus /usr/local/bin/
COPY --from=builder /app/target/release/examples/sentinel_realtime_demo /usr/local/bin/
COPY --from=builder /app/target/release/examples/reentrancy_demo /usr/local/bin/
COPY --from=builder /app/target/release/examples/sentinel_dashboard_demo /usr/local/bin/

EXPOSE 9090

ENV ARGUS_RPC_URL=""
ENV ARGUS_METRICS_PORT="9090"

ENTRYPOINT ["/bin/sh", "-c"]
CMD ["exec argus sentinel --rpc \"$ARGUS_RPC_URL\" --metrics-port \"$ARGUS_METRICS_PORT\" --prefilter-only"]
