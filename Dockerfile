FROM rust:1.85-slim

WORKDIR /usr/src/app

RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy source code
COPY . .
RUN cargo build --release

RUN cp /usr/src/app/target/release/kubevirt-actions-runner /usr/local/bin/kubevirt-actions-runner
RUN rm -rf /usr/src/app
ENTRYPOINT ["/usr/local/bin/kubevirt-actions-runner"]
