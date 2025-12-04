# Build stage
FROM rust:1.75 AS builder

WORKDIR /app

# Install OpenSSL development libraries
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install OpenSSL runtime library
RUN apt-get update && apt-get install -y \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /app/target/release/telegram-password-bot /app/telegram-password-bot

# Set binary as entrypoint
ENTRYPOINT ["/app/telegram-password-bot"]
