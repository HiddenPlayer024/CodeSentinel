# Base image pinned to immutable digest (tag: server)
# Source: ghcr.io/ggml-org/llama.cpp
FROM ghcr.io/ggml-org/llama.cpp@sha256:bf3da52e92c083472b3d1c9f9da081f423ab9def95a87ec4bba51940382d75fd

# Install required dependencies
RUN apt-get update && apt-get install -y curl ca-certificates bash && rm -rf /var/lib/apt/lists/*

# Create unprivileged user
RUN useradd -m -u 1000 -s /bin/bash appuser

# Create models directory and set permissions
RUN mkdir -p /models && chown -R appuser:appuser /models

COPY start.sh /start.sh
RUN chmod +x /start.sh && chown appuser:appuser /start.sh

# Switch to unprivileged user
USER appuser

# Persistent models directory
VOLUME /models

EXPOSE 8080

ENTRYPOINT ["/start.sh"]
