FROM ghcr.io/ggerganov/llama.cpp:server

# We need curl and bash for our download script
RUN apt-get update && apt-get install -y curl bash && rm -rf /var/lib/apt/lists/*

COPY start.sh /start.sh
RUN chmod +x /start.sh

# Persistent models directory
VOLUME /models

EXPOSE 8080

ENTRYPOINT ["/start.sh"]
