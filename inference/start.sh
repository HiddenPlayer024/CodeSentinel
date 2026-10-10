#!/bin/bash
set -e

# Configuration
MODEL_URL="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf?download=true"
MODEL_CHECKSUM="9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0"
MODEL_PATH="/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"

echo "Checking for model at $MODEL_PATH..."
if [ ! -f "$MODEL_PATH" ]; then
    echo "Model not found. Downloading..."
    curl -L -o "$MODEL_PATH" "$MODEL_URL"
    
    echo "Verifying checksum..."
    ACTUAL_CHECKSUM=$(sha256sum "$MODEL_PATH" | awk '{print $1}')
    if [ "$ACTUAL_CHECKSUM" != "$MODEL_CHECKSUM" ]; then
        echo "Checksum mismatch!"
        echo "Expected: $MODEL_CHECKSUM"
        echo "Actual:   $ACTUAL_CHECKSUM"
        rm -f "$MODEL_PATH"
        exit 1
    fi
    echo "Checksum verified."
else
    echo "Model already exists. Skipping download."
fi

# CPU config: short context (2048 tokens), 1 concurrent request (-cb)
# Serve on port 8080 on all interfaces (0.0.0.0) so it can be reached in the private network
echo "Starting llama.cpp server..."
exec /app/llama-server \
    -m "$MODEL_PATH" \
    --host 0.0.0.0 \
    --port 8080 \
    -c 2048 \
    -np 1 \
    -t 4 \
    --metrics
