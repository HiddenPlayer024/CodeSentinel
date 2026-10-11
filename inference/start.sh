#!/bin/bash
set -e

# Configuration
MODEL_URL="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
MODEL_CHECKSUM="9fecc3b3cd76bba89d504f29b616eedf7da85b96540e490ca5824d3f7d2776a0"
MODEL_PATH="/models/tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"

function verify_checksum() {
    local file=$1
    echo "Verifying checksum for $file..."
    local ACTUAL_CHECKSUM=$(sha256sum "$file" | awk '{print $1}')
    if [ "$ACTUAL_CHECKSUM" != "$MODEL_CHECKSUM" ]; then
        echo "Checksum mismatch!"
        echo "Expected: $MODEL_CHECKSUM"
        echo "Actual:   $ACTUAL_CHECKSUM"
        return 1
    fi
    echo "Checksum verified successfully."
    return 0
}

echo "Checking for model at $MODEL_PATH..."
if [ ! -f "$MODEL_PATH" ]; then
    echo "Model not found. Downloading to temporary path..."
    TEMP_PATH="${MODEL_PATH}.tmp"
    curl -fL -o "$TEMP_PATH" "$MODEL_URL"
    
    if verify_checksum "$TEMP_PATH"; then
        mv "$TEMP_PATH" "$MODEL_PATH"
    else
        rm -f "$TEMP_PATH"
        exit 1
    fi
else
    echo "Model already exists. Re-verifying checksum..."
    if ! verify_checksum "$MODEL_PATH"; then
        echo "Cached model checksum is invalid. Deleting and aborting..."
        rm -f "$MODEL_PATH"
        exit 1
    fi
fi

# CPU config: short context (2048 tokens), 1 concurrent request (-cb)
# Serve on port 8080 on all interfaces (0.0.0.0) so it can be reached in the private network
echo "Starting llama.cpp server..."
if [ -x /app/llama-server ]; then
    SERVER_BIN="/app/llama-server"
elif [ -x /llama-server ]; then
    SERVER_BIN="/llama-server"
elif command -v llama-server &> /dev/null; then
    SERVER_BIN="llama-server"
else
    echo "llama-server executable not found!"
    exit 1
fi

exec $SERVER_BIN \
    -m "$MODEL_PATH" \
    --host 0.0.0.0 \
    --port 8080 \
    -c 2048 \
    -np 1 \
    -t 4 \
    --metrics
