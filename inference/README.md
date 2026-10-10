# Local AI Inference Service

This directory contains the configuration to run a private, self-hosted LLM using `llama.cpp` for CodeSentinel.

## Configuration
- **Model**: TinyLlama 1.1B Chat (Q4_K_M GGUF)
- **Context Size**: 2048 tokens
- **Hardware Requirement**: CPU-only. Minimum 1 GB RAM (2 GB recommended).
- **Concurrency**: 1 request at a time

## Security & Reliability
- The `llama.cpp` Docker image (`ghcr.io/ggerganov/llama.cpp:server`) should be pinned to a specific immutable digest in production deployments (e.g., using `@sha256:...`).
- The model file is pinned via SHA-256 checksum in `start.sh`. It is downloaded to a temporary file using robust `curl -fL` options, verified, and only promoted to the actual model path if successful. Already-cached models are also verified on startup.
- The service should be deployed as a **private service** and must not be exposed to the public internet.
- Request timeouts are handled by the caller. Context sizes are bounded to 2048.

## Local Testing
```bash
docker build -t codesentinel-inference .
docker run -p 8080:8080 -v $(pwd)/models:/models codesentinel-inference
```

## Health Check
The model server provides a built-in health endpoint:
```bash
curl http://localhost:8080/health
```
Returns HTTP 200 `{"status": "ok"}` when ready. Returns `{"status": "loading model"}` during initialization.
