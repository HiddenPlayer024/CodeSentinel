# Local AI Inference Service

This directory contains the configuration to run a private, self-hosted LLM using `llama.cpp` for CodeSentinel.

## Configuration
- **Model**: TinyLlama 1.1B Chat (Q4_K_M GGUF)
- **Context Size**: 2048 tokens
- **Hardware Requirement**: CPU-only. Minimum 1 GB RAM (2 GB recommended).
- **Concurrency**: 1 request at a time

## Security & Reliability
- The model file is pinned via SHA-256 checksum in `start.sh` and downloaded only if absent.
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
