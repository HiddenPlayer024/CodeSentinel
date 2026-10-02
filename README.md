# CodeSentinel 🛡️

**CodeSentinel** is a modern, AI-assisted source-code security analysis platform. It combines blazing-fast deterministic static analysis (SAST) with an optional AI verification layer to significantly reduce false positives and provide actionable remediation advice.

Unlike generic LLM wrappers, CodeSentinel is built with a rock-solid, AST-based rule engine and data-flow tracker. The AI only activates when needed, making the platform both fast and highly intelligent.

## 🚀 Key Features

* **Deterministic Rule Engine**: AST-based parsing ensures no false positives from regex matching within comments or strings.
* **Intra-procedural Data Flow**: Traces variables from source to sink to dynamically adjust confidence scores.
* **AI Verification Layer**: Optionally routes uncertain findings to an LLM (Ollama, OpenAI, vLLM) to verify vulnerability and append detailed reasoning.
* **Rich Reporting**: Outputs to Terminal, JSON, SARIF (for GitHub Security integration), or a standalone interactive HTML dashboard.
* **FastAPI Backend**: Built-in REST API to expose the scanner as a microservice.
* **CI/CD Ready**: Configurable failure thresholds (`--fail-on HIGH`) and out-of-the-box GitHub Actions templates.

## 📦 Installation

```bash
git clone https://github.com/yourusername/CodeSentinel.git
cd CodeSentinel
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 💻 Usage

### Command Line Interface

**Basic Scan:**
```bash
codesentinel scan ./my_project
```

**Fail CI Pipeline on High Severities:**
```bash
codesentinel scan . --fail-on HIGH
```

**Generate Reports (JSON, SARIF, HTML):**
```bash
codesentinel scan . -f html -o report.html
codesentinel scan . -f sarif -o report.sarif
```

### AI Verification

CodeSentinel can send "gray-area" findings (where confidence isn't 100%) to an LLM for verification.

**Using OpenAI (GPT-4o, etc.):**
```bash
export OPENAI_API_KEY="your_key"
codesentinel scan . --ai --ai-provider openai
```

**Using Local Ollama (e.g. qwen2.5 or llama3):**
```bash
# Ensure Ollama is running locally on port 11434
codesentinel scan . --ai --ai-provider ollama
```

### REST API

Launch the FastAPI backend:
```bash
codesentinel serve --host 127.0.0.1 --port 8000
```
Then send a POST request to scan a local directory:
```bash
curl -X POST "http://127.0.0.1:8000/scan" \
     -H "Content-Type: application/json" \
     -d '{"target": "./my_project", "ai": true, "ai_provider": "openai"}'
```

### Remote GitHub Scanning

You can scan public GitHub repositories securely without cloning them to your local disk. The scanner will fetch an archive, analyze it in memory/temporary storage, and automatically delete the repository source.

```bash
curl -X POST "http://127.0.0.1:8000/scan/github" \
     -H "Content-Type: application/json" \
     -d '{
       "repository_url": "https://github.com/HiddenPlayer024/CodeSentinel",
       "ref": "main",
       "ai": false
     }'
```

**Security & Limitations:**
* **Public Repositories Only:** CodeSentinel will not ask for or store GitHub authentication tokens.
* **No Code Execution:** CodeSentinel only reads and statically analyzes the repository via AST. It will never run the target repository's build scripts, Makefiles, setup.py, or Docker builds.
* **Limits:** To protect the service, remote repositories are limited to a 50MB downloaded archive, 120MB extracted size, and a maximum of 5,000 files.
* **AI Privacy:** AI integration remains optional. If enabled, only narrow file snippets containing findings are sent to the AI context. Complete repository files are never uploaded to the AI provider.

## 🎓 Examples

A deliberately vulnerable demonstration repository is provided in `examples/vulnerable-python-app/`.
```bash
codesentinel scan examples/vulnerable-python-app/
```

### Suppressing False Positives
If you determine a finding is a false positive, append `# codesentinel:ignore` or `# nosec` to the line or directly above it.

## 🧩 Adding Custom Rules

CodeSentinel features a plugin-based dynamic rule engine. To add a new Python rule, simply drop a new file into `codesentinel/rules/python/`. See `codesentinel/rules/base.py` for the API.

## 📊 Benchmarks

* **Target:** CodeSentinel repository itself
* **Size:** 50 files
* **Rules Executed:** 8 Python AST rules + Data Flow tracking
* **Duration (No AI):** ~0.03s
* **Duration (AI via Mock):** ~0.03s
* **Duration (AI via OpenAI/Ollama):** Dependent heavily on API/local latency.

## ⚠️ Limitations

CodeSentinel is an analysis aid, not a mathematical proof of security.
* **False Positives/Negatives:** Like all SAST tools, it may flag safe code or miss obfuscated vulnerabilities.
* **Language Support:** v1.0 currently only supports Python AST parsing.
* **Data Flow:** Tracking is strictly intra-procedural (within a single function scope). Cross-file and global taint analysis is on the roadmap.
* **AI Hallucinations:** The AI verification layer relies on LLMs, which may occasionally hallucinate or incorrectly dismiss a vulnerability. Always verify manually.

## 🗺️ Roadmap
* Inter-procedural (cross-function) data flow tracking.
* JavaScript / TypeScript AST support.
* Global configuration files (`codesentinel.yaml`) for rule tuning.

## 🛡️ License
MIT License

## 🌐 Web Dashboard (Frontend)

CodeSentinel includes a premium React-based security dashboard for interacting with the API without the CLI.

### Architecture
CodeSentinel uses a two-service architecture for production deployment:
* **Backend API**: A Python FastAPI service (e.g., `codesentinel-api`).
* **Frontend UI**: A React static site communicating purely over HTTP. The browser talks *only* to the CodeSentinel API, never directly to GitHub or other services, ensuring strict security boundaries.

### Local Development

1. **Start the Backend API:**
```bash
export CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
codesentinel serve --host 127.0.0.1 --port 8000
```

2. **Start the Frontend Development Server:**
```bash
cd frontend
npm install
npm run dev
```
The dashboard will be available at `http://localhost:5173`.

### Production Deployment (Render)

Deploying the frontend as a Render Static Site:
1. Build Command: `cd frontend && npm install && npm run build`
2. Publish Directory: `frontend/dist`
3. Environment Variables:
   * `VITE_API_URL`: Set this to your deployed FastAPI backend URL (e.g., `https://codesentinel-api.onrender.com`).
4. Update the **Backend** `CORS_ORIGINS` environment variable to include your newly deployed frontend domain.
