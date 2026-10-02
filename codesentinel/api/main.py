import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from codesentinel.core.scanner import Scanner
from codesentinel.models.core import ScanSession
from codesentinel.ai.verifier import AIVerifier
from codesentinel.ai.providers import MockProvider, OllamaProvider, OpenAICompatibleProvider

app = FastAPI(
    title="CodeSentinel API",
    description="AI-assisted static analysis API",
    version="0.1.0"
)

class ScanRequest(BaseModel):
    target: str
    ai: bool = False
    ai_provider: str = "mock"

@app.get("/health")
def health_check():
    return {"status": "healthy"}

@app.post("/scan", response_model=ScanSession)
def perform_scan(request: ScanRequest):
    target_path = Path(request.target)
    
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Target path does not exist")
        
    scanner = Scanner(target_path)
    session = scanner.run_scan()
    
    if request.ai and session.findings:
        if request.ai_provider == "mock":
            provider = MockProvider()
        elif request.ai_provider == "ollama":
            provider = OllamaProvider()
        elif request.ai_provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                raise HTTPException(status_code=500, detail="OPENAI_API_KEY environment variable not set")
            provider = OpenAICompatibleProvider(api_key=api_key, model="gpt-4o-mini")
        else:
            raise HTTPException(status_code=400, detail=f"Unknown AI provider '{request.ai_provider}'")
            
        verifier = AIVerifier(provider=provider)
        verifier.verify_session(session)
        
    return session
