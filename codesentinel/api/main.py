import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import tempfile
import logging
from fastapi.middleware.cors import CORSMiddleware

from codesentinel.core.scanner import Scanner
from codesentinel.models.core import ScanSession
from codesentinel.ai.verifier import AIVerifier
from codesentinel.ai.providers import MockProvider, OllamaProvider, OpenAICompatibleProvider
from codesentinel.api.github_scan import (
    GitHubArchiveAcquirer, 
    InvalidGitHubURLError, 
    ResourceLimitExceededError, 
    SafeExtractionError, 
    GitHubUpstreamError
)

logger = logging.getLogger(__name__)

app = FastAPI(
    title="CodeSentinel API",
    description="AI-assisted static analysis API",
    version="0.1.0"
)

# CORS Configuration
cors_origins_str = os.environ.get("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
cors_origins = [origin.strip() for origin in cors_origins_str.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target: str
    ai: bool = False
    ai_provider: str = "mock"

class GitHubScanRequest(BaseModel):
    repository_url: str
    ref: Optional[str] = None
    ai: bool = False
    ai_provider: str = "mock"

@app.get("/")
def read_root():
    return {
        "name": "CodeSentinel API",
        "version": "0.1.0",
        "status": "online",
        "docs": "/docs",
        "health": "/health",
        "github_scan": "/scan/github"
    }

@app.get("/health")
def health_check():
    return {"status": "healthy"}

def _run_scanner_and_ai(target_path: Path, ai: bool, ai_provider: str) -> ScanSession:
    scanner = Scanner(target_path)
    session = scanner.run_scan()
    
    if ai and session.findings:
        if ai_provider == "mock":
            provider = MockProvider()
        elif ai_provider == "ollama":
            provider = OllamaProvider()
        elif ai_provider == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                raise HTTPException(status_code=500, detail="OPENAI_API_KEY environment variable not set")
            provider = OpenAICompatibleProvider(api_key=api_key, model="gpt-4o-mini")
        else:
            raise HTTPException(status_code=400, detail=f"Unknown AI provider '{ai_provider}'")
            
        verifier = AIVerifier(provider=provider)
        verifier.verify_session(session)
        
    return session

@app.post("/scan", response_model=ScanSession)
def perform_scan(request: ScanRequest):
    target_path = Path(request.target)
    
    if not target_path.exists():
        raise HTTPException(status_code=404, detail="Target path does not exist")
        
    return _run_scanner_and_ai(target_path, request.ai, request.ai_provider)

@app.post("/scan/github", response_model=ScanSession)
def perform_github_scan(request: GitHubScanRequest):
    try:
        owner, repo = GitHubArchiveAcquirer.validate_url(request.repository_url)
        
        # Avoid GitHub REST API default-branch lookup.
        # Unauthenticated REST requests are rate-limited, so use Git's
        # symbolic HEAD ref when the caller doesn't provide a ref.
        ref = request.ref.strip() if request.ref else "HEAD"
            
        # Create a temporary workspace
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            archive_path = tmp_path / "archive.zip"
            extract_path = tmp_path / "source"
            extract_path.mkdir()
            
            # Download and extract safely
            GitHubArchiveAcquirer.download_archive(owner, repo, ref, archive_path)
            GitHubArchiveAcquirer.safe_extract(archive_path, extract_path)
            
            # The archive usually extracts into a top-level directory (e.g., repo-main/)
            # We just point the scanner at the entire extraction directory.
            session = _run_scanner_and_ai(extract_path, request.ai, request.ai_provider)
            
            # Update metadata to reflect github source instead of random temp dir
            session.project.source_type = "github"
            session.project.repository_url = f"https://github.com/{owner}/{repo}"
            session.project.ref = ref
            session.project.path = f"{owner}/{repo}" # Mask the underlying temp dir
            
            return session
            
    except InvalidGitHubURLError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ResourceLimitExceededError as e:
        raise HTTPException(status_code=413, detail=str(e))
    except SafeExtractionError as e:
        logger.warning(f"Malicious archive rejected: {e}")
        raise HTTPException(status_code=400, detail="Invalid archive contents rejected for security")
    except GitHubUpstreamError as e:
        msg = str(e)
        if "not found" in msg.lower():
            raise HTTPException(status_code=404, detail=msg)
        elif "rate limit" in msg.lower():
            raise HTTPException(status_code=403, detail=msg)
        raise HTTPException(status_code=502, detail=msg)
    except Exception as e:
        logger.error(f"Unexpected error during github scan: {e}")
        raise HTTPException(status_code=500, detail="Internal scanning failure")

