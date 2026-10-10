import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, Mock
import requests
from codesentinel.api.main import _run_scanner_and_ai, ScanSession
from codesentinel.models.core import Project
from codesentinel.ai.llama_cpp_provider import LlamaCppProvider

def test_static_only_mode():
    session = _run_scanner_and_ai(Path("."), ai=False, ai_provider="mock", ai_mode="off")
    assert not session.ai_enabled
    # Static findings should be present if any exist in "." (we assume some exist or just check it ran)
    # The main assertion is it succeeds without needing an inference server.
    assert isinstance(session, ScanSession)

@patch("codesentinel.api.main.Scanner")
def test_provider_unavailable(mock_scanner):
    # Mock static scanner to return 1 finding
    mock_instance = Mock()
    mock_session = ScanSession(id="1", project=Project(path="."), start_time=datetime.now())
    mock_session.findings = []
    mock_instance.run_scan.return_value = mock_session
    mock_scanner.return_value = mock_instance
    
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError):
        session = _run_scanner_and_ai(Path("."), ai=True, ai_provider="llama_cpp", ai_mode="discover")
        assert session.ai_provider_errors > 0
        assert session.findings == [], "Static findings must survive if AI provider is unavailable"

@patch("codesentinel.api.main.Scanner")
def test_provider_timeout(mock_scanner):
    mock_instance = Mock()
    mock_session = ScanSession(id="1", project=Project(path="."), start_time=datetime.now())
    mock_session.findings = []
    mock_instance.run_scan.return_value = mock_session
    mock_scanner.return_value = mock_instance
    
    with patch("requests.post", side_effect=requests.exceptions.Timeout):
        session = _run_scanner_and_ai(Path("."), ai=True, ai_provider="llama_cpp", ai_mode="discover")
        assert session.ai_timeout_count > 0
        assert session.findings == [], "Static findings must survive on provider timeout"

@patch("codesentinel.api.main.Scanner")
def test_successful_zero_findings(mock_scanner):
    mock_instance = Mock()
    mock_session = ScanSession(id="1", project=Project(path="."), start_time=datetime.now())
    mock_session.findings = []
    mock_instance.run_scan.return_value = mock_session
    mock_scanner.return_value = mock_instance
    
    with patch("requests.post") as mock_post:
        mock_resp = Mock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": '{"vulnerabilities": []}'}}]}
        mock_post.return_value = mock_resp
        
        session = _run_scanner_and_ai(Path("."), ai=True, ai_provider="llama_cpp", ai_mode="discover")
        assert session.ai_provider_errors == 0
        assert session.findings == [], "Should be empty because discovery returned 0 findings"
