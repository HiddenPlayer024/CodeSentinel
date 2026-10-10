import pytest
from pydantic import ValidationError
from codesentinel.api.main import ScanRequest, GitHubScanRequest

def test_scan_request_ai_mode():
    for mode in ('verify', 'discover', 'hybrid', 'off'):
        req = ScanRequest(target="test", ai_mode=mode)
        assert req.ai_mode == mode

    with pytest.raises(ValidationError):
        ScanRequest(target="test", ai_mode="invalid_mode")

def test_github_scan_request_ai_mode():
    for mode in ('verify', 'discover', 'hybrid', 'off'):
        req = GitHubScanRequest(repository_url="https://github.com/foo/bar", ai_mode=mode)
        assert req.ai_mode == mode

    with pytest.raises(ValidationError):
        GitHubScanRequest(repository_url="https://github.com/foo/bar", ai_mode="invalid_mode")
