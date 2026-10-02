import pytest
from pathlib import Path
import zipfile
import tempfile
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock

from codesentinel.api.main import app
from codesentinel.api.github_scan import (
    GitHubArchiveAcquirer, 
    InvalidGitHubURLError, 
    SafeExtractionError,
    ResourceLimitExceededError
)

client = TestClient(app)

def test_validate_url_safe():
    owner, repo = GitHubArchiveAcquirer.validate_url("https://github.com/owner/repo")
    assert owner == "owner"
    assert repo == "repo"
    
    owner, repo = GitHubArchiveAcquirer.validate_url("https://github.com/owner/repo/")
    assert owner == "owner"
    assert repo == "repo"
    
    owner, repo = GitHubArchiveAcquirer.validate_url("https://github.com/owner/repo.git")
    assert owner == "owner"
    assert repo == "repo"

def test_validate_url_unsafe():
    invalid_urls = [
        "http://github.com/owner/repo",      # Not HTTPS
        "https://evil.com/owner/repo",       # Not github.com
        "https://github.com/owner",          # Missing repo
        "https://github.com/owner/repo/issues/1", # Issue page
        "https://github.com/owner/repo/pull/1",   # PR page
    ]
    for url in invalid_urls:
        with pytest.raises(InvalidGitHubURLError):
            GitHubArchiveAcquirer.validate_url(url)

def test_safe_extract_rejects_traversal():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        archive_path = tmp_path / "evil.zip"
        dest_path = tmp_path / "extract"
        dest_path.mkdir()
        
        # Create a malicious zip file
        with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr("../escaped.txt", "evil content")
            
        with pytest.raises(SafeExtractionError, match="path traversal"):
            GitHubArchiveAcquirer.safe_extract(archive_path, dest_path)

def test_safe_extract_rejects_absolute_paths():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        archive_path = tmp_path / "evil_abs.zip"
        dest_path = tmp_path / "extract"
        dest_path.mkdir()
        
        with zipfile.ZipFile(archive_path, 'w') as zf:
            zf.writestr("/etc/passwd", "evil content")
            
        with pytest.raises(SafeExtractionError, match="absolute path"):
            GitHubArchiveAcquirer.safe_extract(archive_path, dest_path)

@patch("codesentinel.api.github_scan.GitHubArchiveAcquirer.download_archive")
@patch("codesentinel.api.github_scan.GitHubArchiveAcquirer.get_default_branch")
def test_end_to_end_github_scan(mock_get_branch, mock_download):
    mock_get_branch.return_value = "main"
    
    # Mock download to just create a valid zip with one file
    def fake_download(owner, repo, ref, dest_file):
        with zipfile.ZipFile(dest_file, 'w') as zf:
            zf.writestr("app.py", "import os\ndef do_bad(x):\n    os.system('ls ' + x)")
    
    mock_download.side_effect = fake_download
    
    response = client.post("/scan/github", json={
        "repository_url": "https://github.com/testowner/testrepo",
        "ai": False
    })
    
    assert response.status_code == 200
    data = response.json()
    assert data["project"]["source_type"] == "github"
    assert data["project"]["repository_url"] == "https://github.com/testowner/testrepo"
    assert data["project"]["ref"] == "HEAD"
    assert len(data["findings"]) > 0
    assert data["findings"][0]["identity"]["rule_id"] == "python.command.injection"

@patch("requests.get")
def test_get_default_branch_http_behavior(mock_get):
    from codesentinel.api.github_scan import GitHubUpstreamError
    import requests
    
    # Test 200 OK
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"default_branch": "master"}
    mock_get.return_value = mock_response
    assert GitHubArchiveAcquirer.get_default_branch("owner", "repo") == "master"
    
    # Test 404 Not Found
    mock_response_404 = MagicMock()
    mock_response_404.status_code = 404
    mock_get.return_value = mock_response_404
    with pytest.raises(GitHubUpstreamError, match="not found"):
        GitHubArchiveAcquirer.get_default_branch("owner", "repo")
        
    # Test 403 Rate Limit
    mock_response_403 = MagicMock()
    mock_response_403.status_code = 403
    mock_get.return_value = mock_response_403
    with pytest.raises(GitHubUpstreamError, match="rate limit"):
        GitHubArchiveAcquirer.get_default_branch("owner", "repo")
        
    # Test Timeout
    mock_get.side_effect = requests.Timeout("Connection timed out")
    with pytest.raises(GitHubUpstreamError, match="Failed to communicate"):
        GitHubArchiveAcquirer.get_default_branch("owner", "repo")
