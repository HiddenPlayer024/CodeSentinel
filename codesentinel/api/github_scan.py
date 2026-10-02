import os
import zipfile
import urllib.parse
import requests
from pathlib import Path
from typing import Tuple, Optional

class GitHubScanLimits:
    MAX_ARCHIVE_SIZE_MB = 50
    MAX_EXTRACTED_SIZE_MB = 120
    MAX_FILE_COUNT = 5000
    MAX_INDIVIDUAL_FILE_MB = 10
    
    # Bytes limits
    MAX_ARCHIVE_SIZE = MAX_ARCHIVE_SIZE_MB * 1024 * 1024
    MAX_EXTRACTED_SIZE = MAX_EXTRACTED_SIZE_MB * 1024 * 1024
    MAX_INDIVIDUAL_FILE = MAX_INDIVIDUAL_FILE_MB * 1024 * 1024

    CONNECT_TIMEOUT = 5
    READ_TIMEOUT = 30


class GitHubAcquisitionError(Exception):
    """Base exception for GitHub acquisition failures."""
    pass

class InvalidGitHubURLError(GitHubAcquisitionError):
    pass

class ResourceLimitExceededError(GitHubAcquisitionError):
    pass

class SafeExtractionError(GitHubAcquisitionError):
    pass

class GitHubUpstreamError(GitHubAcquisitionError):
    pass


class GitHubArchiveAcquirer:
    
    @staticmethod
    def validate_url(url: str) -> Tuple[str, str]:
        """
        Validates the GitHub URL and returns (owner, repository).
        Strictly requires HTTPS and github.com domain.
        """
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            raise InvalidGitHubURLError("Malformed URL")

        if parsed.scheme != "https":
            raise InvalidGitHubURLError("Only HTTPS URLs are allowed")
            
        if parsed.netloc.lower() not in ("github.com", "www.github.com"):
            raise InvalidGitHubURLError("Only github.com domain is allowed")
            
        # Path should be /owner/repo[/...]
        path_parts = [p for p in parsed.path.split('/') if p]
        
        if len(path_parts) < 2:
            raise InvalidGitHubURLError("URL must contain owner and repository")
            
        owner = path_parts[0]
        repo = path_parts[1]
        
        # Remove .git suffix if present
        if repo.endswith(".git"):
            repo = repo[:-4]
            
        # Basic sanity check on owner/repo lengths and characters
        # GitHub usernames are max 39 chars, alphanumeric and hyphens.
        # Repos are max 100 chars. We do a loose but safe check.
        if not owner or not repo or len(owner) > 100 or len(repo) > 100:
            raise InvalidGitHubURLError("Invalid owner or repository name")
            
        # Reject if path strongly suggests it's an issue/PR/wiki page rather than repo root
        if len(path_parts) > 2 and path_parts[2] in ("issues", "pull", "releases", "actions", "wiki"):
            raise InvalidGitHubURLError(f"URL points to a specific GitHub page ({path_parts[2]}), not a repository root")
            
        return owner, repo

    @staticmethod
    def get_default_branch(owner: str, repo: str) -> str:
        """
        Queries the GitHub API for the default branch of the repository.
        """
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        try:
            response = requests.get(
                api_url, 
                timeout=(GitHubScanLimits.CONNECT_TIMEOUT, GitHubScanLimits.READ_TIMEOUT),
                headers={"Accept": "application/vnd.github.v3+json"}
            )
            
            if response.status_code == 404:
                raise GitHubUpstreamError("Repository not found or is private")
            if response.status_code == 403:
                raise GitHubUpstreamError("GitHub API rate limit exceeded or access denied")
                
            response.raise_for_status()
            data = response.json()
            return data.get("default_branch", "main")
            
        except requests.RequestException as e:
            if isinstance(e, GitHubUpstreamError):
                raise
            raise GitHubUpstreamError(f"Failed to communicate with GitHub API: {str(e)}")

    @staticmethod
    def download_archive(owner: str, repo: str, ref: str, dest_file: Path) -> None:
        """
        Downloads the repository archive to dest_file using codeload.github.com.
        Enforces MAX_ARCHIVE_SIZE limit during download.
        """
        # Codeload URL gives a standard zip file
        archive_url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{urllib.parse.quote(ref)}"
        
        try:
            with requests.get(
                archive_url, 
                stream=True, 
                timeout=(GitHubScanLimits.CONNECT_TIMEOUT, GitHubScanLimits.READ_TIMEOUT)
            ) as response:
                
                if response.status_code == 404:
                    raise GitHubUpstreamError(f"Branch or ref '{ref}' not found")
                response.raise_for_status()
                
                downloaded_size = 0
                with open(dest_file, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            downloaded_size += len(chunk)
                            if downloaded_size > GitHubScanLimits.MAX_ARCHIVE_SIZE:
                                raise ResourceLimitExceededError(
                                    f"Archive size exceeds maximum allowed ({GitHubScanLimits.MAX_ARCHIVE_SIZE_MB}MB)"
                                )
                            f.write(chunk)
                            
        except requests.RequestException as e:
            if isinstance(e, (GitHubUpstreamError, ResourceLimitExceededError)):
                raise
            raise GitHubUpstreamError(f"Failed to download repository archive: {str(e)}")

    @staticmethod
    def safe_extract(archive_file: Path, dest_dir: Path) -> None:
        """
        Safely extracts the zip file, preventing path traversal, absolute paths,
        and enforcing size and file count limits.
        """
        dest_dir_resolved = dest_dir.resolve()
        extracted_size = 0
        file_count = 0
        
        try:
            with zipfile.ZipFile(archive_file, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    # 1. Prevent absolute paths or suspicious names
                    if member.filename.startswith('/') or member.filename.startswith('\\'):
                        raise SafeExtractionError(f"Archive contains absolute path: {member.filename}")
                    if '..' in member.filename:
                        raise SafeExtractionError(f"Archive contains path traversal: {member.filename}")
                        
                    # 2. Limit checks
                    file_count += 1
                    if file_count > GitHubScanLimits.MAX_FILE_COUNT:
                        raise ResourceLimitExceededError(f"Archive exceeds maximum file count ({GitHubScanLimits.MAX_FILE_COUNT})")
                        
                    if member.file_size > GitHubScanLimits.MAX_INDIVIDUAL_FILE:
                        raise ResourceLimitExceededError(f"File {member.filename} exceeds maximum individual file size")
                        
                    extracted_size += member.file_size
                    if extracted_size > GitHubScanLimits.MAX_EXTRACTED_SIZE:
                        raise ResourceLimitExceededError(f"Extracted size exceeds maximum allowed ({GitHubScanLimits.MAX_EXTRACTED_SIZE_MB}MB)")
                    
                    # Resolve destination and check if it stays within boundary
                    target_path = (dest_dir_resolved / member.filename).resolve()
                    if not str(target_path).startswith(str(dest_dir_resolved)):
                        raise SafeExtractionError(f"Archive entry attempts to escape destination: {member.filename}")
                        
                    # 3. Safe Extraction
                    # zipfile doesn't store symlinks typically, but if it does (UNIX attributes)
                    # we must avoid them
                    is_symlink = (member.external_attr >> 16) & 0o120000 == 0o120000
                    if is_symlink:
                        raise SafeExtractionError(f"Archive contains unsupported symlink: {member.filename}")
                        
                    zip_ref.extract(member, dest_dir_resolved)
                    
        except zipfile.BadZipFile:
            raise GitHubUpstreamError("Downloaded archive is not a valid zip file")
