import type { GitHubScanRequest, ScanSession } from '../types/codesentinel';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export async function checkHealth(): Promise<{ status: string }> {
  const response = await fetch(`${API_URL}/health`);
  if (!response.ok) {
    throw new Error('API is unreachable');
  }
  return response.json();
}

export async function scanGithub(request: GitHubScanRequest): Promise<ScanSession> {
  const response = await fetch(`${API_URL}/scan/github`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    const errorData = await response.json().catch(() => null);
    const errorMessage = errorData?.detail || response.statusText;
    
    // Convert to readable messages
    if (response.status === 400) throw new Error(`Invalid request: ${errorMessage}`);
    if (response.status === 403) {
      if (errorMessage.toLowerCase().includes('rate limit')) {
        throw new Error(`GitHub API Rate Limit Exceeded. Please try again later. (${errorMessage})`);
      } else {
        throw new Error(`Access Denied: Repository may be private. (${errorMessage})`);
      }
    }
    if (response.status === 404) throw new Error(`Repository Not Found: ${errorMessage}`);
    if (response.status === 413) throw new Error(`Repository exceeds scan limits: ${errorMessage}`);
    if (response.status === 422) throw new Error(`Validation Error: ${errorMessage}`);
    if (response.status === 502) throw new Error(`GitHub Upstream Error: ${errorMessage}`);
    if (response.status === 500) throw new Error(`Internal scanner failure: ${errorMessage}`);
    
    throw new Error(errorMessage || 'Unknown error occurred');
  }

  return response.json();
}
