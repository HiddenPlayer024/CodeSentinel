import json
import requests
from typing import Dict, Any, Optional
from .base import AIProvider

class OllamaProvider(AIProvider):
    """Local LLM provider using Ollama's REST API."""
    def __init__(self, model: str = "qwen2.5:3b", endpoint: str = "http://localhost:11434/api/generate"):
        self.model = model
        self.endpoint = endpoint

    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "system": system_prompt or "",
            "stream": False,
            "format": "json"
        }
        
        try:
            response = requests.post(self.endpoint, json=payload, timeout=30)
            response.raise_for_status()
            result = response.json()
            return json.loads(result.get("response", "{}"))
        except (requests.RequestException, json.JSONDecodeError) as e:
            print(f"Ollama API Error: {e}")
            return {}

class OpenAICompatibleProvider(AIProvider):
    """Provider for any OpenAI-compatible API (e.g., vLLM, LMStudio, OpenAI)."""
    def __init__(self, api_key: str, model: str, endpoint: str = "https://api.openai.com/v1/chat/completions"):
        self.api_key = api_key
        self.model = model
        self.endpoint = endpoint

    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        
        try:
            response = requests.post(self.endpoint, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            return json.loads(content)
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            print(f"OpenAI API Error: {e}")
            return {}

class MockProvider(AIProvider):
    """Mock provider for testing."""
    def __init__(self, mock_response: Dict[str, Any] = None):
        self.mock_response = mock_response or {
            "is_likely_vulnerable": True,
            "confidence_adjustment": 0.1,
            "explanation": "Mock AI verified this vulnerability.",
            "false_positive_reason": None
        }
        self.calls = []
        
    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        self.calls.append({"prompt": prompt, "system_prompt": system_prompt})
        return self.mock_response
