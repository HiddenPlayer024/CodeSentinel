import json
import os
import requests
from typing import Dict, Any, Optional, Type
from pydantic import BaseModel
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

    def generate_structured_response(self, prompt: str, schema: Type[BaseModel], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        # Ollama doesn't have native structured output that guarantees schema match in older versions,
        # but we can pass the JSON schema in the prompt.
        schema_json = schema.schema_json()
        augmented_prompt = f"{prompt}\n\nPlease output ONLY JSON that matches this schema:\n{schema_json}"
        return self.generate_response(augmented_prompt, system_prompt)

class OpenAICompatibleProvider(AIProvider):
    """Provider for any OpenAI-compatible API (e.g., vLLM, LMStudio, OpenAI)."""
    def __init__(self, api_key: str = None, model: str = None, endpoint: str = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model = model or os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        self.endpoint = endpoint or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        if not self.endpoint.endswith("/chat/completions"):
            self.endpoint = self.endpoint.rstrip("/") + "/chat/completions"

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
            
    def generate_structured_response(self, prompt: str, schema: Type[BaseModel], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        schema_dict = schema.model_json_schema()
        
        payload = {
            "model": self.model,
            "messages": messages,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": schema.__name__,
                    "strict": True,
                    "schema": schema_dict
                }
            },
            "temperature": 0.1
        }
        
        try:
            response = requests.post(self.endpoint, json=payload, headers=headers, timeout=30)
            response.raise_for_status()
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            return json.loads(content)
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            print(f"OpenAI API Error (structured): {e}")
            # Fallback to standard JSON format if structured output is not supported by this specific endpoint/model
            return self.generate_response(f"{prompt}\n\nPlease output ONLY JSON that matches this schema: {schema_dict}", system_prompt)

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

    def generate_structured_response(self, prompt: str, schema: Type[BaseModel], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        self.calls.append({"prompt": prompt, "system_prompt": system_prompt, "schema": schema.__name__})
        # Try to return a valid object matching the schema for the discovery test
        if schema.__name__ == "DiscoveryResult":
            # Extract file from prompt if possible: "File: examples/security-corpus/python/vulnerable/app.py"
            file_name = "mock.py"
            for line in prompt.split('\n'):
                if line.startswith('File:'):
                    file_name = line.split('File:')[1].strip()
                    break
                    
            if "vulnerable" in file_name or "variant" in file_name:
                return {
                    "vulnerabilities": [{
                        "title": "Mock AI Vulnerability",
                        "category": "Injection",
                        "severity": "HIGH",
                        "confidence": 0.9,
                        "file": file_name,
                        "line_start": 1,
                        "line_end": 1,
                        "evidence": "mock_evidence()",
                        "explanation": "Mock AI discovered this.",
                        "recommended_fix": "Fix it."
                    }]
                }
            return {"vulnerabilities": []}
        return self.mock_response
