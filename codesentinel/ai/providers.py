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
            "messages": messages
        }
        
        try:
            from codesentinel.config import settings
            import time
            max_retries = settings.AI_MAX_RETRIES if hasattr(settings, 'AI_MAX_RETRIES') else 3
            
            for attempt in range(max_retries + 1):
                try:
                    response = requests.post(self.endpoint, json=payload, headers=headers, timeout=settings.AI_TIMEOUT_SECONDS)
                    response.raise_for_status()
                    result = response.json()
                    content = result.get("choices", [{}])[0].get("message", {}).get("content", "{}")
                    return json.loads(content)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code in (429, 502, 503, 504):
                        if attempt < max_retries:
                            time.sleep(2 ** attempt)
                            continue
                    print(f"OpenAI API Error: {e}")
                    return {}
                except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
                    print(f"OpenAI API Error: {e}")
                    return {}
            return {}
        except Exception as e:
            print(f"OpenAI API Error: {e}")
            return {}
            
    def generate_structured_response(self, prompt: str, schema: Type[BaseModel], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        schema_dict = schema.model_json_schema()
        
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
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
            }
        }
        
        try:
            from codesentinel.config import settings
            import time
            payload["max_tokens"] = settings.AI_MAX_OUTPUT_TOKENS
            max_retries = settings.AI_MAX_RETRIES if hasattr(settings, 'AI_MAX_RETRIES') else 3
            
            for attempt in range(max_retries + 1):
                try:
                    response = requests.post(self.endpoint, json=payload, headers=headers, timeout=settings.AI_TIMEOUT_SECONDS)
                    response.raise_for_status()
                    result = response.json()
                    
                    output = result.get("choices", [{}])[0].get("message", {})
                    if output.get("refusal"):
                        print(f"OpenAI API Refusal: {output['refusal']}")
                        return {}
                        
                    content = output.get("content", "{}")
                    return json.loads(content)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code in (429, 502, 503, 504):
                        if attempt < max_retries:
                            time.sleep(2 ** attempt)
                            continue
                    print(f"OpenAI API Error (structured): {e}")
                    return self.generate_response(f"{prompt}\n\nPlease output ONLY JSON that matches this schema: {schema_dict}", system_prompt)
                except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
                    print(f"OpenAI API Error (structured): {e}")
                    return self.generate_response(f"{prompt}\n\nPlease output ONLY JSON that matches this schema: {schema_dict}", system_prompt)
            return {}
        except Exception as e:
            print(f"OpenAI API Error (structured): {e}")
            return self.generate_response(f"{prompt}\n\nPlease output ONLY JSON that matches this schema: {schema_dict}", system_prompt)

class MockProvider(AIProvider):
    """Mock provider for testing."""
    def __init__(self, mock_response: Dict[str, Any] = None, fixtures: Dict[str, str] = None, scenario: str = None):
        self.mock_response = mock_response or {
            "is_likely_vulnerable": True,
            "confidence_adjustment": 0.1,
            "explanation": "Mock AI verified this vulnerability.",
            "false_positive_reason": None
        }
        self.calls = []
        self.fixtures = fixtures or {}
        self.scenario = scenario
        
    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        self.calls.append({"prompt": prompt, "system_prompt": system_prompt})
        return self.mock_response

    def generate_structured_response(self, prompt: str, schema: Type[BaseModel], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        import os
        self.calls.append({"prompt": prompt, "system_prompt": system_prompt, "schema": schema.__name__})
        
        if schema.__name__ == "DiscoveryResult":
            file_name = "mock.py"
            for line in prompt.split('\n'):
                if line.startswith('File:'):
                    file_name = line.split('File:')[1].strip()
                    break
            

                
            base_name = os.path.basename(file_name)
            is_vuln = False
            
            if self.fixtures:
                if file_name in self.fixtures and self.fixtures[file_name] == "vulnerable":
                    is_vuln = True
                elif base_name in self.fixtures and self.fixtures[base_name] == "vulnerable":
                    is_vuln = True
            
            if is_vuln:

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
                        "explanation": "Mock AI discovered this based on fixtures.",
                        "recommended_fix": "Fix it."
                    }]
                }
            return {"vulnerabilities": []}
        return self.mock_response