import os
import json
import time
import requests
from typing import Dict, Any, Optional, Type
from pydantic import BaseModel
from codesentinel.ai.base import AIProvider

class LlamaCppProvider(AIProvider):
    """Provider for self-hosted llama.cpp HTTP server."""
    def __init__(self, endpoint: str = None, model: str = None, api_key: str = None, timeout: int = None):
        self.endpoint = endpoint or os.environ.get("LOCAL_LLM_BASE_URL", "http://127.0.0.1:8080/v1")
        if not self.endpoint.endswith("/chat/completions"):
            self.endpoint = self.endpoint.rstrip("/") + "/chat/completions"
        self.model = model or os.environ.get("LOCAL_LLM_MODEL", "TinyLlama-1.1B-Chat-v1.0")
        self.api_key = api_key or os.environ.get("LOCAL_LLM_API_KEY", "")
        self.timeout = timeout
        if self.timeout is None:
            timeout_str = os.environ.get("LOCAL_LLM_TIMEOUT_SECONDS")
            self.timeout = int(timeout_str) if timeout_str else 30

    def generate_response(self, prompt: str, system_prompt: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }
        
        try:
            from codesentinel.config import settings
            timeout = self.timeout or settings.AI_TIMEOUT_SECONDS
            max_retries = settings.AI_MAX_RETRIES if hasattr(settings, 'AI_MAX_RETRIES') else 1
            
            for attempt in range(max_retries + 1):
                try:
                    response = requests.post(self.endpoint, json=payload, headers=headers, timeout=timeout)
                    response.raise_for_status()
                    result = response.json()
                    content = result["choices"][0]["message"]["content"]
                    return json.loads(content)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code in (429, 502, 503, 504):
                        if attempt < max_retries:
                            time.sleep(1)
                            continue
                    print(f"llama.cpp Error: {e}")
                    if isinstance(e, requests.exceptions.Timeout):
                        return {"_error": "timeout"}
                    return {"_error": "general"}
                except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
                    print(f"llama.cpp Error: {e}")
                    if isinstance(e, requests.exceptions.Timeout):
                        return {"_error": "timeout"}
                    return {"_error": "general"}
            return {"_error": "general"}
        except Exception as e:
            print(f"llama.cpp Error: {e}")
            return {"_error": "general"}

    def generate_structured_response(self, prompt: str, schema: Type[BaseModel], system_prompt: Optional[str] = None) -> Dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
            
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        schema_dict = schema.model_json_schema()
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.1,
            "response_format": {
                "type": "json_object",
                "schema": schema_dict
            }
        }
        
        try:
            from codesentinel.config import settings
            timeout = self.timeout or settings.AI_TIMEOUT_SECONDS
            max_retries = settings.AI_MAX_RETRIES if hasattr(settings, 'AI_MAX_RETRIES') else 1
            
            for attempt in range(max_retries + 1):
                try:
                    response = requests.post(self.endpoint, json=payload, headers=headers, timeout=timeout)
                    response.raise_for_status()
                    result = response.json()
                    content = result["choices"][0]["message"]["content"]
                    return json.loads(content)
                except requests.exceptions.HTTPError as e:
                    if e.response is not None and e.response.status_code in (429, 502, 503, 504):
                        if attempt < max_retries:
                            time.sleep(1)
                            continue
                    print(f"llama.cpp Structured Error: {e}")
                    if isinstance(e, requests.exceptions.Timeout):
                        return {"_error": "timeout"}
                    return {"_error": "general"}
                except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
                    print(f"llama.cpp Structured Error: {e}")
                    if isinstance(e, requests.exceptions.Timeout):
                        return {"_error": "timeout"}
                    return {"_error": "general"}
            return {"_error": "general"}
        except Exception as e:
            print(f"llama.cpp Structured Error: {e}")
            return {"_error": "general"}
