import pytest
import json
from unittest.mock import patch, MagicMock
from codesentinel.ai.providers import OpenAICompatibleProvider
from pydantic import BaseModel
import requests

class DummySchema(BaseModel):
    field: str

def test_openai_provider_timeout_handling():
    provider = OpenAICompatibleProvider(api_key="test")
    with patch("requests.post") as mock_post:
        mock_post.side_effect = requests.Timeout("Timeout")
        
        result = provider.generate_structured_response("test", DummySchema)
        assert result == {}

def test_openai_provider_malformed_json():
    provider = OpenAICompatibleProvider(api_key="test")
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "not json"}}]}
        mock_post.return_value = mock_resp
        
        result = provider.generate_structured_response("test", DummySchema)
        assert result == {}

def test_openai_provider_schema_failure():
    provider = OpenAICompatibleProvider(api_key="test")
    with patch("requests.post") as mock_post:
        mock_resp = MagicMock()
        # Simulate missing choices key
        mock_resp.json.return_value = {"error": "schema failure"}
        mock_post.return_value = mock_resp
        
        result = provider.generate_structured_response("test", DummySchema)
        assert result == {}
