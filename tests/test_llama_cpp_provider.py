import pytest
import requests
import json
from unittest.mock import patch, Mock
from pydantic import BaseModel
from codesentinel.ai.llama_cpp_provider import LlamaCppProvider

from pydantic import ConfigDict
class DummySchema(BaseModel):
    model_config = ConfigDict(extra='forbid')
    message: str
    count: int

def test_successful_json_output():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello", "count": 1}'}}]
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_response("Test prompt")
        assert result == {"message": "hello", "count": 1}

def test_empty_output():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": ""}}]
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_response("Test prompt")
        assert result == {"_error": "general"}

def test_malformed_output():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello", "count": 1'}}] # Missing brace
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_response("Test prompt")
        assert result == {"_error": "general"}

def test_timeout():
    provider = LlamaCppProvider(endpoint="http://dummy/v1", timeout=1)
    with patch("requests.post", side_effect=requests.exceptions.Timeout("Timeout")) as mock_post:
        result = provider.generate_response("Test prompt")
        assert result == {"_error": "timeout"}

def test_http_errors():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError("500 Server Error")
        mock_post.return_value = mock_response
        
        result = provider.generate_response("Test prompt")
        assert result == {"_error": "general"}

def test_unavailable_model_service():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError) as mock_post:
        result = provider.generate_response("Test prompt")
        assert result == {"_error": "general"}

def test_schema_validation_success():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello", "count": 1}'}}]
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_structured_response("Test prompt", DummySchema)
        assert result == {"message": "hello", "count": 1}

def test_schema_validation_missing_field():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello"}'}}] # missing count
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_structured_response("Test prompt", DummySchema)
        assert result == {"_error": "general"}

def test_schema_validation_wrong_type():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello", "count": "one"}'}}] # count is string
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_structured_response("Test prompt", DummySchema)
        assert result == {"_error": "general"}

def test_schema_validation_malformed():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello", "count": 1'}}] # malformed
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_structured_response("Test prompt", DummySchema)
        assert result == {"_error": "general"}

def test_schema_validation_transport_failure():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post", side_effect=requests.exceptions.ConnectionError) as mock_post:
        result = provider.generate_structured_response("Test prompt", DummySchema)
        assert result == {"_error": "general"}

def test_schema_validation_extra_field():
    provider = LlamaCppProvider(endpoint="http://dummy/v1")
    with patch("requests.post") as mock_post:
        mock_response = Mock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"message": "hello", "count": 1, "extra_field": "disallowed"}'}}]
        }
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response
        
        result = provider.generate_structured_response("Test prompt", DummySchema)
        assert result == {"_error": "general"}
