import pytest
from unittest.mock import patch, Mock
from pydantic import BaseModel
from codesentinel.ai.providers import OpenAICompatibleProvider

class DummySchema(BaseModel):
    name: str

@patch("requests.post")
def test_openai_generate_response(mock_post):
    provider = OpenAICompatibleProvider(api_key="test", endpoint="http://dummy/v1/chat/completions")
    
    mock_resp = Mock()
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": '{"name": "test"}'}}]
    }
    mock_post.return_value = mock_resp
    
    res = provider.generate_response("hello")
    assert res == {"name": "test"}
    
    # Verify request payload
    called_json = mock_post.call_args[1]["json"]
    assert called_json["messages"][0]["content"] == "hello"
    assert called_json["model"] == "gpt-4o-mini"

@patch("requests.post")
def test_openai_generate_structured_response(mock_post):
    provider = OpenAICompatibleProvider(api_key="test", endpoint="http://dummy/v1/chat/completions")
    
    mock_resp = Mock()
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": '{"name": "test"}'}}]
    }
    mock_post.return_value = mock_resp
    
    res = provider.generate_structured_response("hello", DummySchema)
    assert res == {"name": "test"}
    
    # Verify request payload
    called_json = mock_post.call_args[1]["json"]
    assert called_json["response_format"]["type"] == "json_schema"
    assert called_json["response_format"]["json_schema"]["name"] == "DummySchema"
