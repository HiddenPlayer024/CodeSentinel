import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock
import requests
from codesentinel.api.main import app
import os

client = TestClient(app)

def test_health_check_no_url():
    with patch.dict(os.environ, {}, clear=True):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["api"] == "online"
        assert data["model_configured"] == False

def test_health_check_ready():
    with patch.dict(os.environ, {"LOCAL_LLM_BASE_URL": "http://dummy/v1"}, clear=True):
        with patch("requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"status": "ok"}
            mock_get.return_value = mock_resp
            
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["api"] == "online"
            assert data["model_configured"] == True
            assert data["model"] == "ready"

def test_health_check_loading():
    with patch.dict(os.environ, {"LOCAL_LLM_BASE_URL": "http://dummy/v1"}, clear=True):
        with patch("requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"status": "loading model"}
            mock_get.return_value = mock_resp
            
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["model"] == "loading"

def test_health_check_503():
    with patch.dict(os.environ, {"LOCAL_LLM_BASE_URL": "http://dummy/v1"}, clear=True):
        with patch("requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 503
            mock_get.return_value = mock_resp
            
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["model"] == "loading"

def test_health_check_unavailable():
    with patch.dict(os.environ, {"LOCAL_LLM_BASE_URL": "http://dummy/v1"}, clear=True):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError) as mock_get:
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["model"] == "unavailable"

def test_health_check_unknown_200():
    with patch.dict(os.environ, {"LOCAL_LLM_BASE_URL": "http://dummy/v1"}, clear=True):
        with patch("requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"status": "something else"}
            mock_get.return_value = mock_resp
            
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["model"] == "unavailable"

def test_health_check_malformed_200():
    with patch.dict(os.environ, {"LOCAL_LLM_BASE_URL": "http://dummy/v1"}, clear=True):
        with patch("requests.get") as mock_get:
            mock_resp = Mock()
            mock_resp.status_code = 200
            mock_resp.json.side_effect = ValueError("Invalid JSON")
            mock_get.return_value = mock_resp
            
            response = client.get("/health")
            assert response.status_code == 200
            data = response.json()
            assert data["model"] == "unavailable"
