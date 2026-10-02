import pytest
from pathlib import Path
from codesentinel.ai.discovery import AIDiscoveryEngine
from codesentinel.models.core import Project, ScanSession
from pydantic import BaseModel

class MockProviderForDiscovery:
    def __init__(self, response_data):
        self.response_data = response_data
    def generate_structured_response(self, prompt, schema_class, system_prompt=None):
        return schema_class(**self.response_data)

@pytest.fixture
def dummy_session(tmp_path):
    p = tmp_path / "app.py"
    p.write_text("def vulnerable():\n    eval('1')\n")
    proj = Project(path=str(tmp_path), file_count=1, scanned_files=[str(p)])
    return ScanSession(id="test", project=proj, start_time="2026-10-02T00:00:00")

def test_valid_candidate(dummy_session, tmp_path):
    mock_response = {
        "vulnerabilities": [
            {
                "title": "Unsafe Eval",
                "category": "injection",
                "severity": "CRITICAL",
                "confidence": 0.9,
                "file": "app.py",
                "line_start": 2,
                "line_end": 2,
                "evidence": "eval('1')",
                "explanation": "eval is dangerous",
                "recommended_fix": "don't use eval"
            }
        ]
    }
    engine = AIDiscoveryEngine(provider=MockProviderForDiscovery(mock_response), project_path=str(tmp_path))
    findings = engine.run_discovery(dummy_session)
    
    assert len(findings) == 1
    assert findings[0].identity.title == "Unsafe Eval"
    assert "ai-discovery" in findings[0].analysis_source

def test_malformed_json_caught(dummy_session, tmp_path):
    class ThrowingProvider:
        def generate_structured_response(self, prompt, schema_class, system_prompt=None):
            raise ValueError("Malformed JSON")
            
    engine = AIDiscoveryEngine(provider=ThrowingProvider(), project_path=str(tmp_path))
    findings = engine.run_discovery(dummy_session)
    assert len(findings) == 0 # Should gracefully handle failure
