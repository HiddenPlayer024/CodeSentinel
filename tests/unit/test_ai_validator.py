import pytest
from pathlib import Path
from codesentinel.ai.validator import AIValidator
from codesentinel.models.core import ScanSession, Project
from datetime import datetime

@pytest.fixture
def session():
    return ScanSession(
        id="test-session",
        project=Project(path="/tmp"),
        start_time=datetime.now()
    )

@pytest.fixture
def tmp_project(tmp_path):
    (tmp_path / "app.py").write_text("line 1\nline 2\nline 3\nline 4\nline 5")
    return tmp_path

def test_validator_rejects_missing_file(tmp_project, session):
    validator = AIValidator(tmp_project)
    finding = {"file": "missing.py", "line_start": 1, "line_end": 2}
    result = validator.validate_finding(finding, session)
    assert result is None
    assert session.ai_rejected_findings == 1

def test_validator_rejects_traversal(tmp_project, session):
    validator = AIValidator(tmp_project)
    finding = {"file": "../outside.py", "line_start": 1, "line_end": 2}
    result = validator.validate_finding(finding, session)
    assert result is None

def test_validator_rejects_out_of_bounds(tmp_project, session):
    validator = AIValidator(tmp_project)
    finding = {"file": "app.py", "line_start": 0, "line_end": 2}
    result = validator.validate_finding(finding, session)
    assert result is None

def test_validator_rejects_end_past_total(tmp_project, session):
    validator = AIValidator(tmp_project)
    finding = {"file": "app.py", "line_start": 2, "line_end": 10}
    result = validator.validate_finding(finding, session)
    assert result is None

def test_validator_extracts_evidence(tmp_project, session):
    validator = AIValidator(tmp_project)
    finding = {"file": "app.py", "line_start": 2, "line_end": 3}
    result = validator.validate_finding(finding, session)
    assert result is not None
    assert result["evidence"] == "line 2\nline 3"
