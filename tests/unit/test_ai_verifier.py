import pytest
from datetime import datetime

from codesentinel.ai.verifier import AIVerifier
from codesentinel.ai.providers import MockProvider
from codesentinel.models.core import (
    ScanSession, Project, Finding, FindingIdentity, FindingLocation, 
    FindingClassification, FindingContext, DataFlowInfo, FindingRemediation, Severity
)

@pytest.fixture
def dummy_session():
    project = Project(path="/test", languages=["python"], file_count=1, scanned_files=["app.py"])
    
    # Finding 1: Needs verification (Confidence 0.6)
    f1 = Finding(
        identity=FindingIdentity(id="1", rule_id="test.rule", title="Test Rule"),
        location=FindingLocation(file="app.py", line_start=1, line_end=1),
        classification=FindingClassification(category="test", severity=Severity.MEDIUM, confidence=0.6),
        context=FindingContext(snippet="test", surrounding_code="test"),
        data_flow=DataFlowInfo(),
        remediation=FindingRemediation(explanation="exp", recommended_fix="fix")
    )
    
    # Finding 2: High confidence, should NOT be verified (Confidence 0.99)
    f2 = Finding(
        identity=FindingIdentity(id="2", rule_id="test.rule2", title="Test Rule 2"),
        location=FindingLocation(file="app.py", line_start=2, line_end=2),
        classification=FindingClassification(category="test", severity=Severity.HIGH, confidence=0.99),
        context=FindingContext(snippet="test", surrounding_code="test"),
        data_flow=DataFlowInfo(),
        remediation=FindingRemediation(explanation="exp", recommended_fix="fix")
    )
    
    return ScanSession(id="123", project=project, start_time=datetime.now(), findings=[f1, f2])

def test_ai_verifier_mock(dummy_session):
    # Mock says it's a false positive
    mock_response = {
        "is_likely_vulnerable": False,
        "confidence_adjustment": -0.5,
        "explanation": "This is safely sanitized.",
        "false_positive_reason": "Sanitization in helper function."
    }
    
    provider = MockProvider(mock_response=mock_response)
    verifier = AIVerifier(provider=provider, min_conf=0.4, max_conf=0.95)
    
    verifier.verify_session(dummy_session)
    
    assert len(provider.calls) == 1, "Should only verify findings within confidence bounds"
    
    f1 = dummy_session.findings[0]
    f2 = dummy_session.findings[1]
    
    # f1 should be heavily adjusted down to 0.2 because is_likely_vulnerable=False
    assert f1.confidence <= 0.2
    assert f1.ai_assessment is not None
    assert f1.ai_assessment.is_likely_vulnerable is False
    assert f1.ai_assessment.false_positive_reason == "Sanitization in helper function."
    
    # f2 should be untouched
    assert f2.confidence == 0.99
    assert f2.ai_assessment is None
