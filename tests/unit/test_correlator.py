import pytest
from codesentinel.analysis.correlator import Correlator
from codesentinel.models.core import ScanSession, Finding, FindingIdentity, FindingLocation, FindingClassification, FindingContext, DataFlowInfo, FindingRemediation, Severity, Project
from datetime import datetime

def create_finding(file: str, line: int, rule_id: str, category: str, snippet: str):
    return Finding(
        identity=FindingIdentity(id="1", rule_id=rule_id, title="Test"),
        location=FindingLocation(file=file, line_start=line, line_end=line),
        classification=FindingClassification(category=category, severity=Severity.HIGH, confidence=1.0),
        context=FindingContext(snippet=snippet),
        data_flow=DataFlowInfo(),
        remediation=FindingRemediation(explanation="", recommended_fix="")
    )

def test_legitimate_correlation():
    correlator = Correlator()
    session = ScanSession(id="1", project=Project(path=""), start_time=datetime.now())
    
    stat_f = create_finding("test.py", 10, "python-sqli", "Injection", "execute(query)")
    ai_f = create_finding("test.py", 10, "ai-sqli", "Injection", "execute(query)")
    
    merged = correlator.correlate(session, [stat_f], [ai_f])
    assert len(merged) == 1
    assert merged[0].correlation_reason == ["Exact match"]

def test_unrelated_findings_remain_separate():
    correlator = Correlator()
    session = ScanSession(id="1", project=Project(path=""), start_time=datetime.now())
    
    # Same line, but completely unrelated family
    stat_f = create_finding("test.py", 10, "python-sqli", "Injection", "execute(query)")
    ai_f = create_finding("test.py", 10, "ai-xss", "Security", "execute(query)")
    
    merged = correlator.correlate(session, [stat_f], [ai_f])
    assert len(merged) == 2
