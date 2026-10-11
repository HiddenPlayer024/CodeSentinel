import json
import pytest
from pathlib import Path
from codesentinel.reporting.sarif_reporter import SarifReporter
from codesentinel.models.core import ScanSession, Project, Finding, FindingIdentity, FindingLocation, FindingClassification, FindingContext, DataFlowInfo, FindingRemediation, Severity
from datetime import datetime, timezone

def test_sarif_reporter_schema_compliance(tmp_path):
    f = Finding(
        identity=FindingIdentity(id="f1", rule_id="python.test", title="Test Rule", fingerprint="fingerprint123"),
        location=FindingLocation(file="/project/app.py", line_start=10, line_end=10),
        classification=FindingClassification(category="test", severity=Severity.HIGH, confidence=0.9),
        context=FindingContext(snippet="print('vuln')"),
        data_flow=DataFlowInfo(),
        remediation=FindingRemediation(explanation="Explain", recommended_fix="Fix")
    )
    
    session = ScanSession(
        id="test-session",
        project=Project(path="/project", file_count=1, languages=["python"], scanned_files=["app.py"]),
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        duration_seconds=1.0,
        findings=[f],
        status="completed"
    )
    
    out = tmp_path / "out.sarif"
    reporter = SarifReporter()
    reporter.generate(session, out)
    
    data = json.loads(out.read_text())
    
    assert data["version"] == "2.1.0"
    assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    
    rules = data["runs"][0]["tool"]["driver"]["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "python.test"
    
    results = data["runs"][0]["results"]
    assert len(results) == 1
    res = results[0]
    
    assert res["ruleId"] == "python.test"
    assert res["level"] == "error"
    assert res["partialFingerprints"]["identity"] == "fingerprint123"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    
    # Assert there is no invalid "fingerprint" property on the root of result
    assert "fingerprint" not in res
