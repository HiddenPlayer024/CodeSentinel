import pytest
from pathlib import Path

from codesentinel.analysis.parser.python import PythonParser
from codesentinel.analysis.engine.rule_engine import RuleEngine
from codesentinel.rules.base import RuleContext

@pytest.fixture
def engine():
    return RuleEngine()

@pytest.fixture
def parser():
    return PythonParser()

def test_python_vulnerable_app(engine, parser):
    vuln_path = Path("tests/rules/python/vulnerable/app.py")
    tree, source = parser.parse(vuln_path)
    context = RuleContext(str(vuln_path), source)
    
    findings = engine.analyze_python_ast(tree, context)
    
    assert len(findings) == 9, f"Expected 9 findings, got {len(findings)}"
    
    rule_ids = [f.rule_id for f in findings]
    assert "python.command.injection" in rule_ids
    assert rule_ids.count("python.command.injection") == 2
    assert "python.crypto.insecure_hash" in rule_ids
    assert "python.deserialization.unsafe" in rule_ids
    assert "python.sql.injection" in rule_ids

def test_python_safe_app(engine, parser):
    safe_path = Path("tests/rules/python/safe/app.py")
    tree, source = parser.parse(safe_path)
    context = RuleContext(str(safe_path), source)
    
    findings = engine.analyze_python_ast(tree, context)
    
    assert len(findings) == 0, f"Expected 0 findings, got {len(findings)}: {[f.rule_id for f in findings]}"
