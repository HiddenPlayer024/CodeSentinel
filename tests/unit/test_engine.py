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
    vuln_path = Path(__file__).parent.parent / "rules/python/vulnerable/app.py"
    tree, source = parser.parse(vuln_path)
    context = RuleContext(str(vuln_path), source)
    
    findings = engine.analyze_python_ast(tree, context)
    
    assert len(findings) > 0, f"Expected findings, got {len(findings)}"
    
    rule_ids = [f.rule_id for f in findings]
    assert "python.command.injection" in rule_ids
    assert rule_ids.count("python.command.injection") == 2
    assert "python.crypto.insecure_hash" in rule_ids
    assert "python.deserialization.unsafe" in rule_ids
    assert "python.sql.injection" in rule_ids

def test_python_safe_app(engine, parser):
    safe_path = Path(__file__).parent.parent / "rules/python/safe/app.py"
    tree, source = parser.parse(safe_path)
    context = RuleContext(str(safe_path), source)
    
    findings = engine.analyze_python_ast(tree, context)
    
    assert len(findings) == 0, f"Expected 0 findings, got {len(findings)}: {[f.rule_id for f in findings]}"

def test_ssrf_logic(engine, parser):
    source = """
import requests
# Should NOT be flagged (safe fixed hostname)
requests.get(f"https://api.github.com/repos/{owner}")
requests.get(f"http://api.github.com?query={user_input}")
requests.get(f"http://api.github.com#foo{user_input}")

# SHOULD be flagged (vulnerable hostname control)
requests.get(f"https://{host}/resource")
requests.get(f"{scheme}://api.github.com/")
requests.get(user_input)
requests.get(f"http://api.github.com{user_input}")
"""
    import ast
    tree = ast.parse(source)
    context = RuleContext("test_ssrf.py", source)
    findings = engine.analyze_python_ast(tree, context)
    
    ssrf_findings = [f for f in findings if f.rule_id == "python.ssrf"]
    assert len(ssrf_findings) == 4, f"Expected 4 SSRF findings, got {len(ssrf_findings)}"
    
    lines = [f.location.line_start for f in ssrf_findings]
    assert 9 in lines # https://{host}
    assert 10 in lines # {scheme}
    assert 11 in lines # user_input
    assert 12 in lines # http://api.github.com{user_input}

def test_xxe_logic(engine, parser):
    source = """
# Real XXE
import xml.etree.ElementTree as ET
ET.parse("untrusted.xml")
from xml.dom.minidom import parseString
parseString(user_input)

# False Positive (non-XML)
class MyAST:
    def parse(self, x): pass
parser = MyAST()
parser.parse("something")
"""
    import ast
    tree = ast.parse(source)
    context = RuleContext("test_xxe.py", source)
    findings = engine.analyze_python_ast(tree, context)
    
    xxe_findings = [f for f in findings if f.rule_id == "python.xxe"]
    assert len(xxe_findings) == 2, f"Expected 2 XXE findings, got {len(xxe_findings)}"
    
    lines = [f.location.line_start for f in xxe_findings]
    assert 4 in lines
    assert 6 in lines
