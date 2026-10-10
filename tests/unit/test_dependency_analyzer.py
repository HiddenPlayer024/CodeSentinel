import pytest
from codesentinel.analysis.dependencies import DependencyAnalyzer

def test_dependency_analyzer_requirements():
    analyzer = DependencyAnalyzer()
    content = "flask\nrequests>=2.0.0\n# comment\ndjango==4.0.0\n"
    findings = analyzer.analyze("requirements.txt", content)
    
    assert len(findings) == 1
    assert findings[0].identity.rule_id == "dep.unpinned"
    assert findings[0].context.snippet == "flask"

def test_dependency_analyzer_package_json():
    analyzer = DependencyAnalyzer()
    content = '{"dependencies": {"react": "^18.0.0"}}'
    findings = analyzer.analyze("package.json", content)
    
    assert len(findings) == 0
