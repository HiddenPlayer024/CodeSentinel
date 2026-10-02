import pytest
from pathlib import Path
from typer.testing import CliRunner
import json

from codesentinel.cli.main import app

runner = CliRunner()

def test_end_to_end_scan(tmp_path):
    # Create a vulnerable file
    app_code = """
import os
def execute_cmd(user_input):
    os.system("ping -c 4 " + user_input) # Injection!
"""
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text(app_code)
    
    # Run CLI with JSON output
    out_json = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "-o", str(out_json)])
    
    # Should fail because of findings
    assert result.exit_code == 1
    
    # Parse JSON
    assert out_json.exists()
    report = json.loads(out_json.read_text())
    
    assert report["project"]["file_count"] == 1
    assert "python" in report["project"]["languages"]
    assert len(report["findings"]) == 1
    
    finding = report["findings"][0]
    assert finding["identity"]["rule_id"] == "python.command.injection"
    assert finding["classification"]["severity"] == "HIGH"
    assert finding["context"]["function_name"] == "execute_cmd"
    assert "os.system" in finding["context"]["snippet"]
    assert "static-rule" in finding["analysis_source"]
    
def test_end_to_end_scan_with_ai(tmp_path):
    # Same file
    app_code = """
import os
def execute_cmd(user_input):
    os.system("ping -c 4 " + user_input)
"""
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text(app_code)
    
    out_json = tmp_path / "report_ai.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "json", "-o", str(out_json), "--ai", "--ai-provider", "mock"])
    
    assert result.exit_code == 1
    report = json.loads(out_json.read_text())
    
    finding = report["findings"][0]
    assert "ai-verified" in finding["analysis_source"]
    assert finding["ai_assessment"] is not None
    assert finding["ai_assessment"]["is_likely_vulnerable"] is True
