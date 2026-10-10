import os
import json
import pytest
from hypothesis import given, strategies as st
from codesentinel.analysis.fingerprint import normalize_path, generate_fingerprint
from codesentinel.baseline import Baseline

@given(
    project_root=st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cc", "Cs"])),
    file_path=st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cc", "Cs"]))
)
def test_path_normalization_properties(project_root, file_path):
    # Just checking it doesn't crash
    result = normalize_path(project_root, file_path)
    assert isinstance(result, str)

@given(
    project_root=st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cc", "Cs"])),
    file_path=st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cc", "Cs"])),
    line_start=st.integers(min_value=0, max_value=100000),
    line_end=st.integers(min_value=0, max_value=100000),
    rule_family=st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cc", "Cs"])),
    category=st.text(min_size=1, alphabet=st.characters(exclude_categories=["Cc", "Cs"]))
)
def test_fingerprint_generation_properties(project_root, file_path, line_start, line_end, rule_family, category):
    result = generate_fingerprint(project_root, file_path, line_start, line_end, rule_family, category)
    assert isinstance(result, str)
    assert len(result) == 64  # SHA256 length

class MockFinding:
    def __init__(self, fingerprint):
        self.evidence_fingerprint = fingerprint

import tempfile

@given(
    suppressed=st.lists(st.text(min_size=10, max_size=10), min_size=0, max_size=10),
    new_findings=st.lists(st.text(min_size=10, max_size=10), min_size=0, max_size=10)
)
def test_baseline_matching(suppressed, new_findings):
    with tempfile.TemporaryDirectory() as d:
        filepath = os.path.join(d, "baseline.json")
        with open(filepath, "w") as f:
            json.dump({"suppressed_fingerprints": suppressed}, f)
        
        baseline = Baseline(filepath)
        baseline.load()
        
        findings = [MockFinding(fp) for fp in new_findings]
        filtered = baseline.apply(findings)
        
        for f in filtered:
            assert f.evidence_fingerprint not in suppressed
            
        for original_f in findings:
            if original_f.evidence_fingerprint not in suppressed:
                assert any(f.evidence_fingerprint == original_f.evidence_fingerprint for f in filtered)
