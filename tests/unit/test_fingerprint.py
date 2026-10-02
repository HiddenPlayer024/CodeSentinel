import pytest
from codesentinel.analysis.fingerprint import normalize_path, generate_fingerprint
import os

def test_normalize_path():
    root = "/app/project"
    path = "/app/project/src/main.py"
    assert normalize_path(root, path) == "src/main.py"
    
    # Not in root
    assert normalize_path(root, "/other/src/main.py") == "/other/src/main.py"

def test_generate_fingerprint():
    root = "/app/project"
    path = "/app/project/src/main.py"
    
    fp1 = generate_fingerprint(root, path, 10, 15, "SQLi", "Security")
    fp2 = generate_fingerprint(root, "src/main.py", 10, 15, "sqli", "security")
    
    assert fp1 == fp2 # Should match due to normalization
    
    fp3 = generate_fingerprint(root, path, 10, 16, "SQLi", "Security")
    assert fp1 != fp3 # Different line end
