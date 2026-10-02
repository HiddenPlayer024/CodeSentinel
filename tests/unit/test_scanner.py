import os
import tempfile
from pathlib import Path

from codesentinel.core.scanner import Scanner

def test_scanner_discovery():
    with tempfile.TemporaryDirectory() as temp_dir:
        base_path = Path(temp_dir)
        
        # Create some dummy files
        (base_path / "main.py").write_text("print('hello')")
        (base_path / "script.js").write_text("console.log('hello')")
        (base_path / "readme.md").write_text("# Hello") # Should not be scanned (unknown lang)
        
        # Create an ignored directory
        venv_dir = base_path / "venv"
        venv_dir.mkdir()
        (venv_dir / "ignored.py").write_text("print('ignored')")
        
        # Initialize scanner
        scanner = Scanner(target_path=str(base_path))
        session = scanner.run_scan()
        
        # Assertions
        assert session.project.file_count == 1
        assert set(session.project.languages) == {"python"}
        assert "main.py" in session.project.scanned_files
        assert "readme.md" not in session.project.scanned_files
        assert "venv/ignored.py" not in session.project.scanned_files
        
def test_scanner_single_file():
    with tempfile.TemporaryDirectory() as temp_dir:
        base_path = Path(temp_dir)
        file_path = base_path / "main.py"
        file_path.write_text("print('hello')")
        
        scanner = Scanner(target_path=str(file_path))
        session = scanner.run_scan()
        
        assert session.project.file_count == 1
        assert session.project.languages == ["python"]
        assert "main.py" in session.project.scanned_files
