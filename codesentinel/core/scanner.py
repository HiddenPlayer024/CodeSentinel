import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set

from codesentinel.models.core import Project, ScanSession

# Default paths to ignore during scan
DEFAULT_IGNORES = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "coverage", "target", ".idea", ".vscode"
}

# Simple language detection based on extension
EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".sql": "sql"
}

class Scanner:
    def __init__(self, target_path: str, ignores: Optional[Set[str]] = None):
        self.target_path = Path(target_path).resolve()
        self.ignores = ignores or DEFAULT_IGNORES

    def is_ignored(self, path: Path) -> bool:
        """Check if a path should be ignored."""
        for part in path.parts:
            if part in self.ignores:
                return True
        return False

    def detect_language(self, path: Path) -> Optional[str]:
        """Detect language based on file extension."""
        return EXTENSION_TO_LANGUAGE.get(path.suffix.lower())

    def discover_files(self) -> List[Path]:
        """Walk the target path and return a list of scannable files."""
        scannable_files = []
        if self.target_path.is_file():
            if not self.is_ignored(self.target_path) and self.detect_language(self.target_path):
                scannable_files.append(self.target_path)
            return scannable_files

        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

        for root, dirs, files in os.walk(self.target_path):
            # Modify dirs in-place to avoid descending into ignored directories
            dirs[:] = [d for d in dirs if not self.is_ignored(Path(root) / d)]
            
            for file in files:
                file_path = Path(root) / file
                if not self.is_ignored(file_path):
                    # For MVP, we only scan files with known extensions
                    if self.detect_language(file_path):
                        scannable_files.append(file_path)
                        
        return scannable_files

    def run_scan(self) -> ScanSession:
        """Execute the initial discovery phase of a scan."""
        start_time = datetime.now(timezone.utc)
        
        files = self.discover_files()
        
        languages_found = set()
        scanned_file_paths = []
        
        for f in files:
            lang = self.detect_language(f)
            if lang:
                languages_found.add(lang)
            # Store relative paths for cleaner output
            if self.target_path.is_file():
                rel_path = f.name
            else:
                try:
                    rel_path = str(f.relative_to(self.target_path))
                except ValueError:
                    rel_path = str(f.name)
            scanned_file_paths.append(rel_path)

        project = Project(
            path=str(self.target_path),
            languages=list(languages_found),
            file_count=len(files),
            scanned_files=scanned_file_paths
        )
        
        # --- PHASE 2: Analysis ---
        from codesentinel.analysis.parser.python import PythonParser
        from codesentinel.analysis.engine.rule_engine import RuleEngine
        from codesentinel.rules.base import RuleContext
        
        engine = RuleEngine()
        python_parser = PythonParser()
        all_findings = []
        
        for f in files:
            lang = self.detect_language(f)
            if lang == "python":
                try:
                    tree, source = python_parser.parse(f)
                    context = RuleContext(file_path=str(f), source_code=source)
                    file_findings = engine.analyze_python_ast(tree, context)
                    all_findings.extend(file_findings)
                except SyntaxError:
                    pass
                except Exception as e:
                    print(f"Error analyzing {f}: {e}")

        end_time = datetime.now(timezone.utc)
        
        session = ScanSession(
            id=str(uuid.uuid4()),
            project=project,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            findings=all_findings,
            status="completed"
        )
        
        return session
