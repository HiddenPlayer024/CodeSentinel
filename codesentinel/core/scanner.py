import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

from codesentinel.models.core import Project, ScanSession
from codesentinel.analysis.parser.python import PythonParser
from codesentinel.analysis.engine.rule_engine import RuleEngine
from codesentinel.rules.base import RuleContext

# Default paths to ignore during scan
DEFAULT_IGNORES = {
    ".git", "node_modules", "venv", ".venv", "__pycache__",
    "dist", "build", "coverage", "target", ".idea", ".vscode"
}

# Explicit registry of available parsers/analyzers
ANALYZERS = {
    "python": {
        "extensions": [".py"],
        "parser": PythonParser,
        "type": "ast"
    },
    "config": {
        "extensions": [".json", ".txt", ".env", ".yml", ".yaml", "Dockerfile", "package.json", "requirements.txt"],
        "parser": None, # Handled differently, or we can make a ConfigParser
        "type": "config"
    }
}

def get_language_for_file(path: Path) -> Optional[str]:
    # Check exact filenames first (like Dockerfile, Makefile)
    for lang, data in ANALYZERS.items():
        if path.name in data["extensions"]:
            return lang
            
    # Then check extensions
    suffix = path.suffix.lower()
    for lang, data in ANALYZERS.items():
        if suffix in data["extensions"]:
            return lang
            
    return None


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

    def discover_files(self) -> List[Path]:
        """Walk the target path and return a list of scannable files."""
        scannable_files = []
        if self.target_path.is_file():
            if not self.is_ignored(self.target_path) and get_language_for_file(self.target_path):
                scannable_files.append(self.target_path)
            return scannable_files

        if not self.target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {self.target_path}")

        for root, dirs, files in os.walk(self.target_path):
            dirs[:] = [d for d in dirs if not self.is_ignored(Path(root) / d)]
            
            for file in files:
                file_path = Path(root) / file
                if not self.is_ignored(file_path):
                    if get_language_for_file(file_path):
                        scannable_files.append(file_path)
                        
        return scannable_files

    def run_scan(self) -> ScanSession:
        """Execute the initial discovery phase of a scan."""
        start_time = datetime.now(timezone.utc)
        
        files = self.discover_files()
        
        languages_found = set()
        scanned_file_paths = []
        
        for f in files:
            lang = get_language_for_file(f)
            if lang:
                languages_found.add(lang)
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
        
        engine = RuleEngine()
        all_findings = []
        
        parsers = {}
        for lang, data in ANALYZERS.items():
            if data["parser"]:
                parsers[lang] = data["parser"]()
        
        for f in files:
            lang = get_language_for_file(f)
            if not lang:
                continue
                
            analyzer_data = ANALYZERS[lang]
            
            if analyzer_data["type"] == "ast" and lang in parsers:
                try:
                    tree, source = parsers[lang].parse(f)
                    context = RuleContext(file_path=str(f), source_code=source)
                    file_findings = engine.analyze_python_ast(tree, context)
                    all_findings.extend(file_findings)
                except SyntaxError:
                    pass
                except Exception as e:
                    print(f"Error analyzing {f}: {e}")
            elif analyzer_data["type"] == "config":
                try:
                    with open(f, "r", encoding="utf-8") as file_obj:
                        source = file_obj.read()
                    context = RuleContext(file_path=str(f), source_code=source)
                    # We will implement analyze_config in RuleEngine
                    file_findings = engine.analyze_config(context)
                    all_findings.extend(file_findings)
                except Exception as e:
                    print(f"Error analyzing config {f}: {e}")

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
