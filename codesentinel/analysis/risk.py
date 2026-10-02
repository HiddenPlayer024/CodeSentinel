import re
import ast
from pathlib import Path
from typing import List, Dict, Any
from pydantic import BaseModel

class RiskScore(BaseModel):
    score: int
    reasons: List[str]

def score_file_risk(file_path: Path) -> RiskScore:
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception:
        return RiskScore(score=0, reasons=["Failed to read file"])
        
    score = 0
    reasons = []
    
    # 1. Regex-based checks
    patterns = {
        'Network': (r'(requests\.|urllib|http|fastapi|app\.route|flask)', 5),
        'Command': (r'(subprocess|os\.system|eval\(|exec\()', 10),
        'DB': (r'(sql|commit|session\.query|pymysql|psycopg2)', 5),
        'Filesystem': (r'(open\(|os\.path|Path\()', 3),
        'Auth': (r'(login|password|secret|token|jwt|auth)', 8),
        'Serialization': (r'(pickle|yaml\.load|json\.loads)', 7),
        'Template': (r'(render_template|jinja2)', 4),
        'Config': (r'(config|settings|env)', 3)
    }
    
    for cat, (pattern, weight) in patterns.items():
        if re.search(pattern, content, re.IGNORECASE):
            score += weight
            reasons.append(f"Matched {cat} regex")
            
    # 2. AST-based checks for more robust analysis if it's a Python file
    if file_path.suffix == '.py':
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec']:
                            score += 15
                            reasons.append("Found eval/exec call via AST")
                    elif isinstance(node.func, ast.Attribute):
                        if node.func.attr in ['execute', 'system']:
                            score += 10
                            reasons.append(f"Found {node.func.attr} method call via AST")
                elif isinstance(node, ast.Import) or isinstance(node, ast.ImportFrom):
                    module_name = ""
                    if isinstance(node, ast.ImportFrom) and node.module:
                        module_name = node.module
                    for alias in node.names:
                        full_name = f"{module_name}.{alias.name}" if module_name else alias.name
                        if 'subprocess' in full_name or 'pickle' in full_name:
                            score += 10
                            reasons.append(f"Dangerous import: {full_name}")
        except Exception:
            reasons.append("AST parsing failed")

    return RiskScore(score=score, reasons=reasons)

def _risk_key(file_path: Path) -> int:
    return score_file_risk(file_path).score

def sort_files_by_risk(files: List[Path]) -> List[Path]:
    return sorted(files, key=_risk_key, reverse=True)
