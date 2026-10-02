from pathlib import Path
from typing import List

def score_file_risk(file_path: Path) -> int:
    try:
        content = file_path.read_text(encoding='utf-8')
    except Exception:
        return 0
        
    score = 0
    content_lower = content.lower()
    
    keywords = {
        'request': 2,
        'app.route': 5,
        'fastapi': 3,
        'execute': 4,
        'commit': 3,
        'session.query': 4,
        'subprocess': 10,
        'os.system': 10,
        'eval': 10,
        'exec(': 10,
        'open(': 2,
        'requests.': 5,
        'urllib': 5,
        'http': 3,
        'sql': 5
    }
    
    for kw, points in keywords.items():
        if kw in content_lower:
            score += points
            
    return score

def sort_files_by_risk(files: List[Path]) -> List[Path]:
    return sorted(files, key=score_file_risk, reverse=True)
