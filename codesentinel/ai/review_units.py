from dataclasses import dataclass, field
from typing import List, Optional
import ast
import re
from pathlib import Path
import hashlib
from codesentinel.config import settings

@dataclass
class ReviewUnit:
    file_path: Path
    language: str
    start_line: int
    end_line: int
    context_type: str
    code_chunk: str
    risk_score: float = 0.0
    risk_reasons: List[str] = field(default_factory=list)
    unit_id: str = ""

def generate_unit_id(file_path: Path, start_line: int, end_line: int, context_type: str) -> str:
    s = f"{file_path}:{start_line}:{end_line}:{context_type}"
    return hashlib.sha256(s.encode('utf-8')).hexdigest()[:16]

def get_review_units_for_file(file_path: Path, max_lines: int = settings.AI_MAX_REVIEW_LINES, min_lines: int = 20) -> List[ReviewUnit]:
    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.splitlines()
    except Exception:
        return []

    ext = file_path.suffix.lower()
    name = file_path.name.lower()
    units = []

    def add_chunk(start, end, ctx_type, lang):
        if end - start < min_lines:
            pad = min_lines - (end - start)
            start = max(1, start - pad // 2)
            end = min(len(lines), end + pad // 2)
        if end - start > max_lines:
            end = start + max_lines
        
        chunk = "\n".join(lines[start-1:end])
        uid = generate_unit_id(file_path, start, end, ctx_type)
        units.append(ReviewUnit(
            file_path=file_path,
            language=lang,
            start_line=start,
            end_line=end,
            context_type=ctx_type,
            code_chunk=chunk,
            risk_score=0.0,
            risk_reasons=[],
            unit_id=uid
        ))

    if ext == '.py':
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    start_line = node.lineno
                    end_line = getattr(node, 'end_lineno', start_line + min_lines)
                    add_chunk(start_line, end_line, "function", "python")
        except Exception:
            pass

    elif ext in ['.js', '.ts', '.jsx', '.tsx']:
        # Simple regex based extraction for functions/routes
        func_pattern = re.compile(r'^(?:export\s+)?(?:async\s+)?function\s+\w+\s*\(|^\s*(?:const|let|var)\s+\w+\s*=\s*(?:async\s+)?(?:\([^)]*\)|[^=]+)\s*=>|^\s*(?:app|router)\.(?:get|post|put|delete|patch|all)\(')
        in_func = False
        start_line = 1
        brace_count = 0
        
        for i, line in enumerate(lines):
            if not in_func and func_pattern.search(line):
                in_func = True
                start_line = i + 1
                brace_count = line.count('{') - line.count('}')
            elif in_func:
                brace_count += line.count('{') - line.count('}')
                if brace_count <= 0:
                    add_chunk(start_line, i + 1, "function_or_route", "javascript")
                    in_func = False

    elif ext in ['.yml', '.yaml']:
        # Chunk by top-level keys
        start_line = 1
        for i, line in enumerate(lines):
            if i > 0 and not line.startswith(' ') and not line.startswith('-') and line.strip() and not line.startswith('#'):
                add_chunk(start_line, i, "yaml_block", "yaml")
                start_line = i + 1
        if start_line <= len(lines):
            add_chunk(start_line, len(lines), "yaml_block", "yaml")

    elif 'dockerfile' in name:
        # Chunk by stages or just whole file if small
        add_chunk(1, len(lines), "dockerfile", "dockerfile")
        
    elif ext == '.env' or 'env' in name:
        add_chunk(1, len(lines), "env_file", "env")

    # Fallback to simple chunking if no units extracted
    if not units:
        lang = "unknown"
        if ext == '.py': lang = "python"
        elif ext in ['.js', '.ts']: lang = "javascript"
        elif ext in ['.yml', '.yaml']: lang = "yaml"
        
        for i in range(0, len(lines), max_lines):
            end_i = min(i + max_lines, len(lines))
            add_chunk(i + 1, end_i, "chunk", lang)

    return units
