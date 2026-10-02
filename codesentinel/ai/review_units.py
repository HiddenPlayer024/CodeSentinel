from dataclasses import dataclass
from typing import List
import ast
from pathlib import Path

@dataclass
class ReviewUnit:
    file_path: Path
    start_line: int
    end_line: int
    context_type: str
    code_chunk: str

def get_review_units_for_file(file_path: Path, max_lines: int = 100, min_lines: int = 20) -> List[ReviewUnit]:
    try:
        content = file_path.read_text(encoding='utf-8')
        lines = content.splitlines()
        tree = ast.parse(content)
    except Exception:
        return []

    units = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            context_type = "function"
            
            start_line = node.lineno
            end_line = getattr(node, 'end_lineno', start_line + min_lines)
            
            if end_line - start_line < min_lines:
                pad = min_lines - (end_line - start_line)
                start_line = max(1, start_line - pad // 2)
                end_line = min(len(lines), end_line + pad // 2)
                
            if end_line - start_line > max_lines:
                end_line = start_line + max_lines

            chunk = "\n".join(lines[start_line-1:end_line])
            units.append(ReviewUnit(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                context_type=context_type,
                code_chunk=chunk
            ))
            
    if not units:
        for i in range(0, len(lines), max_lines):
            end_i = min(i + max_lines, len(lines))
            start_line = i + 1
            end_line = end_i
            chunk = "\n".join(lines[i:end_i])
            units.append(ReviewUnit(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                context_type="chunk",
                code_chunk=chunk
            ))
            
    return units
