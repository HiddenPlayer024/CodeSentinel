import ast
from pathlib import Path
from typing import Any, Tuple

from .base import BaseParser

class PythonParser(BaseParser):
    """AST Parser for Python using the built-in ast module."""
    
    @property
    def supported_language(self) -> str:
        return "python"

    def parse(self, file_path: Path) -> Tuple[Any, str]:
        """
        Parses the python file.
        Returns a tuple of (AST Node, raw source code).
        """
        with open(file_path, "r", encoding="utf-8") as f:
            source = f.read()
            
        try:
            tree = ast.parse(source, filename=str(file_path))
            return tree, source
        except SyntaxError as e:
            raise SyntaxError(f"Failed to parse {file_path}: {e}")
