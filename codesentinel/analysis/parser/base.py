from abc import ABC, abstractmethod
from typing import Any
from pathlib import Path

class BaseParser(ABC):
    """
    Abstract base class for all language-specific AST parsers.
    """
    
    @abstractmethod
    def parse(self, file_path: Path) -> Any:
        """
        Parse the given file and return the Abstract Syntax Tree (AST).
        
        Args:
            file_path: The path to the source file.
            
        Returns:
            An object representing the parsed AST. The exact type depends
            on the language and parsing library used.
            
        Raises:
            SyntaxError: If the file cannot be parsed due to invalid syntax.
            IOError: If the file cannot be read.
        """
        pass

    @property
    @abstractmethod
    def supported_language(self) -> str:
        """
        Returns the language identifier this parser supports (e.g., 'python').
        """
        pass
