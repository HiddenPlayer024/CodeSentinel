from abc import ABC, abstractmethod
from pathlib import Path

from codesentinel.models.core import ScanSession

class BaseReporter(ABC):
    """Abstract base class for all report generators."""
    
    @abstractmethod
    def generate(self, session: ScanSession, output_path: Path) -> None:
        """
        Generate the report and write it to the output path.
        """
        pass
