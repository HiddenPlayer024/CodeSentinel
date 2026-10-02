import json
from pathlib import Path

from codesentinel.models.core import ScanSession
from .base import BaseReporter

class JsonReporter(BaseReporter):
    """Generates a raw JSON report of the ScanSession."""
    
    def generate(self, session: ScanSession, output_path: Path) -> None:
        json_data = session.model_dump_json(indent=2)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(json_data)
