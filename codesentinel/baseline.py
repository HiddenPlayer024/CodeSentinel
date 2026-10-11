import json
import os
from typing import List, Dict, Any

class Baseline:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.suppressed_fingerprints = set()
        
    def load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                data = json.load(f)
                self.suppressed_fingerprints = set(data.get("suppressed_fingerprints", []))
                
    def save(self, findings: List[Any]):
        fingerprints = []
        for f in findings:
            fp = getattr(f, 'evidence_fingerprint', None)
            if fp:
                fingerprints.append(fp)
        
        data = {
            "suppressed_fingerprints": fingerprints
        }
        with open(self.filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
    def apply(self, findings: List[Any]) -> List[Any]:
        """Return findings that are NOT in the baseline."""
        filtered = []
        for f in findings:
            fp = getattr(f, 'evidence_fingerprint', None)
            if not fp or fp not in self.suppressed_fingerprints:
                filtered.append(f)
        return filtered
