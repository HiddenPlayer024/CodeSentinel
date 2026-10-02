from pathlib import Path
from typing import Dict, Any, Optional
from codesentinel.models.core import ScanSession

class AIValidator:
    def __init__(self, project_path: Path):
        self.project_path = project_path

    def validate_finding(self, finding_dict: Dict[str, Any], session: ScanSession) -> Optional[Dict[str, Any]]:
        session.ai_candidate_findings += 1
        
        file_path_str = finding_dict.get('file')
        if not file_path_str:
            self._reject(session)
            return None
            
        try:
            full_path = (self.project_path / file_path_str).resolve()
            if not str(full_path).startswith(str(self.project_path.resolve())):
                self._reject(session)
                return None
            if not full_path.exists() or not full_path.is_file():
                self._reject(session)
                return None
        except Exception:
            self._reject(session)
            return None
            
        try:
            lines = full_path.read_text(encoding='utf-8').splitlines()
        except Exception:
            self._reject(session)
            return None
            
        line_start = finding_dict.get('line_start', 1)
        line_end = finding_dict.get('line_end', 1)
        
        total_lines = len(lines)
        if not (1 <= line_start <= line_end <= total_lines):
            self._reject(session)
            return None
            
        actual_evidence = "\n".join(lines[line_start-1:line_end])
        finding_dict['evidence'] = actual_evidence
        
        return finding_dict
        
    def _reject(self, session: ScanSession):
        session.invalid_ai_locations += 1
        session.ai_rejected_findings += 1
