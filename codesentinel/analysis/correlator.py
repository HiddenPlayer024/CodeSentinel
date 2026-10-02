from typing import List
from codesentinel.models.core import Finding

class Correlator:
    def __init__(self):
        pass
        
    def correlate(self, static_findings: List[Finding], ai_findings: List[Finding]) -> List[Finding]:
        """
        Merge identical Static findings and AI discoveries.
        If a static finding matches an AI discovery, mark its analysis_source as ["static-rule", "ai-discovery"].
        """
        correlated = list(static_findings)
        
        for ai_f in ai_findings:
            matched = False
            for stat_f in correlated:
                # Basic matching logic: same file and overlapping lines, or similar category
                if stat_f.file == ai_f.file and abs(stat_f.line_start - ai_f.line_start) <= 5:
                    if "ai-discovery" not in stat_f.analysis_source:
                        stat_f.analysis_source.append("ai-discovery")
                    matched = True
                    break
            
            if not matched:
                correlated.append(ai_f)
                
        return correlated
