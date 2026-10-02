import os
from typing import List
from codesentinel.models.core import Finding
from codesentinel.analysis.fingerprint import generate_fingerprint

class Correlator:
    def __init__(self, project_root: str = ""):
        self.project_root = project_root
        
    def _get_rule_family(self, rule_id: str, category: str) -> str:
        s = f"{rule_id} {category}".lower()
        if "sql" in s or "sqli" in s:
            return "sqli"
        if "path" in s or "traversal" in s or "zipslip" in s or "archive" in s:
            return "path_traversal"
        if "ssrf" in s or "request" in s:
            return "ssrf"
        if "xss" in s or "cross-site" in s:
            return "xss"
        if "cmd" in s or "command" in s or "eval" in s or "exec" in s:
            return "cmd_injection"
        if "deserialization" in s or "pickle" in s:
            return "deserialization"
        return "other"

    def correlate(self, static_findings: List[Finding], ai_findings: List[Finding]) -> List[Finding]:
        """
        Merge identical Static findings and AI discoveries.
        Assign relationships: standalone, correlated, duplicate, verified, ai-added
        """
        correlated = []
        static_fingerprints = {}
        
        for f in static_findings:
            cat = f.classification.category
            family = self._get_rule_family(f.identity.rule_id, cat)
            fp = generate_fingerprint(
                self.project_root, 
                f.location.file, 
                f.location.line_start, 
                f.location.line_end, 
                family, 
                cat
            )
            f.identity.fingerprint = fp
            if f.ai_assessment is not None:
                f.relationship = "verified"
            else:
                f.relationship = "standalone"
                
            static_fingerprints[fp] = f
            correlated.append(f)
            
        for ai_f in ai_findings:
            cat = ai_f.classification.category
            family = self._get_rule_family(ai_f.identity.rule_id, cat)
            ai_fp = generate_fingerprint(
                self.project_root,
                ai_f.location.file,
                ai_f.location.line_start,
                ai_f.location.line_end,
                family,
                cat
            )
            ai_f.identity.fingerprint = ai_fp
            
            matched = False
            for stat_f in correlated:
                if stat_f.location.file == ai_f.location.file:
                    stat_family = self._get_rule_family(stat_f.identity.rule_id, stat_f.classification.category)
                    if stat_family == family:
                        # proximity check
                        if abs(stat_f.location.line_start - ai_f.location.line_start) <= 5:
                            if "ai-discovery" not in stat_f.analysis_source:
                                stat_f.analysis_source.append("ai-discovery")
                            stat_f.relationship = "correlated"
                            matched = True
                            break
            
            if not matched:
                ai_f.relationship = "ai-added"
                if "ai-discovery" not in ai_f.analysis_source:
                    ai_f.analysis_source.append("ai-discovery")
                correlated.append(ai_f)
            else:
                ai_f.relationship = "duplicate"
                
        return correlated
