import os
from typing import List
from codesentinel.models.core import Finding, ScanSession
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

    def correlate(self, session: ScanSession, static_findings: List[Finding], ai_findings: List[Finding]) -> List[Finding]:
        """
        Merge identical Static findings and AI discoveries.
        Staged correlation: Exact match -> Evidence overlap -> Same family -> Source/sink comp -> Proximity.
        Assign Finding.correlation_reason.
        Use fingerprinting to track duplicates. Keep the first canonical AI finding, 
        increment session.ai_duplicate_findings for others, and drop them.
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
            
        unique_ai_findings = []
        ai_seen_fps = set()
        
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
            
            if ai_fp in ai_seen_fps:
                session.ai_duplicate_findings += 1
            else:
                ai_seen_fps.add(ai_fp)
                unique_ai_findings.append(ai_f)

        for ai_f in unique_ai_findings:
            matched = False
            family = self._get_rule_family(ai_f.identity.rule_id, ai_f.classification.category)
            
            for stat_f in correlated:
                if stat_f.location.file != ai_f.location.file:
                    continue
                
                stat_family = self._get_rule_family(stat_f.identity.rule_id, stat_f.classification.category)
                reason = None
                
                # For correlation, we MUST require same family
                if stat_family != family:
                    continue
                    
                # 1. Exact match
                if stat_f.location.line_start == ai_f.location.line_start and stat_f.location.line_end == ai_f.location.line_end:
                    reason = "Exact match"
                # 2. Evidence overlap
                elif stat_f.context.snippet and ai_f.context.snippet and (stat_f.context.snippet in ai_f.context.snippet or ai_f.context.snippet in stat_f.context.snippet):
                    reason = "Evidence overlap"
                # 3. Same family line overlap
                elif max(stat_f.location.line_start, ai_f.location.line_start) <= min(stat_f.location.line_end, ai_f.location.line_end):
                    reason = "Same family"
                # 4. Source/sink comp
                elif stat_f.data_flow.sources and ai_f.data_flow.sources and set(stat_f.data_flow.sources).intersection(ai_f.data_flow.sources):
                    reason = "Source/sink comp"
                # 5. Proximity (fallback)
                elif stat_family == family and abs(stat_f.location.line_start - ai_f.location.line_start) <= 5:
                    reason = "Proximity"

                if reason:
                    if "ai-discovery" not in stat_f.analysis_source:
                        stat_f.analysis_source.append("ai-discovery")
                    stat_f.relationship = "correlated"
                    if reason not in stat_f.correlation_reason:
                        stat_f.correlation_reason.append(reason)
                    matched = True
                    break
            
            if not matched:
                ai_f.relationship = "ai-added"
                if "ai-discovery" not in ai_f.analysis_source:
                    ai_f.analysis_source.append("ai-discovery")
                correlated.append(ai_f)
                
        return correlated
