from typing import List
import hashlib
from codesentinel.models.core import Finding

class Correlator:
    def __init__(self):
        pass
        
    def _generate_fingerprint(self, finding: Finding) -> str:
        # Normalize file and line
        category = finding.classification.category
        normalized_file = finding.location.file.split('/')[-1]
        normalized_line = str(finding.location.line_start)
        # rule family (e.g. "sql.injection" from "python.sql.injection" or "ai.sqli")
        # simplistic approach to get a family:
        # 'python.sql.injection' -> 'sql.injection'
        # 'ai.sqli' -> 'sqli' (maybe map them?)
        # For simplicity, we can extract common keywords
        cat = category.lower()
        if "sql" in cat or "sqli" in cat:
            rule_family = "sqli"
        elif "path" in cat or "traversal" in cat:
            rule_family = "path_traversal"
        elif "ssrf" in cat:
            rule_family = "ssrf"
        elif "xss" in cat:
            rule_family = "xss"
        elif "command" in cat or "injection" in cat:
            rule_family = "cmd_injection"
        else:
            rule_family = cat
            
        fp_string = f"{category}:{normalized_file}:{normalized_line}:{rule_family}"
        return hashlib.sha256(fp_string.encode('utf-8')).hexdigest()

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
        If a static finding matches an AI discovery, mark its analysis_source as ["static-rule", "ai-discovery"].
        Base correlation on fingerprint = hash(category, normalized_file, normalized_line, rule_family).
        """
        correlated = list(static_findings)
        
        for f in correlated:
            if not f.identity.fingerprint:
                cat = f.classification.category
                norm_file = f.location.file.split('/')[-1]
                norm_line = str(f.location.line_start)
                family = self._get_rule_family(f.identity.rule_id, cat)
                fp_str = f"{cat}:{norm_file}:{norm_line}:{family}"
                f.identity.fingerprint = str(hash((cat, norm_file, norm_line, family)))
                
        for ai_f in ai_findings:
            cat = ai_f.classification.category
            norm_file = ai_f.location.file.split('/')[-1]
            norm_line = str(ai_f.location.line_start)
            family = self._get_rule_family(ai_f.identity.rule_id, cat)
            ai_fingerprint = str(hash((cat, norm_file, norm_line, family)))
            ai_f.identity.fingerprint = ai_fingerprint
            
            matched = False
            for stat_f in correlated:
                # Merge intelligently based on file, rule family, and proximity
                if stat_f.location.file == ai_f.location.file:
                    stat_family = self._get_rule_family(stat_f.identity.rule_id, stat_f.classification.category)
                    
                    # Merge intelligently (Static SQLi + AI SQLi = merged; Static path traversal + AI SSRF = do not merge).
                    if stat_family == family:
                        if abs(stat_f.location.line_start - ai_f.location.line_start) <= 5:
                            if "ai-discovery" not in stat_f.analysis_source:
                                stat_f.analysis_source.append("ai-discovery")
                            matched = True
                            break
            
            if not matched:
                correlated.append(ai_f)
                
        return correlated
