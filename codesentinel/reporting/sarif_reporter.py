import json
from pathlib import Path

from codesentinel.models.core import ScanSession, Severity
from .base import BaseReporter

class SarifReporter(BaseReporter):
    """Generates a SARIF v2.1.0 formatted report."""
    
    def _map_severity(self, severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note"
        }
        return mapping.get(severity, "note")

    def generate(self, session: ScanSession, output_path: Path) -> None:
        
        # Build rules taxonomy
        rules = {}
        for f in session.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.remediation.explanation},
                    "help": {"text": f.remediation.recommended_fix},
                    "properties": {
                        "category": f.classification.category,
                        "severity": f.classification.severity.value
                    }
                }
        
        results = []
        for f in session.findings:
            msg_text = f"[{f.confidence*100:.0f}% confidence] {f.title}: {f.remediation.explanation}"
            if f.ai_assessment:
                if f.ai_assessment.is_likely_vulnerable:
                    msg_text += f"\n\nAI Analysis: {f.ai_assessment.explanation}"
                else:
                    msg_text += f"\n\nAI Note (Likely False Positive): {f.ai_assessment.false_positive_reason}"
                    
            results.append({
                "ruleId": f.rule_id,
                "level": self._map_severity(f.severity),
                "message": {
                    "text": msg_text
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.file
                        },
                        "region": {
                            "startLine": f.location.line_start,
                            "endLine": f.location.line_end,
                            "snippet": {
                                "text": f.context.snippet
                            }
                        }
                    }
                }]
            })
            
        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeSentinel",
                            "informationUri": "https://github.com/codesentinel",
                            "version": "0.1.0",
                            "rules": list(rules.values())
                        }
                    },
                    "results": results
                }
            ]
        }
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2)
