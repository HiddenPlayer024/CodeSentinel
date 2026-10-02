import re
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class PackageJsonPermissiveRule(SecurityRule):
    id = "config.package_json"
    name = "Permissive versions in package.json"
    description = "Checks for overly permissive dependency versions."
    language = "config"
    severity = "LOW"
    default_confidence = 0.8
    remediation = "Pin dependencies."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not context.file_path.endswith('package.json'):
            return findings
            
        for i, line in enumerate(context.lines, 1):
            if '": "*"' in line or '": ">' in line:
                class DummyNode:
                    lineno = i
                    end_lineno = i
                findings.append(self.create_finding(DummyNode(), context))
                
        return findings
