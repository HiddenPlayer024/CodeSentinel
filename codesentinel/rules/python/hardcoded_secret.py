import ast
from typing import List, Any
import re

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class HardcodedSecretRule(SecurityRule):
    id = "python.secret.hardcoded"
    name = "Hardcoded Secret"
    description = "Hardcoded credentials or API keys found in source code."
    language = "python"
    severity = Severity.CRITICAL
    default_confidence = 0.8
    remediation = "Use environment variables or a secure secret management system instead of hardcoding secrets."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Assign):
            return findings

        # Check if right side is a string constant
        if not isinstance(node.value, ast.Constant) or not isinstance(node.value.value, str):
            return findings

        value_str = node.value.value
        if len(value_str) < 8 or len(value_str) > 100:
            return findings # Ignore very short or very long strings

        # Check left side targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                name = target.id.lower()
                # Basic heuristic for secret names
                if any(kw in name for kw in ['secret', 'token', 'api_key', 'password', 'credentials']):
                    # Ensure it's not an empty string or generic placeholder
                    if value_str.lower() not in ('', 'test', 'password', 'secret', 'changeme'):
                        # Mask the secret value to prevent leakage
                        finding = self.create_finding(node, context)
                        masked_value = value_str[:4] + "***" if len(value_str) > 4 else "***"
                        finding.context.snippet = finding.context.snippet.replace(value_str, masked_value)
                        if finding.context.surrounding_code:
                            finding.context.surrounding_code = finding.context.surrounding_code.replace(value_str, masked_value)
                        findings.append(finding)
                        
        return findings
