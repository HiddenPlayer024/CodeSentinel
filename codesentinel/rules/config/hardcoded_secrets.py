import re
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class ConfigHardcodedSecretsRule(SecurityRule):
    id = "config.hardcoded_secrets"
    name = "Hardcoded Secrets in Config"
    description = "Checks for hardcoded secrets in config files."
    language = "config"
    severity = "CRITICAL"
    default_confidence = 0.9
    remediation = "Use environment variables or a secret manager."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        secret_patterns = [
            r'AWS_ACCESS_KEY_ID=["\']?[A-Z0-9]{20}["\']?',
            r'AWS_SECRET_ACCESS_KEY=["\']?[A-Za-z0-9/+=]{40}["\']?',
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']'
        ]
        
        for i, line in enumerate(context.lines, 1):
            for pattern in secret_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # We create a dummy node with lineno
                    class DummyNode:
                        lineno = i
                        end_lineno = i
                    findings.append(self.create_finding(DummyNode(), context))
                    break
        return findings
