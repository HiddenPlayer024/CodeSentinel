import ast
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class PasswordStorageRule(SecurityRule):
    id = "python.password_storage"
    name = "Insecure password hashing/storage"
    description = "Checks for password_storage vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, 'attr', getattr(node.func, 'id', ''))
            if func_name in ('md5', 'sha1'):
                findings.append(self.create_finding(node, context))
        return findings
