import ast
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class UnsafeRedirectRule(SecurityRule):
    id = "python.unsafe_redirect"
    name = "Unvalidated redirects or forwards"
    description = "Checks for unsafe_redirect vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, 'attr', getattr(node.func, 'id', ''))
            if func_name in ('redirect', 'HttpResponseRedirect'):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    findings.append(self.create_finding(node, context))
        return findings
