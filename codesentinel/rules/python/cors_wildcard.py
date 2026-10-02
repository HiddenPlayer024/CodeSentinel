import ast
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class CorsWildcardRule(SecurityRule):
    id = "python.cors_wildcard"
    name = "CORS configured with wildcard origin"
    description = "Checks for cors_wildcard vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, 'id', getattr(node.func, 'attr', ''))
            if func_name in ('CORS', 'add_middleware'):
                for kw in node.keywords:
                    if kw.arg in ('allow_origins', 'origins'):
                        if isinstance(kw.value, ast.List):
                            for elt in kw.value.elts:
                                if isinstance(elt, ast.Constant) and elt.value == '*':
                                    findings.append(self.create_finding(node, context))
                        elif isinstance(kw.value, ast.Constant) and kw.value.value == '*':
                            findings.append(self.create_finding(node, context))
        return findings
