import ast
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class DebugModeRule(SecurityRule):
    id = "python.debug_mode"
    name = "Running framework in Debug mode"
    description = "Checks for debug_mode vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = getattr(node.func, 'attr', '')
            if func_name == 'run':
                for kw in node.keywords:
                    if kw.arg == 'debug' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        findings.append(self.create_finding(node, context))
        return findings
