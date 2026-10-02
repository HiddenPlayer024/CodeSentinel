import ast
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class SstiRule(SecurityRule):
    id = "python.ssti"
    name = "Server-Side Template Injection"
    description = "Checks for ssti vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id
            
            if func_name in ('render_template_string', 'Template'):
                if node.args and not isinstance(node.args[0], ast.Constant):
                    findings.append(self.create_finding(node, context))
        return findings
