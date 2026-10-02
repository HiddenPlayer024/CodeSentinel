import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class XxeRule(SecurityRule):
    id = "python.xxe"
    name = "XML External Entity injection"
    description = "Checks for xxe vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = resolve_call_name(node)
            if func_name in ('parse', 'parseString', 'fromstring'):
                # Many standard lib XML parsers are vulnerable by default
                findings.append(self.create_finding(node, context))
        return findings
