import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class LoggingSecretsRule(SecurityRule):
    id = "python.logging_secrets"
    name = "Sensitive information logged"
    description = "Checks for logging_secrets vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = resolve_call_name(node)
            if func_name in ('debug', 'info', 'warning', 'error', 'critical', 'exception'):
                # Heuristic: Check if arguments contain password/secret
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if any(s in arg.id.lower() for s in ['password', 'secret', 'token', 'key']):
                            findings.append(self.create_finding(node, context))
        return findings
