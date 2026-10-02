import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class FilePermissionsRule(SecurityRule):
    id = "python.file_permissions"
    name = "Insecure file permissions"
    description = "Checks for file_permissions vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = resolve_call_name(node)
            if func_name.endswith('chmod'):
                if len(node.args) >= 2:
                    mode = node.args[1]
                    if isinstance(mode, ast.Constant) and mode.value == 0o777:
                        findings.append(self.create_finding(node, context))
        return findings
