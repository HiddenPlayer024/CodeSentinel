import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class EvalExecRule(SecurityRule):
    id = "python.eval_exec"
    name = "eval, exec, compile or __import__ used safely?"
    description = "Checks for eval_exec vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ('eval', 'exec', 'compile', '__import__'):
                    # Check if arg is user-controlled (not a constant)
                    if node.args and not isinstance(node.args[0], ast.Constant):
                        findings.append(self.create_finding(node, context))
        return findings
