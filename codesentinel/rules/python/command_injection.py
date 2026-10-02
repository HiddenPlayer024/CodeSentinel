import ast
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class CommandInjectionRule(SecurityRule):
    id = "python.command.injection"
    name = "Potential Command Injection"
    description = "Executing OS commands with untrusted or dynamically constructed input can lead to command injection."
    language = "python"
    severity = Severity.HIGH
    default_confidence = 0.7
    remediation = "Use subprocess.run with shell=False and pass arguments as a list. Avoid os.system and os.popen."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        # Check for os.system or os.popen
        func_name = self._get_func_name(node.func)
        if func_name in ("os.system", "os.popen"):
            # Check if argument is dynamic (not a simple string literal)
            if node.args and not isinstance(node.args[0], ast.Constant):
                findings.append(self.create_finding(node, context))
        
        # Check for subprocess.run, subprocess.Popen, etc. with shell=True
        elif func_name and func_name.startswith("subprocess."):
            has_shell_true = False
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    has_shell_true = True
                    break
            
            if has_shell_true:
                # If args[0] is dynamic (e.g. FormattedValue, BinOp, Name) -> command injection risk
                if node.args and not isinstance(node.args[0], (ast.Constant, ast.List, ast.Tuple)):
                    findings.append(self.create_finding(node, context, confidence=0.85))

        return findings

    def _get_func_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                return f"{node.value.id}.{node.attr}"
        return ""
