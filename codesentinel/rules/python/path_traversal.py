import ast
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class PathTraversalRule(SecurityRule):
    id = "python.path.traversal"
    name = "Potential Path Traversal"
    description = "Opening files using dynamically constructed paths may allow attackers to read arbitrary files."
    language = "python"
    severity = Severity.HIGH
    default_confidence = 0.6
    remediation = "Validate and sanitize user input before using it in file paths. Use os.path.abspath and os.path.commonprefix to restrict paths."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        # Check for open()
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args:
                arg = node.args[0]
                is_vulnerable = False
                
                # Check for dynamic string concatenation
                if isinstance(arg, ast.JoinedStr): # f-string
                    is_vulnerable = True
                elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)): # + or %
                    is_vulnerable = True
                elif isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format":
                    is_vulnerable = True
                    
                if is_vulnerable:
                    findings.append(self.create_finding(node, context))

        return findings
