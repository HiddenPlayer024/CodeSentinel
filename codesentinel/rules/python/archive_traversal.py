import ast
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class ArchiveTraversalRule(SecurityRule):
    id = "python.archive_traversal"
    name = "Unsafe archive extraction (ZipSlip)"
    description = "Checks for archive_traversal vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == 'extractall':
                findings.append(self.create_finding(node, context))
        return findings
