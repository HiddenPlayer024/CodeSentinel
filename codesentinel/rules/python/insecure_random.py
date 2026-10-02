import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class InsecureRandomRule(SecurityRule):
    id = "python.crypto.insecure_random"
    name = "Insecure Randomness"
    description = "The standard 'random' module is not cryptographically secure."
    language = "python"
    severity = Severity.LOW
    default_confidence = 0.5 # Low confidence as it might just be for a game or non-security use
    remediation = "Use the 'secrets' module for cryptographically secure random numbers."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        # Look for random.randint, random.choice, etc.
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "random":
                findings.append(self.create_finding(node, context))
                
        return findings
