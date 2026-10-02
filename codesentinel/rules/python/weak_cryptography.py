import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class WeakCryptographyRule(SecurityRule):
    id = "python.crypto.weak_cipher"
    name = "Weak Cryptographic Cipher"
    description = "Use of a broken or weak cryptographic algorithm (e.g., DES, RC4)."
    language = "python"
    severity = Severity.HIGH
    default_confidence = 0.95
    remediation = "Use AES (Advanced Encryption Standard) with a secure mode like GCM."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        # Check for Crypto.Cipher.DES.new() or similar PyCryptodome usage
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "new":
                # Is it called on DES, ARC4, ARC2, Blowfish?
                if isinstance(node.func.value, ast.Name):
                    if node.func.value.id in ("DES", "ARC4", "ARC2", "Blowfish", "DES3"):
                        findings.append(self.create_finding(node, context))
                elif isinstance(node.func.value, ast.Attribute):
                    if node.func.value.attr in ("DES", "ARC4", "ARC2", "Blowfish", "DES3"):
                        findings.append(self.create_finding(node, context))

        return findings
