import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class InsecureHashRule(SecurityRule):
    id = "python.crypto.insecure_hash"
    name = "Insecure Cryptographic Hash"
    description = "Use of weak or broken cryptographic hash functions (e.g., MD5, SHA1)."
    language = "python"
    severity = Severity.MEDIUM
    default_confidence = 0.9
    remediation = "Use stronger hashing algorithms like SHA-256 or SHA-3. For passwords, use bcrypt, argon2, or scrypt."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        # Check for hashlib.md5 or hashlib.sha1
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "hashlib":
                if node.func.attr in ("md5", "sha1"):
                    findings.append(self.create_finding(node, context))
        
        # Check for hashlib.new('md5')
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
             if node.func.value.id == "hashlib" and node.func.attr == "new":
                 if node.args and isinstance(node.args[0], ast.Constant):
                     algo = str(node.args[0].value).lower()
                     if algo in ("md5", "sha1"):
                         findings.append(self.create_finding(node, context))

        return findings
