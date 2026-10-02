import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class TlsVerifyRule(SecurityRule):
    id = "python.tls_verify"
    name = "Insecure TLS validation"
    description = "Checks for tls_verify vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == 'verify' and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    findings.append(self.create_finding(node, context))
            
            if isinstance(node.func, ast.Attribute) and node.func.attr == '_create_unverified_context':
                findings.append(self.create_finding(node, context))
        return findings
