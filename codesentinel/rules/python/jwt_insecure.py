import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class JwtInsecureRule(SecurityRule):
    id = "python.jwt_insecure"
    name = "Insecure JWT validation"
    description = "Checks for jwt_insecure vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = resolve_call_name(node)
            if func_name == 'decode':
                for kw in node.keywords:
                    if kw.arg == 'verify_signature' and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        findings.append(self.create_finding(node, context))
                    if kw.arg == 'algorithms' and isinstance(kw.value, ast.List):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and str(elt.value).lower() == 'none':
                                findings.append(self.create_finding(node, context))
        return findings
