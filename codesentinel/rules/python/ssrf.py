import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class SsrfRule(SecurityRule):
    id = "python.ssrf"
    name = "SSRF vulnerability via unvalidated URL requests"
    description = "Checks for ssrf vulnerabilities."
    language = "python"
    severity = "HIGH"
    default_confidence = 0.8
    remediation = "Fix the vulnerable usage."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if isinstance(node, ast.Call):
            func_name = resolve_call_name(node)
                
            ssrf_sinks = {"requests.get", "requests.post", "httpx.get", "httpx.post", "urlopen", "urllib.request.urlopen"}
            if func_name in ssrf_sinks:
                if node.args:
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant):
                        return findings
                    # Check if it's an f-string (JoinedStr) with a hardcoded absolute URL prefix
                    if isinstance(arg, ast.JoinedStr):
                        if arg.values and isinstance(arg.values[0], ast.Constant):
                            val = arg.values[0].value
                            if isinstance(val, str) and (val.startswith("http://") or val.startswith("https://")):
                                import urllib.parse
                                parsed = urllib.parse.urlparse(val)
                                # Ensure the authority is fully hardcoded and terminated (by a path, query, or fragment)
                                # If it's not terminated, interpolation could modify the hostname (e.g. appending ".evil.com" or "@evil.com")
                                if bool(parsed.netloc) and (bool(parsed.path) or bool(parsed.query) or bool(parsed.fragment)):
                                    return findings

                    findings.append(self.create_finding(node, context))

        return findings
