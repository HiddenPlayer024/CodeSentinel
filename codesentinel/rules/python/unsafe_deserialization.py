import ast
from codesentinel.analysis.ast_utils import resolve_call_name, is_dynamic_string
from codesentinel.analysis.taint import TaintConfig
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity

class UnsafeDeserializationRule(SecurityRule):
    id = "python.deserialization.unsafe"
    name = "Unsafe Deserialization"
    description = "Deserializing untrusted data can lead to arbitrary code execution."
    language = "python"
    severity = Severity.CRITICAL
    default_confidence = 0.85
    remediation = "Avoid using pickle or marshal for untrusted data. Use JSON or safe loaders like yaml.safe_load."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            module_name = node.func.value.id
            func_name = node.func.attr
            
            # Pickle / Marshal
            if module_name in ("pickle", "cPickle", "marshal") and func_name in ("load", "loads"):
                findings.append(self.create_finding(node, context))
                
            # PyYAML yaml.load without SafeLoader
            elif module_name == "yaml" and func_name == "load":
                # Check if Loader is passed safely
                is_safe = False
                for keyword in node.keywords:
                    if keyword.arg == "Loader":
                        if isinstance(keyword.value, ast.Attribute) and keyword.value.attr == "SafeLoader":
                            is_safe = True
                
                if not is_safe:
                    # In PyYAML 6+, yaml.load requires Loader, but using yaml.Loader is still unsafe
                    findings.append(self.create_finding(node, context))

        return findings
