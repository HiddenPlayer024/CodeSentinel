import ast
from typing import List, Any

from codesentinel.rules.base import SecurityRule, RuleContext
from codesentinel.models.core import Finding, Severity, DataFlowInfo

class SQLInjectionRule(SecurityRule):
    id = "python.sql.injection"
    name = "Potential SQL Injection"
    description = "Constructing SQL queries by concatenating or formatting strings with untrusted input."
    language = "python"
    severity = Severity.HIGH
    default_confidence = 0.65
    remediation = "Use parameterized queries or prepared statements (e.g., execute('SELECT * FROM users WHERE id=?', (user_id,)))."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not isinstance(node, ast.Call):
            return findings

        # Check for cursor.execute or conn.execute
        if isinstance(node.func, ast.Attribute) and node.func.attr == "execute":
            if node.args:
                arg = node.args[0]
                is_vulnerable = False
                df_info = DataFlowInfo(sinks=["execute"])
                confidence = self.default_confidence
                
                # Directly vulnerable constructs
                if isinstance(arg, ast.JoinedStr) or \
                   (isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Mod, ast.Add))) or \
                   (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute) and arg.func.attr == "format"):
                    is_vulnerable = True
                    df_info.sources.append("inline_formatting")
                    confidence += 0.1 # Direct injection
                    
                # Indirect via variable
                elif isinstance(arg, ast.Name):
                    var_name = arg.id
                    if var_name in context.variable_traces:
                        trace = context.variable_traces[var_name]
                        df_info.propagation_path = trace.path
                        
                        if trace.is_constant:
                            is_vulnerable = True
                            confidence -= 0.5 # It's just a constant string
                            df_info.sources.append("constant")
                        else:
                            is_vulnerable = True
                            df_info.sources.extend(list(trace.dependencies))
                            
                            if trace.is_sanitized:
                                confidence -= 0.4
                                df_info.sanitizers.append("sanitized")
                            else:
                                confidence += 0.2
                    else:
                        # We don't have trace (e.g. global or argument), assume potentially risky
                        is_vulnerable = True
                        confidence -= 0.2

                if is_vulnerable:
                    # Bound confidence
                    confidence = max(0.0, min(1.0, confidence))
                    findings.append(self.create_finding(node, context, confidence=confidence, data_flow=df_info))

        return findings
