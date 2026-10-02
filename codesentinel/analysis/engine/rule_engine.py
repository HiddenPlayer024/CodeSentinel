import ast
from typing import List, Dict, Any, Type
import importlib
import pkgutil
import sys

from codesentinel.models.core import Finding
from codesentinel.rules.base import SecurityRule, RuleContext

class RuleEngine:
    def __init__(self):
        self.rules: Dict[str, List[SecurityRule]] = {}
        self._discover_rules()

    def _discover_rules(self):
        """Dynamically load all rules from codesentinel.rules."""
        try:
            import codesentinel.rules as rules_pkg
        except ImportError:
            return

        for _, module_name, is_pkg in pkgutil.walk_packages(rules_pkg.__path__, rules_pkg.__name__ + "."):
            if not is_pkg:
                try:
                    module = importlib.import_module(module_name)
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type) and issubclass(attr, SecurityRule) and attr is not SecurityRule:
                            # Instantiate and register the rule
                            rule_instance = attr()
                            lang = rule_instance.language
                            if lang not in self.rules:
                                self.rules[lang] = []
                            self.rules[lang].append(rule_instance)
                except Exception as e:
                    print(f"Failed to load rule module {module_name}: {e}", file=sys.stderr)

    def get_rules_for_language(self, language: str) -> List[SecurityRule]:
        return self.rules.get(language, [])

    def analyze_python_ast(self, tree: ast.AST, context: RuleContext) -> List[Finding]:
        """Traverse Python AST and run applicable rules."""
        findings = []
        active_rules = self.get_rules_for_language("python")
        
        if not active_rules:
            return findings

        from codesentinel.analysis.context.data_flow import DataFlowVisitor

        visitor = DataFlowVisitor(active_rules, context)
        visitor.visit(tree)
        return visitor.findings

    def analyze_config(self, context: RuleContext) -> List[Finding]:
        """Run config rules against the file content directly."""
        findings = []
        active_rules = self.get_rules_for_language("config")
        
        for rule in active_rules:
            try:
                rule_findings = rule.analyze(None, context)
                if rule_findings:
                    findings.extend(rule_findings)
            except Exception as e:
                import traceback
                traceback.print_exc()
                
        return findings
