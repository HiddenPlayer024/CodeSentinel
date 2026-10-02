import ast
from typing import Dict, List, Set, Any

from codesentinel.rules.base import RuleContext, VariableTrace

class DataFlowVisitor(ast.NodeVisitor):
    """
    Traverses the AST to build context and variable traces, 
    and applies rules at each node.
    """
    def __init__(self, rules: List[Any], context: RuleContext):
        self.rules = rules
        self.context = context
        self.findings = []
        
        self.class_stack = []
        self.func_stack = []
        
        # Sinks mapping category to common sink function patterns
        self.sinks = {
            "subprocess": {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call", "os.system", "os.popen", "os.execv"},
            "filesystem": {"open", "os.open", "os.remove", "os.rename", "shutil.rmtree"},
            "networking": {"requests.get", "requests.post", "urllib.request.urlopen", "httpx.get", "httpx.post", "aiohttp.ClientSession.get"},
            "rendering": {"render_template_string", "jinja2.Template"}
        }

    def _resolve_name(self, name: str) -> str:
        """Resolve a name using import aliases."""
        parts = name.split('.')
        base = parts[0]
        if base in self.context.import_aliases:
            parts[0] = self.context.import_aliases[base]
            return ".".join(parts)
        return name

    def is_sink(self, node: ast.Call, category: str = None) -> bool:
        """Check if a call node is a recognized sink, optionally filtering by category."""
        if not isinstance(node, ast.Call):
            return False
            
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr
                
        resolved_name = self._resolve_name(func_name)
        
        if category and category in self.sinks:
            return resolved_name in self.sinks[category] or func_name in self.sinks[category]
            
        for cat_sinks in self.sinks.values():
            if resolved_name in cat_sinks or func_name in cat_sinks:
                return True
                
        return False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.context.import_aliases[name] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        module = node.module or ""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.context.import_aliases[name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.class_stack.append(node.name)
        self.context.current_class = node.name
        self.generic_visit(node)
        self.class_stack.pop()
        self.context.current_class = self.class_stack[-1] if self.class_stack else None

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.func_stack.append(node.name)
        self.context.current_function = node.name
        
        # Reset variable traces for new function scope
        old_traces = self.context.variable_traces
        self.context.variable_traces = {}
        
        # Mark arguments as sources
        for arg in node.args.args:
            trace = VariableTrace(arg.arg)
            trace.is_constant = False
            self.context.variable_traces[arg.arg] = trace
            
        self.generic_visit(node)
        
        self.func_stack.pop()
        self.context.current_function = self.func_stack[-1] if self.func_stack else None
        # Restore old scope
        self.context.variable_traces = old_traces

    def visit_Assign(self, node: ast.Assign):
        # We need to visit the value to see if it contains dependencies or constants
        self.visit(node.value)
        
        # Analyze the assigned value
        is_constant = False
        is_sanitized = False
        deps = set()
        
        if isinstance(node.value, ast.Constant):
            is_constant = True
        elif isinstance(node.value, ast.Name):
            deps.add(node.value.id)
            if node.value.id in self.context.variable_traces:
                tr = self.context.variable_traces[node.value.id]
                is_constant = tr.is_constant
                is_sanitized = tr.is_sanitized
                deps.update(tr.dependencies)
        elif isinstance(node.value, ast.BinOp):
            # A simple heuristic: if it's an operation involving variables, combine dependencies
            # We don't fully recurse here for MVP, just grab direct names
            for child in ast.walk(node.value):
                if isinstance(child, ast.Name):
                    deps.add(child.id)
                    if child.id in self.context.variable_traces:
                        tr = self.context.variable_traces[child.id]
                        deps.update(tr.dependencies)
                        if tr.is_sanitized:
                            is_sanitized = True
        elif isinstance(node.value, ast.Call):
            # Check for sanitization
            func_name = ""
            if isinstance(node.value.func, ast.Name):
                func_name = node.value.func.id
            elif isinstance(node.value.func, ast.Attribute):
                func_name = node.value.func.attr
                
            if func_name.lower() in ("sanitize", "escape", "quote"):
                is_sanitized = True
            
            for child in ast.walk(node.value):
                if isinstance(child, ast.Name) and child is not node.value.func:
                    deps.add(child.id)
                    if child.id in self.context.variable_traces:
                        deps.update(self.context.variable_traces[child.id].dependencies)
                        
        # Now apply this state to all targets
        for target in node.targets:
            if isinstance(target, ast.Name):
                trace = VariableTrace(target.id)
                trace.is_constant = is_constant
                trace.is_sanitized = is_sanitized
                trace.dependencies = deps
                # For path, we just trace 1 level deep for now
                trace.path = [target.id] + list(deps)
                self.context.variable_traces[target.id] = trace

        # Also visit the targets just in case
        for target in node.targets:
            self.visit(target)
            
        self._apply_rules(node)

    def visit(self, node: ast.AST):
        """Override visit to apply rules to EVERY node after traversal."""
        method_name = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method_name, None)
        if visitor:
            visitor(node)
        else:
            self.generic_visit(node)
            self._apply_rules(node)
            
    def _apply_rules(self, node: ast.AST):
        for rule in self.rules:
            try:
                rule_findings = rule.analyze(node, self.context)
                if rule_findings:
                    for f in rule_findings:
                        # Extract source context to check for suppression comments
                        combined_text = (f.context.snippet + (f.context.surrounding_code or "")).lower()
                        if "# codesentinel:ignore" not in combined_text and "# nosec" not in combined_text:
                            self.findings.append(f)
            except Exception as e:
                import traceback
                traceback.print_exc()
