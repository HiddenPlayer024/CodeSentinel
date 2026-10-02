import ast
from typing import Optional, List, Tuple

def resolve_call_name(node: ast.Call) -> str:
    """Resolve the fully qualified name of a called function if possible."""
    return _get_expr_name(node.func)

def _get_expr_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        base = _get_expr_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return ""

def is_dynamic_string(node: ast.expr) -> bool:
    """Check if an expression is a dynamically constructed string (e.g. f-string, concat, .format)."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            return True
    return False

def resolve_import_alias(name: str, aliases: List[ast.alias]) -> str:
    """Resolve an import alias to its actual name."""
    for alias in aliases:
        if alias.asname == name:
            return alias.name
        if alias.name == name:
            return alias.name
    return name
