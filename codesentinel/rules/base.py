from abc import ABC, abstractmethod
from typing import Any, List, Dict, Optional
import ast

from codesentinel.models.core import (
    Finding, Severity, FindingIdentity, FindingLocation, 
    FindingClassification, FindingContext, DataFlowInfo, FindingRemediation
)

class VariableTrace:
    """Tracks state of a variable within a scope for basic data-flow analysis."""
    def __init__(self, name: str):
        self.name = name
        self.is_constant = False
        self.is_sanitized = False
        self.dependencies: set[str] = set()
        self.path: List[str] = [name]

class RuleContext:
    """Context passed to rules containing file metadata and traversal state."""
    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None
        self.variable_traces: Dict[str, VariableTrace] = {}

    def get_line(self, line_number: int) -> str:
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""

    def get_surrounding_code(self, line_number: int, window: int = 2) -> str:
        start = max(1, line_number - window)
        end = min(len(self.lines), line_number + window)
        return "\n".join(self.lines[start-1:end])

class SecurityRule(ABC):
    """Base class for all security rules."""
    
    id: str
    name: str
    description: str
    language: str
    severity: Severity
    default_confidence: float
    remediation: str

    @abstractmethod
    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        """
        Analyze a specific AST node.
        Must return a list of Finding objects (empty list if no vulnerability).
        """
        pass

    def create_finding(
        self, 
        node: ast.AST, 
        context: RuleContext, 
        confidence: float = None, 
        data_flow: DataFlowInfo = None
    ) -> Finding:
        """Helper to construct a Finding from an AST node."""
        conf = confidence if confidence is not None else self.default_confidence
        
        line_start = getattr(node, 'lineno', 1)
        line_end = getattr(node, 'end_lineno', line_start)
        
        snippet = context.get_line(line_start).strip()
        surrounding = context.get_surrounding_code(line_start)
        
        df_info = data_flow or DataFlowInfo()

        return Finding(
            identity=FindingIdentity(
                id=f"{self.id}-{line_start}",
                rule_id=self.id,
                title=self.name
            ),
            location=FindingLocation(
                file=context.file_path,
                line_start=line_start,
                line_end=line_end
            ),
            classification=FindingClassification(
                category=self.id.split('.')[1],
                severity=self.severity,
                confidence=conf
            ),
            context=FindingContext(
                function_name=context.current_function,
                class_name=context.current_class,
                snippet=snippet,
                surrounding_code=surrounding
            ),
            data_flow=df_info,
            remediation=FindingRemediation(
                explanation=self.description,
                recommended_fix=self.remediation
            )
        )
