from enum import Enum
from typing import List, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingIdentity(BaseModel):
    id: str
    rule_id: str
    title: str

class FindingLocation(BaseModel):
    file: str
    line_start: int
    line_end: int

class FindingClassification(BaseModel):
    category: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)

class FindingContext(BaseModel):
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    snippet: str
    surrounding_code: Optional[str] = None

class DataFlowInfo(BaseModel):
    sources: List[str] = []
    sinks: List[str] = []
    sanitizers: List[str] = []
    propagation_path: List[str] = []

class FindingRemediation(BaseModel):
    explanation: str
    recommended_fix: str

class AIAssessment(BaseModel):
    is_likely_vulnerable: bool
    confidence_adjustment: float
    explanation: str
    false_positive_reason: Optional[str] = None

class Finding(BaseModel):
    identity: FindingIdentity
    location: FindingLocation
    classification: FindingClassification
    context: FindingContext
    data_flow: DataFlowInfo
    remediation: FindingRemediation
    ai_assessment: Optional[AIAssessment] = None
    analysis_source: List[str] = ["static-rule"]

    # Properties to maintain backward compatibility with CLI
    @property
    def id(self): return self.identity.id
    @property
    def rule_id(self): return self.identity.rule_id
    @property
    def severity(self): return self.classification.severity
    
    @property
    def confidence(self): 
        base_conf = self.classification.confidence
        if self.ai_assessment:
            adjusted = base_conf + self.ai_assessment.confidence_adjustment
            if not self.ai_assessment.is_likely_vulnerable:
                adjusted = min(adjusted, 0.2)
            return max(0.0, min(1.0, adjusted))
        return base_conf
        
    @property
    def file(self): return self.location.file
    @property
    def line_start(self): return self.location.line_start
    @property
    def title(self): return self.identity.title
    @property
    def description(self): return self.remediation.explanation
    @property
    def remediation_text(self): return self.remediation.recommended_fix
    
    # We construct a mock evidence object to satisfy older CLI code
    @property
    def evidence(self): 
        class MockEvidence:
            def __init__(self, snippet):
                self.snippet = snippet
        return MockEvidence(self.context.snippet)

class Project(BaseModel):
    path: str
    languages: List[str] = []
    file_count: int = 0
    scanned_files: List[str] = []

class ScanSession(BaseModel):
    id: str
    project: Project
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    findings: List[Finding] = []
    status: str = "running"
