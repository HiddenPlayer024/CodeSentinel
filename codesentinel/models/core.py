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
    fingerprint: Optional[str] = None

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
    is_test_fixture: bool = False

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
    relationship: str = "standalone"

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
    source_type: str = "local"
    repository_url: Optional[str] = None
    ref: Optional[str] = None

class ScanSession(BaseModel):
    id: str
    project: Project
    start_time: datetime
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    findings: List[Finding] = []
    status: str = "running"
    
    # Metadata
    analysis_version: str = "2.2.0"
    static_rule_count: int = 0
    ai_enabled: bool = False
    ai_mode: Optional[str] = None
    ai_provider: Optional[str] = None
    
    # Basic Metrics
    static_findings_count: int = 0
    ai_findings_count: int = 0
    verified_findings_count: int = 0
    
    # AI Telemetry
    ai_files_considered: int = 0
    ai_files_selected: int = 0
    ai_review_units_created: int = 0
    ai_review_units_scanned: int = 0
    ai_candidate_findings: int = 0
    ai_valid_findings: int = 0
    ai_rejected_findings: int = 0
    ai_added_findings: int = 0
    ai_correlated_findings: int = 0
    ai_duplicate_findings: int = 0
    ai_invalid_locations: int = 0
    ai_provider_calls: int = 0
    ai_provider_errors: int = 0
    ai_timeout_count: int = 0
    ai_redacted_secrets: int = 0
    ai_input_tokens: int = 0
    ai_output_tokens: int = 0
    
    # Legacy metric mappings to prevent breakages
    @property
    def correlated_findings(self): return self.ai_correlated_findings
    @correlated_findings.setter
    def correlated_findings(self, v): self.ai_correlated_findings = v
    @property
    def duplicate_ai_findings(self): return self.ai_duplicate_findings
    @duplicate_ai_findings.setter
    def duplicate_ai_findings(self, v): self.ai_duplicate_findings = v
    @property
    def invalid_ai_locations(self): return self.ai_invalid_locations
    @invalid_ai_locations.setter
    def invalid_ai_locations(self, v): self.ai_invalid_locations = v
    @property
    def provider_errors(self): return self.ai_provider_errors
    @provider_errors.setter
    def provider_errors(self, v): self.ai_provider_errors = v
