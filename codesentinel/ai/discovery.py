from typing import List
from pathlib import Path
from pydantic import BaseModel
import uuid
import os

from codesentinel.models.core import (
    Finding, FindingIdentity, FindingLocation, FindingClassification,
    FindingContext, DataFlowInfo, FindingRemediation, Severity, ScanSession
)
from codesentinel.ai.providers import AIProvider

DISCOVERY_SYSTEM_PROMPT = """You are an expert Application Security Engine.
You perform security discovery on code provided to you.
Analyze the code and identify potential vulnerabilities (focusing on HTTP routes, DB queries, subprocess calls).
Return your findings strictly adhering to the requested JSON schema.
"""

class DiscoveredVulnerability(BaseModel):
    title: str
    category: str
    severity: Severity
    confidence: float
    file: str
    line_start: int
    line_end: int
    evidence: str
    explanation: str
    recommended_fix: str

class DiscoveryResult(BaseModel):
    vulnerabilities: List[DiscoveredVulnerability]

class AIDiscoveryEngine:
    def __init__(self, provider: AIProvider, project_path: str):
        self.provider = provider
        self.project_path = Path(project_path)

    def _get_files_to_scan(self) -> List[Path]:
        files = []
        # Priority scanning (simple implementation)
        for root, dirs, filenames in os.walk(self.project_path):
            if '.venv' in root or '.git' in root or '__pycache__' in root:
                continue
            for filename in filenames:
                if filename.endswith('.py'):
                    files.append(Path(root) / filename)
        return files

    def run_discovery(self, session: ScanSession) -> List[Finding]:
        findings = []
        files = self._get_files_to_scan()
        
        for file_path in files:
            try:
                content = file_path.read_text()
            except Exception:
                continue
                
            prompt = f"Analyze the following code for vulnerabilities.\n\nFile: {file_path.relative_to(self.project_path)}\n\nCode:\n{content}"
            
            try:
                result = self.provider.generate_structured_response(prompt, DiscoveryResult, system_prompt=DISCOVERY_SYSTEM_PROMPT)
                if not result:
                    continue
                
                # Check for structure (dict or BaseModel)
                if hasattr(result, 'model_dump'):
                    result = result.model_dump()
                elif hasattr(result, 'dict'):
                    result = result.dict()
                
                vulns = result.get('vulnerabilities', [])
                for v in vulns:
                    rel_file = file_path.relative_to(self.project_path)
                    if v.get('file') != str(rel_file):
                        # Ensure we don't allow arbitrary paths
                        v['file'] = str(rel_file)
                        
                    finding = Finding(
                        identity=FindingIdentity(
                            id=str(uuid.uuid4()),
                            rule_id=f"ai-{v.get('category', 'vuln').lower()}",
                            title=v.get('title', 'AI Discovered Vulnerability')
                        ),
                        location=FindingLocation(
                            file=v.get('file'),
                            line_start=v.get('line_start', 1),
                            line_end=v.get('line_end', 1)
                        ),
                        classification=FindingClassification(
                            category=v.get('category', 'Security'),
                            severity=v.get('severity', Severity.MEDIUM),
                            confidence=v.get('confidence', 0.5)
                        ),
                        context=FindingContext(
                            snippet=v.get('evidence', '')
                        ),
                        data_flow=DataFlowInfo(),
                        remediation=FindingRemediation(
                            explanation=v.get('explanation', ''),
                            recommended_fix=v.get('recommended_fix', '')
                        ),
                        analysis_source=["ai-discovery"]
                    )
                    findings.append(finding)
            except Exception as e:
                print(f"Error in discovery for {file_path}: {e}")
                
        return findings
