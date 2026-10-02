import re
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class DockerfileRootUserRule(SecurityRule):
    id = "config.docker_root"
    name = "Dockerfile runs as root"
    description = "Checks if Dockerfile runs as root without USER instruction."
    language = "config"
    severity = "MEDIUM"
    default_confidence = 0.8
    remediation = "Add a USER instruction to change to a non-root user."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not context.file_path.endswith('Dockerfile'):
            return findings
            
        has_user = False
        for line in context.lines:
            if line.strip().startswith('USER '):
                has_user = True
                break
                
        if not has_user:
            class DummyNode:
                lineno = 1
                end_lineno = 1
            findings.append(self.create_finding(DummyNode(), context))
            
        return findings
