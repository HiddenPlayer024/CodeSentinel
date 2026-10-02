import re
from pathlib import Path
from codesentinel.models.core import Finding, FindingIdentity, FindingLocation, FindingClassification, FindingContext, FindingRemediation, DataFlowInfo

class DependencyAnalyzer:
    def __init__(self):
        pass

    def check_requirements_txt(self, path: str, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            line = line.strip()
            # Ignore comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Simple check for unpinned dependencies (no ==, >=, etc.)
            if not re.search(r'[=<>~!]', line):
                findings.append(Finding(
                    identity=FindingIdentity(
                        id=f"dep.unpinned-{i}",
                        rule_id="dep.unpinned",
                        title="Unpinned Dependency"
                    ),
                    location=FindingLocation(
                        file=path,
                        line_start=i,
                        line_end=i
                    ),
                    classification=FindingClassification(
                        category="dependencies",
                        severity="MEDIUM",
                        confidence=0.9
                    ),
                    context=FindingContext(
                        snippet=line,
                    ),
                    data_flow=DataFlowInfo(),
                    remediation=FindingRemediation(
                        explanation="Dependency is unpinned, which can lead to unpredictable builds and security risks from malicious updates.",
                        recommended_fix="Pin the dependency to a specific version or version range."
                    )
                ))
        return findings

    def check_package_json(self, path: str, content: str) -> List[Finding]:
        # Would implement similar logic for package.json here (or integrate with OSV later)
        return []

    def analyze(self, file_path: str, content: str) -> List[Finding]:
        if file_path.endswith("requirements.txt"):
            return self.check_requirements_txt(file_path, content)
        elif file_path.endswith("package.json"):
            return self.check_package_json(file_path, content)
        return []
