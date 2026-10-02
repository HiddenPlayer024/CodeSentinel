import re
from typing import List, Any
from codesentinel.rules.base import SecurityRule, RuleContext, Finding

class GHActionsUntrustedDataRule(SecurityRule):
    id = "ci.gh_actions_untrusted_data"
    name = "Untrusted PR Data in GitHub Actions"
    description = "Checks for untrusted pull request data interpolated directly into shell commands."
    language = "config"
    severity = "HIGH"
    default_confidence = 0.85
    remediation = "Bind untrusted data to an intermediate environment variable rather than inline string interpolation."

    def analyze(self, node: Any, context: RuleContext) -> List[Finding]:
        findings = []
        if not (context.file_path.endswith(".yml") or context.file_path.endswith(".yaml")):
            return findings
        
        # Check if it's a GitHub action file (simple heuristic: in .github/workflows or has typical structure)
        # Even simpler, just look for the vulnerable patterns
        untrusted_patterns = [
            r'\${{\s*github\.event\.pull_request\.title\s*}}',
            r'\${{\s*github\.event\.pull_request\.body\s*}}',
            r'\${{\s*github\.event\.comment\.body\s*}}'
        ]
        
        # We need to ensure this is used in a run step directly.
        # A simple check: line contains 'run:' and the pattern
        for i, line in enumerate(context.lines, 1):
            if "run:" in line:
                for pattern in untrusted_patterns:
                    if re.search(pattern, line):
                        class DummyNode:
                            lineno = i
                            end_lineno = i
                        findings.append(self.create_finding(DummyNode(), context))
                        break
        return findings
