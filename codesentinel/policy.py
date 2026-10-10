import yaml
import os
from typing import List, Dict, Any

class Policy:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.fail_on = ["CRITICAL", "HIGH"]
        self.max_new_high = 0
        self.allow_rules = []
        self.deny_rules = []
        self.load()
        
    def load(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r') as f:
                data = yaml.safe_load(f) or {}
                self.fail_on = data.get("fail_on", self.fail_on)
                self.max_new_high = data.get("max_new_high", self.max_new_high)
                self.allow_rules = data.get("allow_rules", self.allow_rules)
                self.deny_rules = data.get("deny_rules", self.deny_rules)

    def evaluate(self, findings: List[Any], new_findings: List[Any] = None) -> bool:
        """
        Evaluate policy against findings.
        Return True if PASS, False if FAIL.
        """
        new_findings = new_findings or []
        
        # Check rule deny list
        for f in findings:
            if hasattr(f, 'rule_id') and f.rule_id in self.deny_rules:
                return False
                
        new_high_count = 0
        for f in new_findings:
            sev = getattr(f, 'severity', '').upper()
            if hasattr(f, 'severity') and hasattr(f.severity, 'name'):
                sev = f.severity.name.upper()
                
            rule_id = getattr(f, 'rule_id', '')
            if rule_id in self.allow_rules:
                continue
                
            if sev in ["HIGH", "CRITICAL"]:
                if sev in self.fail_on or "HIGH" in self.fail_on:
                    new_high_count += 1
                
            if sev in self.fail_on:
                
                return False

        if new_high_count > self.max_new_high and ("HIGH" in self.fail_on or "CRITICAL" in self.fail_on):
            
            return False

        return True
