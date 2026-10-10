import subprocess
from typing import List, Dict, Any, Set, Tuple
import os

def parse_git_diff(base: str, head: str, cwd: str) -> Dict[str, List[Tuple[int, int]]]:
    """Parse git diff between base and head to find changed files and their modified line ranges."""
    changed = {}
    try:
        diff_output = subprocess.check_output(
            ["git", "diff", f"{base}..{head}"],
            cwd=cwd,
            text=True
        )
        current_file = None
        for line in diff_output.splitlines():
            if line.startswith("+++ b/"):
                current_file = line[6:]
                changed[current_file] = []
            elif line.startswith("@@ ") and current_file:
                # @@ -a,b +c,d @@
                parts = line.split(" ")
                if len(parts) >= 3:
                    added = parts[2]
                    if added.startswith("+"):
                        added = added[1:]
                        if "," in added:
                            start, length = added.split(",")
                        else:
                            start, length = added, "1"
                        start = int(start)
                        length = int(length)
                        changed[current_file].append((start, start + length - 1))
    except Exception as e:
        print(f"Error parsing git diff: {e}")
    return changed

def categorize_findings(
    base_findings: List[Any],
    head_findings: List[Any],
    changed_files: Dict[str, List[Tuple[int, int]]]
) -> Dict[str, List[Any]]:
    """
    Categorize findings into:
    - New
    - Existing
    - Resolved
    - Unchanged
    using evidence_fingerprint or fallback to basic equality if not available.
    """
    base_map = {f.evidence_fingerprint if hasattr(f, 'evidence_fingerprint') and f.evidence_fingerprint else f.id: f for f in base_findings}
    head_map = {f.evidence_fingerprint if hasattr(f, 'evidence_fingerprint') and f.evidence_fingerprint else f.id: f for f in head_findings}
    
    new = []
    existing = []
    resolved = []
    unchanged = []
    
    for fp, f in head_map.items():
        if fp in base_map:
            # It existed before, check if it's in a changed file
            file_path = getattr(f, 'file', None)
            if file_path and file_path in changed_files:
                existing.append(f)
            else:
                unchanged.append(f)
        else:
            new.append(f)
            
    for fp, f in base_map.items():
        if fp not in head_map:
            resolved.append(f)
            
    return {
        "new": new,
        "existing": existing,
        "resolved": resolved,
        "unchanged": unchanged
    }
