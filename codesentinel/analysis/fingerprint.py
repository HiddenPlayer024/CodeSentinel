import hashlib
import os

def normalize_path(project_root: str, file_path: str) -> str:
    """Normalize file path relative to project root."""
    if not file_path or not project_root:
        return file_path
    
    try:
        # Get absolute paths to avoid issues with different starting directories
        abs_root = os.path.abspath(project_root)
        abs_file = os.path.abspath(file_path)
        
        # Check if file is actually under root
        if abs_file.startswith(abs_root):
            return os.path.relpath(abs_file, abs_root)
        return file_path
    except ValueError:
        return file_path

def generate_fingerprint(project_root: str, file_path: str, line_start: int, line_end: int, rule_family: str, category: str) -> str:
    """
    Generate a deterministic SHA256 fingerprint for a finding based on:
    - normalized file path
    - line_start
    - line_end
    - normalized_rule_family
    - category
    """
    norm_path = normalize_path(project_root, file_path)
    # Normalize rule family (e.g., lowercased, stripped)
    norm_rule = str(rule_family).strip().lower() if rule_family else "unknown"
    norm_cat = str(category).strip().lower() if category else "unknown"
    
    # Ensure line numbers are integers
    l_start = int(line_start) if line_start is not None else 0
    l_end = int(line_end) if line_end is not None else 0
    
    # Construct string to hash
    fingerprint_string = f"{norm_path}:{l_start}:{l_end}:{norm_rule}:{norm_cat}"
    
    # Generate SHA256
    return hashlib.sha256(fingerprint_string.encode('utf-8')).hexdigest()
