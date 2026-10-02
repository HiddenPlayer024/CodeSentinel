import re
from codesentinel.models.core import ScanSession

SECRET_PATTERNS = [
    (re.compile(r'(api_key|password|secret|token)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE), r'\1 = "REDACTED"'),
    (re.compile(r'(AIza[0-9A-Za-z-_]{35})'), r'REDACTED'),
    (re.compile(r'(ghp_[0-9a-zA-Z]{36})'), r'REDACTED'),
]

def redact_secrets(prompt: str, session: ScanSession) -> str:
    redacted_prompt = prompt
    for pattern, replacement in SECRET_PATTERNS:
        matches = pattern.findall(redacted_prompt)
        if matches:
            session.ai_redacted_secrets += len(matches)
            redacted_prompt = pattern.sub(replacement, redacted_prompt)
    return redacted_prompt
