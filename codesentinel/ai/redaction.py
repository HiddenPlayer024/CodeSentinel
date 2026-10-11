import re
from codesentinel.models.core import ScanSession

SECRET_PATTERNS = [
    # Generic API keys
    (re.compile(r'(api[_-]?key|password|secret|token)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE), r'\1 = "REDACTED"'),
    # Bearer tokens
    (re.compile(r'Bearer\s+[a-zA-Z0-9\-\._~+/]+=*', re.IGNORECASE), r'Bearer REDACTED'),
    # JWT tokens
    (re.compile(r'eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'), r'REDACTED_JWT'),
    # AWS Access Key ID
    (re.compile(r'(AKIA[0-9A-Z]{16})'), r'REDACTED_AWS_KEY_ID'),
    # AWS Secret Access Key
    (re.compile(r'(aws[_-]?secret[_-]?(?:access[_-]?)?key)\s*=\s*["\']?[a-zA-Z0-9/+=]{40}["\']?', re.IGNORECASE), r'\1 = "REDACTED_AWS_SECRET"'),
    # DB passwords in URLs (e.g., postgres://user:password@host)
    (re.compile(r'(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://([^:]+):([^@]+)@'), r'\1://\2:REDACTED@'),
    # Generic AIza key
    (re.compile(r'(AIza[0-9A-Za-z-_]{35})'), r'REDACTED'),
    # GitHub Token
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
