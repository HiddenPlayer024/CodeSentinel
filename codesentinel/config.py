import os

# AI Configuration Bounds
AI_MAX_FILES = int(os.environ.get("AI_MAX_FILES", 100))
AI_MAX_REVIEW_UNITS = int(os.environ.get("AI_MAX_REVIEW_UNITS", 200))
AI_MAX_REVIEW_LINES = int(os.environ.get("AI_MAX_REVIEW_LINES", 100))
AI_MAX_FINDINGS_PER_UNIT = int(os.environ.get("AI_MAX_FINDINGS_PER_UNIT", 5))
AI_MAX_TOTAL_AI_FINDINGS = int(os.environ.get("AI_MAX_TOTAL_AI_FINDINGS", 200))
AI_MAX_OUTPUT_TOKENS = int(os.environ.get("AI_MAX_OUTPUT_TOKENS", 1500))
AI_TIMEOUT_SECONDS = int(os.environ.get("AI_TIMEOUT_SECONDS", 30))
