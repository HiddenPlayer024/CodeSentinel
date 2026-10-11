import os
from dataclasses import dataclass

@dataclass
class SecurityConfig:
    AI_MAX_FILES: int = 20
    AI_MAX_REVIEW_UNITS: int = 40
    AI_MAX_REVIEW_LINES: int = 100
    AI_MAX_FINDINGS_PER_UNIT: int = 5
    AI_MAX_TOTAL_AI_FINDINGS: int = 50
    AI_MAX_OUTPUT_TOKENS: int = 1500
    AI_TIMEOUT_SECONDS: int = 30
    AI_MAX_CONCURRENCY: int = 5
    AI_MAX_RETRIES: int = 3

def load_config() -> SecurityConfig:
    config = SecurityConfig()
    
    def get_pos_int(name: str, default: int) -> int:
        try:
            val = int(os.environ.get(name, default))
            return val if val > 0 else default
        except (ValueError, TypeError):
            return default

    config.AI_MAX_FILES = get_pos_int("AI_MAX_FILES", config.AI_MAX_FILES)
    config.AI_MAX_REVIEW_UNITS = get_pos_int("AI_MAX_REVIEW_UNITS", config.AI_MAX_REVIEW_UNITS)
    config.AI_MAX_REVIEW_LINES = get_pos_int("AI_MAX_REVIEW_LINES", config.AI_MAX_REVIEW_LINES)
    config.AI_MAX_FINDINGS_PER_UNIT = get_pos_int("AI_MAX_FINDINGS_PER_UNIT", config.AI_MAX_FINDINGS_PER_UNIT)
    config.AI_MAX_TOTAL_AI_FINDINGS = get_pos_int("AI_MAX_TOTAL_AI_FINDINGS", config.AI_MAX_TOTAL_AI_FINDINGS)
    config.AI_MAX_OUTPUT_TOKENS = get_pos_int("AI_MAX_OUTPUT_TOKENS", config.AI_MAX_OUTPUT_TOKENS)
    config.AI_TIMEOUT_SECONDS = get_pos_int("AI_TIMEOUT_SECONDS", config.AI_TIMEOUT_SECONDS)
    config.AI_MAX_CONCURRENCY = get_pos_int("AI_MAX_CONCURRENCY", config.AI_MAX_CONCURRENCY)
    config.AI_MAX_RETRIES = get_pos_int("AI_MAX_RETRIES", config.AI_MAX_RETRIES)
    
    return config

settings = load_config()
