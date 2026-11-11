"""
sanitizer.py — PII Masking & Prompt Security Guard
OmniCache Gateway Core Security Module

TECHNICAL EXPLANATION:
---------------------
When users or internal employees send prompts to an LLM, they often accidentally
include sensitive data: passwords, credit cards, emails, API keys, or personal IDs.
If sent directly to external AI providers (OpenAI, Google, Anthropic), this creates:
1. Severe regulatory non-compliance (GDPR, HIPAA, DPDP Act 2023).
2. Data leakage risks where confidential company secrets enter third-party training pipelines.

This module acts as an automated security boundary. It runs deterministic regular
expression (Regex) scanners across all incoming prompt text before any caching or
forwarding occurs. Sensitive entities are replaced with deterministic placeholder tokens:
[REDACTED_EMAIL], [REDACTED_PHONE], [REDACTED_CREDIT_CARD], [REDACTED_API_KEY].
"""

import re
from typing import Tuple, List, Dict, Any

# Compiled regular expression patterns for maximum throughput
# Order matters: check specific high-entropy tokens first (API keys, Credit Cards) before general patterns (Phone)
PATTERNS = {
    "API_KEY": re.compile(
        r"\b(?:sk-[a-zA-Z0-9]{20,}|AIzaSy[a-zA-Z0-9_-]{33}|ghp_[a-zA-Z0-9]{36}|eyJh[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})\b"
    ),
    "CREDIT_CARD": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    ),
    "PHONE": re.compile(
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
    ),
    "AADHAAR_OR_SSN": re.compile(
        r"\b(?:\d{4}\s\d{4}\s\d{4}|\d{3}-\d{2}-\d{4})\b"
    )
}

class PIISanitizer:
    """
    Scans, audits, and redacts sensitive information from input prompts.
    """
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def sanitize(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Scans the input string for sensitive entities and redacts them.

        Args:
            text (str): The raw user prompt.

        Returns:
            Tuple[str, List[Dict[str, Any]]]:
                - sanitized_text: Text with sensitive entities replaced.
                - audit_trail: List of redacted entity types and match counts.
        """
        if not self.enabled or not text:
            return text, []

        sanitized_text = text
        audit_trail = []

        for entity_type, pattern in PATTERNS.items():
            matches = list(pattern.finditer(sanitized_text))
            if matches:
                audit_trail.append({
                    "entity_type": entity_type,
                    "count": len(matches)
                })
                # Replace with placeholder token
                placeholder = f"[REDACTED_{entity_type}]"
                sanitized_text = pattern.sub(placeholder, sanitized_text)

        return sanitized_text, audit_trail

if __name__ == "__main__":
    # Self-test demonstration
    sanitizer = PIISanitizer(enabled=True)
    sample_prompt = (
        "Hello, my email is john.doe@company.com and my phone number is +1-555-234-5678. "
        "Also my OpenAI key was sk-abcdef12345678901234567890123456 and card is 4111111111111111."
    )
    cleaned, audit = sanitizer.sanitize(sample_prompt)
    print("--- ORIGINAL PROMPT ---")
    print(sample_prompt)
    print("\n--- SANITIZED PROMPT ---")
    print(cleaned)
    print("\n--- SECURITY AUDIT TRAIL ---")
    print(audit)
