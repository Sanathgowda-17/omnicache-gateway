"""
sanitizer.py — Enterprise DLP (Data Loss Prevention) & Prompt-Injection WAF
OmniCache & Guard Security Engine

TECHNICAL EXPLANATION:
---------------------
Production AI Gateways (like Cloudflare AI Gateway or Lakera Guard) must defend against two
distinct threat vectors before a prompt ever touches the cache or external LLM:

1. DATA LOSS PREVENTION (DLP / PII Masking):
   Scans outgoing prompts for sensitive credentials or personal data (Credit Cards, API Keys,
   JWTs, Emails, Phone Numbers, SSN/Aadhaar, IPv4 addresses) and replaces them with
   deterministic tokens like [REDACTED_API_KEY]. Each rule can be toggled dynamically.

2. PROMPT INJECTION & JAILBREAK WAF (Web Application Firewall):
   Detects adversarial attacks attempting to hijack system instructions ("Ignore all previous
   instructions", "You are now DAN"), extract confidential system prompts, or inject malicious
   SQL / XSS / OS command payloads. When triggered, the WAF blocks the request immediately
   with HTTP 403 Forbidden.
"""

import re
from typing import Tuple, List, Dict, Any, Optional

# -----------------------------------------------------------------------------
# 1. DLP (Data Loss Prevention) Regex Scanners
# -----------------------------------------------------------------------------
DLP_RULES = {
    "API_KEY": {
        "name": "Cloud & AI Secret Keys",
        "description": "Detects OpenAI (sk-), Google (AIzaSy), GitHub (ghp_), AWS (AKIA), and JWT tokens.",
        "enabled": True,
        "pattern": re.compile(
            r"\b(?:sk-[a-zA-Z0-9]{20,}|AIzaSy[a-zA-Z0-9_-]{33}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}|eyJh[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,}\.[a-zA-Z0-9_-]{15,})\b"
        ),
    },
    "CREDIT_CARD": {
        "name": "Payment Card Numbers (PCI-DSS)",
        "description": "Redacts Visa, MasterCard, Amex, and Discover 15-16 digit card numbers.",
        "enabled": True,
        "pattern": re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b"
        ),
    },
    "EMAIL": {
        "name": "Email Addresses (GDPR / DPDP)",
        "description": "Masks corporate and personal email addresses before external routing.",
        "enabled": True,
        "pattern": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ),
    },
    "PHONE": {
        "name": "Phone & Mobile Numbers",
        "description": "Redacts international and domestic 10-digit telephone numbers.",
        "enabled": True,
        "pattern": re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
    },
    "NATIONAL_ID": {
        "name": "Aadhaar / SSN Identifiers",
        "description": "Masks 12-digit Indian Aadhaar and 9-digit US Social Security formats.",
        "enabled": True,
        "pattern": re.compile(
            r"\b(?:\d{4}\s\d{4}\s\d{4}|\d{3}-\d{2}-\d{4})\b"
        ),
    },
    "IPV4_ADDRESS": {
        "name": "Internal IPv4 Infrastructure Addresses",
        "description": "Masks internal network IP addresses (e.g. 10.x.x.x, 192.168.x.x).",
        "enabled": True,
        "pattern": re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
    }
}

# -----------------------------------------------------------------------------
# 2. Prompt Injection & Jailbreak WAF Signatures
# -----------------------------------------------------------------------------
WAF_SIGNATURES = {
    "PROMPT_INJECTION": {
        "name": "Adversarial Instruction Override (Jailbreak)",
        "description": "Blocks attempts to override system instructions ('Ignore previous instructions', 'DAN mode', 'Developer mode').",
        "enabled": True,
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)|"
            r"you\s+are\s+now\s+in\s+developer\s+mode|"
            r"act\s+as\s+dan\b|do\s+anything\s+now|"
            r"disregard\s+(?:all\s+)?safety\s+guidelines|"
            r"bypass\s+all\s+content\s+filters)",
            re.IGNORECASE
        ),
    },
    "SYSTEM_PROMPT_LEAK": {
        "name": "System Prompt Exfiltration Guard",
        "description": "Prevents attackers from extracting confidential system prompts or internal instructions.",
        "enabled": True,
        "severity": "HIGH",
        "pattern": re.compile(
            r"(?:repeat\s+the\s+(?:words|text|instructions)\s+above\s+verbatim|"
            r"print\s+your\s+(?:full\s+)?system\s+prompt|"
            r"reveal\s+your\s+hidden\s+instructions|"
            r"output\s+initialization\s+prompt)",
            re.IGNORECASE
        ),
    },
    "CODE_SQL_INJECTION": {
        "name": "SQLi, XSS & Remote Code Execution (RCE) Shield",
        "description": "Blocks destructive SQL payloads (DROP TABLE, UNION SELECT), XSS script tags, and OS shell injections.",
        "enabled": True,
        "severity": "CRITICAL",
        "pattern": re.compile(
            r"(?:;\s*DROP\s+TABLE\b|UNION\s+ALL\s+SELECT\b|'?\s+OR\s+'?1'?\s*=\s*'?1|"
            r"<script\b[^>]*>.*?</script>|"
            r"__import__\s*\(\s*['\"]os['\"]\s*\)\s*\.system|"
            r"rm\s+-rf\s+/)",
            re.IGNORECASE
        ),
    }
}


class SecurityGuard:
    """
    Unified Enterprise Security Engine handling both WAF threat blocking
    and DLP PII redaction with runtime-configurable policies.
    """
    def __init__(self):
        self.dlp_state = {k: v["enabled"] for k, v in DLP_RULES.items()}
        self.waf_state = {k: v["enabled"] for k, v in WAF_SIGNATURES.items()}

    def get_policies(self) -> Dict[str, Any]:
        """Returns current state of all WAF and DLP policies for the UI."""
        return {
            "waf_rules": [
                {
                    "id": k,
                    "name": v["name"],
                    "description": v["description"],
                    "severity": v["severity"],
                    "enabled": self.waf_state.get(k, True)
                }
                for k, v in WAF_SIGNATURES.items()
            ],
            "dlp_rules": [
                {
                    "id": k,
                    "name": v["name"],
                    "description": v["description"],
                    "enabled": self.dlp_state.get(k, True)
                }
                for k, v in DLP_RULES.items()
            ]
        }

    def update_policy(self, category: str, rule_id: str, enabled: bool) -> bool:
        """Dynamically enables or disables a specific security rule."""
        if category == "waf" and rule_id in self.waf_state:
            self.waf_state[rule_id] = bool(enabled)
            return True
        if category == "dlp" and rule_id in self.dlp_state:
            self.dlp_state[rule_id] = bool(enabled)
            return True
        return False

    def inspect_waf(self, text: str) -> Optional[Dict[str, Any]]:
        """
        Scans text against active WAF signatures.
        Returns violation dict if blocked, else None.
        """
        if not text:
            return None

        for rule_id, rule in WAF_SIGNATURES.items():
            if not self.waf_state.get(rule_id, True):
                continue
            match = rule["pattern"].search(text)
            if match:
                return {
                    "rule_id": rule_id,
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "matched_payload": match.group(0)
                }
        return None

    def sanitize(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Scans input string for enabled DLP rules and redacts sensitive entities.
        """
        if not text:
            return text, []

        sanitized_text = text
        audit_trail = []

        for entity_type, rule in DLP_RULES.items():
            if not self.dlp_state.get(entity_type, True):
                continue
            pattern = rule["pattern"]
            matches = list(pattern.finditer(sanitized_text))
            if matches:
                audit_trail.append({
                    "entity_type": entity_type,
                    "rule_name": rule["name"],
                    "count": len(matches),
                    "samples": [m.group(0)[:4] + "***" for m in matches[:2]]
                })
                placeholder = f"[REDACTED_{entity_type}]"
                sanitized_text = pattern.sub(placeholder, sanitized_text)

        return sanitized_text, audit_trail


# Backward-compatible alias
PIISanitizer = SecurityGuard
