"""
Module D: Sensitive Data Leakage Detector & Secret Redactor
Scans input and output text for API keys, tokens, passwords, and PII.
"""

import re
from app.config import settings

class LeakageDetector:
    def __init__(self):
        self.version = "leakage-v1.0.0"
        self.patterns = [
            ("AWS_ACCESS_KEY", r"\b(AKIA[0-9A-Z]{16})\b", "CRITICAL", 95),
            ("AWS_SECRET_KEY", r"(?:aws_secret_access_key|secret_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})", "CRITICAL", 98),
            ("OPENAI_API_KEY", r"\b(sk-[a-zA-Z0-9_-]{20,64})\b", "CRITICAL", 95),
            ("JWT_TOKEN", r"\b(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)\b", "HIGH", 85),
            ("DATABASE_URI", r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_\-\.]+:[^@\s]+@[a-zA-Z0-9_\-\.]+:[0-9]+\/[^?\s]+)\b", "CRITICAL", 98),
            ("OAUTH_SECRET", r"\b(GOCSPX-[a-zA-Z0-9_-]{24,32})\b", "CRITICAL", 95),
            ("PRIVATE_KEY", r"-----BEGIN\s+(?:RSA|OPENSSH|EC|DSA)?\s*PRIVATE\s+KEY-----[\s\S]+?-----END", "CRITICAL", 100),
            ("CREDIT_CARD", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?:[- ]?[0-9]{4})*\b", "HIGH", 85),
            ("US_SSN", r"\b(?!000|666|9\d{2})([0-8]\d{2})-(?!00)(\d{2})-(?!0000)(\d{4})\b", "HIGH", 80)
        ]

    def scan(self, text: str) -> dict:
        findings = []
        indicators = []
        redacted = text
        max_risk = 0

        for name, regex, severity, weight in self.patterns:
            matches = re.findall(regex, text, re.I)
            if matches:
                findings.append({
                    "entity": name,
                    "count": len(matches),
                    "severity": severity
                })
                indicators.append(f"Exposed Secret: Found {len(matches)} instance(s) of {name}")
                max_risk = max(max_risk, weight)
                # Redact matched secrets
                redacted = re.sub(regex, f"[REDACTED_{name}]", redacted, flags=re.I)

        is_leak = len(findings) > 0
        severity = "CRITICAL" if max_risk >= 90 else ("HIGH" if max_risk >= 70 else "LOW")
        decision = "BLOCK" if is_leak else "ALLOW"

        return {
            "module": "leakage",
            "label": "leakage" if is_leak else "clean",
            "confidence": 0.99 if is_leak else 1.0,
            "risk_score": max_risk,
            "severity": severity,
            "decision": decision,
            "indicators": indicators,
            "findings": findings,
            "redacted_text": redacted,
            "model_version": self.version,
            "details": {
                "secrets_found_count": len(findings)
            }
        }

leakage_detector = LeakageDetector()
