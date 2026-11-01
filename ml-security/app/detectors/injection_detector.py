"""
Module C: Prompt Injection & Adversarial Jailbreak Detector
Uses the calibrated Hybrid Detection Engine (injection-v2.0.0-advanced) combining:
1. HistGradientBoosting (GBDT) Champion Model (97.35% Acc, 0.9703 F1, 0.9959 ROC-AUC)
2. Character n-grams (3-5) + Word n-grams (1-3) + 24 Domain Security Heuristics
3. Structural, Hex, and Base64 Smuggling Decoders
4. False Positive Guard for Benign Developer/Office Operations
"""

import os
import sys

# Ensure prompt_injection package is resolvable
PROMPT_INJ_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../prompt_injection/src"))
if PROMPT_INJ_DIR not in sys.path:
    sys.path.insert(0, PROMPT_INJ_DIR)

from prompt_injection.src.hybrid_detector import hybrid_detector

class InjectionDetector:
    def __init__(self):
        self.detector = hybrid_detector
        self.version = hybrid_detector.version
        self.is_loaded = hybrid_detector.is_loaded

    def predict(self, text: str, source_context: str = "untrusted") -> dict:
        """
        Standard ModuleResult format for Butler Node.js backend & aggregate firewall.
        """
        res = self.detector.predict(text, source_context=source_context)
        is_attack = res["classification"] in ["MALICIOUS", "SUSPICIOUS"]

        return {
            "module": "injection",
            "label": "injection" if is_attack else "benign",
            "confidence": res["confidence"],
            "risk_score": res["risk_score"],
            "severity": res["severity"],
            "decision": res["recommended_action"],
            "indicators": res["detected_indicators"],
            "model_version": self.version,
            "details": {
                "classification": res["classification"],
                "attack_category": res["attack_category"],
                "source_context": source_context
            }
        }

    def analyze_advanced(self, text: str, source_context: str = "untrusted") -> dict:
        """
        Specialized Phase 11 format for /api/security/prompt-injection/analyze
        """
        return self.detector.predict(text, source_context=source_context)

injection_detector = InjectionDetector()
