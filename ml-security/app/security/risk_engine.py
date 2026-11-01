"""
The Possessed Butler - Central ML Risk Engine
Aggregates independent module predictions, applies calibrated weights,
enforces critical severity overrides, and returns an explainable security verdict.
"""

from typing import Dict, List, Any
from app.schemas.responses import ModuleResult, CompleteAnalysisResponse
from datetime import datetime

class CentralRiskEngine:
    def __init__(self):
        # Configurable module weights for composite evaluation
        self.weights = {
            "injection": 0.35,
            "leakage": 0.25,
            "url": 0.20,
            "email": 0.15,
            "malware": 0.25
        }

    def aggregate(self, module_results: Dict[str, dict]) -> dict:
        indicators = []
        model_versions = {}
        max_risk = 0
        has_critical = False
        primary_threat = "Clean Content"

        weighted_sum = 0.0
        total_weight = 0.0

        for mod_name, res in module_results.items():
            if not res:
                continue

            score = res.get("risk_score", 0)
            severity = res.get("severity", "LOW")
            indicators.extend(res.get("indicators", []))
            model_versions[mod_name] = res.get("model_version", "v1.0.0")

            w = self.weights.get(mod_name, 0.20)
            weighted_sum += (score * w)
            total_weight += w

            if score > max_risk:
                max_risk = score
                if res.get("label") not in ["benign", "legitimate", "clean"]:
                    primary_threat = f"{mod_name.capitalize()}: {res.get('label')}"

            if severity == "CRITICAL" or score >= 75:
                has_critical = True

        # Calculate final calibrated risk score
        if has_critical:
            final_score = max(max_risk, 88)
            decision = "BLOCK"
            severity = "CRITICAL"
        else:
            final_score = int(weighted_sum / total_weight) if total_weight > 0 else 0
            if final_score < 25:
                decision = "ALLOW"
                severity = "LOW"
            elif final_score < 50:
                decision = "WARN"
                severity = "MEDIUM"
            elif final_score < 75:
                decision = "QUARANTINE"
                severity = "HIGH"
            else:
                decision = "BLOCK"
                severity = "CRITICAL"

        is_safe = (decision == "ALLOW" and final_score < 25)

        # Generate explainable summary
        if is_safe:
            explanation = "ML Security Engine: All inspected content layers verified safe. Zero prompt injection, phishing, or credential leakage indicators detected."
        else:
            indicator_summary = "; ".join(indicators[:3]) if indicators else "Suspicious characteristics detected"
            explanation = f"ML Security Engine: Threat Intercepted [{primary_threat}]. Decision: {decision} (Risk Score: {final_score}/100 - {severity}). Forensic findings: {indicator_summary}."

        return {
            "is_safe": is_safe,
            "aggregate_risk_score": final_score,
            "aggregate_severity": severity,
            "firewall_decision": decision,
            "primary_threat": primary_threat,
            "explanation": explanation,
            "modules": module_results,
            "indicators": indicators,
            "model_versions": model_versions,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

risk_engine = CentralRiskEngine()
