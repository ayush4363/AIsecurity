from fastapi import APIRouter
from app.schemas.requests import InjectionAnalysisRequest, BatchInjectionRequest
from app.schemas.responses import (
    ModuleResult,
    PromptInjectionAnalysisResponse,
    BatchPromptInjectionResponse
)
from app.detectors.injection_detector import injection_detector

router = APIRouter(tags=["Prompt Injection & Jailbreak Defense"])

@router.post("/analyze/injection", response_model=ModuleResult)
async def analyze_injection(req: InjectionAnalysisRequest):
    """
    Standard Butler security module result for Node.js backend & firewall pipeline.
    """
    return injection_detector.predict(
        text=req.text,
        source_context=req.source_context or "untrusted"
    )

@router.post("/api/security/prompt-injection/analyze", response_model=PromptInjectionAnalysisResponse)
async def analyze_prompt_injection(req: InjectionAnalysisRequest):
    """
    Direct prompt injection classification endpoint returning:
    - classification (SAFE | NEEDS_REVIEW | SUSPICIOUS | MALICIOUS)
    - risk_score (0 - 100)
    - confidence (0.00 - 1.00)
    - attack_category (INSTRUCTION_OVERRIDE | JAILBREAK | PROMPT_EXTRACTION | etc.)
    - detected_indicators (list of forensic cues)
    - recommended_action (ALLOW | WARN | REQUIRE_APPROVAL | BLOCK)
    - severity (LOW | MODERATE | HIGH | CRITICAL)
    - model_version
    - is_injection (boolean)
    """
    res = injection_detector.analyze_advanced(
        text=req.text,
        source_context=req.source_context or "untrusted"
    )
    return {
        "classification": res["classification"],
        "risk_score": res["risk_score"],
        "confidence": res["confidence"],
        "attack_category": res["attack_category"],
        "detected_indicators": res["detected_indicators"],
        "recommended_action": res["recommended_action"],
        "severity": res["severity"],
        "model_version": res["model_version"],
        "is_injection": res["is_injection"]
    }

@router.post("/api/security/prompt-injection/analyze-batch", response_model=BatchPromptInjectionResponse)
async def analyze_prompt_injection_batch(req: BatchInjectionRequest):
    """
    Batch analysis endpoint for processing multiple prompts concurrently.
    """
    results = []
    malicious_count = 0
    for text in req.texts:
        res = injection_detector.analyze_advanced(text=text, source_context=req.source_context or "untrusted")
        analysis = {
            "classification": res["classification"],
            "risk_score": res["risk_score"],
            "confidence": res["confidence"],
            "attack_category": res["attack_category"],
            "detected_indicators": res["detected_indicators"],
            "recommended_action": res["recommended_action"],
            "severity": res["severity"],
            "model_version": res["model_version"],
            "is_injection": res["is_injection"]
        }
        if analysis["is_injection"]:
            malicious_count += 1
        results.append(analysis)

    return {
        "results": results,
        "total": len(results),
        "malicious_count": malicious_count
    }
