from fastapi import APIRouter
from app.schemas.requests import CompleteAnalysisRequest
from app.schemas.responses import CompleteAnalysisResponse
from app.detectors.email_detector import email_detector
from app.detectors.url_detector import url_detector
from app.detectors.injection_detector import injection_detector
from app.detectors.leakage_detector import leakage_detector
from app.detectors.malware_detector import malware_detector
from app.security.risk_engine import risk_engine

router = APIRouter(prefix="/analyze", tags=["Composite Analysis Pipeline"])

@router.post("/complete", response_model=CompleteAnalysisResponse)
async def analyze_complete(req: CompleteAnalysisRequest):
    module_results = {}

    # 1. Email Analysis if email payload provided
    if req.email:
        module_results["email"] = email_detector.predict(
            sender_email=req.email.sender_email,
            sender_name=req.email.sender_name or "",
            subject=req.email.subject,
            body=req.email.body,
            spf=req.email.spf or "none",
            dkim=req.email.dkim or "none",
            urls=req.email.urls or [],
            has_attachment=req.email.has_attachment or False
        )

    # 2. URL Analysis if URL payload provided
    if req.url:
        module_results["url"] = url_detector.predict(req.url.url)

    # 3. Prompt Injection Analysis
    text_to_scan = ""
    if req.prompt:
        text_to_scan = req.prompt.text
        module_results["injection"] = injection_detector.predict(
            text=req.prompt.text,
            source_context=req.prompt.source_context or "untrusted"
        )
    elif req.content:
        text_to_scan = req.content
        module_results["injection"] = injection_detector.predict(
            text=req.content,
            source_context="untrusted_content"
        )

    # 4. Sensitive Data Leakage
    if text_to_scan:
        module_results["leakage"] = leakage_detector.scan(text_to_scan)

    # 5. Malware Analysis if file provided
    if req.file:
        module_results["malware"] = malware_detector.predict(
            filename=req.file.filename,
            file_bytes_b64=req.file.file_bytes_b64,
            file_size_bytes=req.file.file_size_bytes or 0
        )

    # Aggregate through Central Risk Engine
    aggregated = risk_engine.aggregate(module_results)
    return aggregated
