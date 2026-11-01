from fastapi import APIRouter
from app.schemas.requests import EmailAnalysisRequest
from app.schemas.responses import ModuleResult
from app.detectors.email_detector import email_detector

router = APIRouter(prefix="/analyze", tags=["Email Phishing Analysis"])

@router.post("/email", response_model=ModuleResult)
async def analyze_email(req: EmailAnalysisRequest):
    return email_detector.predict(
        sender_email=req.sender_email,
        sender_name=req.sender_name or "",
        subject=req.subject,
        body=req.body,
        spf=req.spf or "none",
        dkim=req.dkim or "none",
        urls=req.urls or [],
        has_attachment=req.has_attachment or False
    )
