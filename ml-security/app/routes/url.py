from fastapi import APIRouter
from app.schemas.requests import URLAnalysisRequest
from app.schemas.responses import ModuleResult
from app.detectors.url_detector import url_detector

router = APIRouter(prefix="/analyze", tags=["URL Reputation & Phishing Analysis"])

@router.post("/url", response_model=ModuleResult)
async def analyze_url(req: URLAnalysisRequest):
    return url_detector.predict(req.url)
