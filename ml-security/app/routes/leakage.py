from fastapi import APIRouter
from app.schemas.requests import LeakageAnalysisRequest
from app.schemas.responses import ModuleResult
from app.detectors.leakage_detector import leakage_detector

router = APIRouter(prefix="/analyze", tags=["Sensitive Data Leakage & Secret Redaction"])

@router.post("/leakage", response_model=ModuleResult)
async def analyze_leakage(req: LeakageAnalysisRequest):
    return leakage_detector.scan(req.text)
