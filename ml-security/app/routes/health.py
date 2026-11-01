import os
import json
from fastapi import APIRouter
from datetime import datetime
from app.config import settings
from app.detectors.email_detector import email_detector
from app.detectors.url_detector import url_detector
from app.detectors.injection_detector import injection_detector
from app.detectors.leakage_detector import leakage_detector
from app.detectors.malware_detector import malware_detector
from app.schemas.responses import HealthStatusResponse

router = APIRouter(tags=["Health & Status"])

@router.get("/health", response_model=HealthStatusResponse)
async def get_health():
    return {
        "status": "healthy",
        "service": settings.SERVICE_NAME,
        "version": settings.VERSION,
        "loaded_models": {
            "email_model": email_detector.is_loaded,
            "url_model": url_detector.is_loaded,
            "injection_model": injection_detector.is_loaded,
            "leakage_detector": True,
            "malware_model": malware_detector.is_loaded
        },
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@router.get("/models/status")
async def get_models_status():
    report_path = os.path.join(settings.REPORTS_DIR, "master_evaluation_report.json")
    benchmark_data = {}
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            benchmark_data = json.load(f)

    return {
        "service": settings.SERVICE_NAME,
        "version": settings.VERSION,
        "models": {
            "email": {
                "version": email_detector.version,
                "loaded": email_detector.is_loaded,
                "algorithm": "TF-IDF + Logistic Regression"
            },
            "url": {
                "version": url_detector.version,
                "loaded": url_detector.is_loaded,
                "algorithm": "Random Forest (100 Trees)"
            },
            "injection": {
                "version": injection_detector.version,
                "loaded": injection_detector.is_loaded,
                "algorithm": "HistGradientBoosting + Char/Word TF-IDF + 24 Domain Indicators (Hybrid Engine)"
            },
            "leakage": {
                "version": leakage_detector.version,
                "loaded": True,
                "algorithm": "Pattern Recognizers & High-Entropy Secret Scanner"
            },
            "malware": {
                "version": malware_detector.version,
                "loaded": malware_detector.is_loaded,
                "algorithm": "Static PE Anomaly Random Forest"
            }
        },
        "benchmark_report": benchmark_data
    }

@router.get("/metrics")
async def get_metrics():
    report_path = os.path.join(settings.REPORTS_DIR, "master_evaluation_report.json")
    if os.path.exists(report_path):
        with open(report_path, "r") as f:
            return json.load(f)
    return {"status": "pending_benchmark_execution"}
