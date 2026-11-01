"""
FastAPI ML Security Engine Configuration
"""

import os

class Settings:
    SERVICE_NAME: str = "The Possessed Butler - Hybrid ML Security Engine"
    VERSION: str = "2.0.0"
    HOST: str = os.getenv("ML_SERVICE_HOST", "127.0.0.1")
    PORT: int = int(os.getenv("ML_SERVICE_PORT", "8000"))
    SECRET_TOKEN: str = os.getenv("ML_SERVICE_TOKEN", "butler-local-ml-secret-2026")
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    MODELS_DIR: str = os.path.join(BASE_DIR, "models")
    REPORTS_DIR: str = os.path.join(BASE_DIR, "evaluation", "reports")

settings = Settings()
