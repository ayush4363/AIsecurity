"""
The Possessed Butler - Hybrid ML Security Engine (FastAPI Service)
Runs locally on Port 8000. Provides real ML inference across:
- Email Phishing & Spam Classification
- Malicious & Phishing URL Detection
- Prompt Injection & Jailbreak Defense
- Sensitive Data Leakage & Secret Redaction
- Static Malware & Document Analysis
"""

import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routes import health, email, url, injection, leakage, malware, complete

app = FastAPI(
    title=settings.SERVICE_NAME,
    version=settings.VERSION,
    description="Local Machine Learning Security Microservice for The Possessed Butler AI Platform"
)

# CORS Middleware (Restricted to internal Node backend and local origins)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5001", "http://127.0.0.1:5001", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Latency and Telemetry Middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    return response

# Mount routers
app.include_router(health.router)
app.include_router(email.router)
app.include_router(url.router)
app.include_router(injection.router)
app.include_router(leakage.router)
app.include_router(malware.router)
app.include_router(complete.router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
