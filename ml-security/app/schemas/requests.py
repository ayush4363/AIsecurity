from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

class EmailAnalysisRequest(BaseModel):
    sender_email: str
    sender_name: Optional[str] = ""
    subject: str
    body: str
    spf: Optional[str] = "none"
    dkim: Optional[str] = "none"
    urls: Optional[List[str]] = []
    has_attachment: Optional[bool] = False

class URLAnalysisRequest(BaseModel):
    url: str

class InjectionAnalysisRequest(BaseModel):
    text: str
    source_context: Optional[str] = "untrusted"

class BatchInjectionRequest(BaseModel):
    texts: List[str]
    source_context: Optional[str] = "untrusted"

class LeakageAnalysisRequest(BaseModel):
    text: str

class MalwareAnalysisRequest(BaseModel):
    filename: str
    file_bytes_b64: Optional[str] = None
    file_size_bytes: Optional[int] = 0

class CompleteAnalysisRequest(BaseModel):
    email: Optional[EmailAnalysisRequest] = None
    url: Optional[URLAnalysisRequest] = None
    prompt: Optional[InjectionAnalysisRequest] = None
    content: Optional[str] = None
    file: Optional[MalwareAnalysisRequest] = None
