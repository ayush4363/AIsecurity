from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class ModuleResult(BaseModel):
    module: str
    label: str
    confidence: float
    risk_score: int
    severity: str
    decision: str
    indicators: List[str]
    model_version: str
    details: Optional[Dict[str, Any]] = None

class CompleteAnalysisResponse(BaseModel):
    is_safe: bool
    aggregate_risk_score: int
    aggregate_severity: str
    firewall_decision: str
    primary_threat: str
    explanation: str
    modules: Dict[str, ModuleResult]
    indicators: List[str]
    model_versions: Dict[str, str]
    timestamp: str

class HealthStatusResponse(BaseModel):
    status: str
    service: str
    version: str
    loaded_models: Dict[str, bool]
    timestamp: str

class PromptInjectionAnalysisResponse(BaseModel):
    classification: str
    risk_score: int
    confidence: float
    attack_category: str
    detected_indicators: List[str]
    recommended_action: str
    severity: str
    model_version: str
    is_injection: bool

class BatchPromptInjectionResponse(BaseModel):
    results: List[PromptInjectionAnalysisResponse]
    total: int
    malicious_count: int
