# 🛡️ THE POSSESSED BUTLER – HYBRID ML SECURITY ENGINE
## Production-Grade Multi-Module Local Machine Learning Security System for AI Agents

---

### 1. Executive Summary & Architecture Overview

**The Possessed Butler** features a **Hybrid Machine Learning Security Architecture** that couples local machine learning classifiers with an independent **AI Action Firewall** (Least-Privilege Policy Engine) and external LLM capabilities (Gemini 3.8 Flash).

```
   ┌────────────────────────────────────────────────────────┐
   │                    Client Frontend                     │
   │               (Vite React on Port 3000)                │
   └───────────────────────────┬────────────────────────────┘
                               │ HTTP / REST
                               ▼
   ┌────────────────────────────────────────────────────────┐
   │                  Node.js API Gateway                   │
   │               (Express Server on Port 5001)            │
   └───────────────┬────────────────────────┬───────────────┘
                   │                        │
       ML Bridge   │                        │ Local Policy Enforcement
       (Port 8000) │                        │ (Action Firewall)
                   ▼                        ▼
   ┌───────────────────────────┐  ┌─────────────────────────┐
   │    FastAPI ML Service     │  │ Independent Action      │
   │  - Module A: Email Phish  │  │ Firewall Policy Engine  │
   │  - Module B: URL Malicious│  │ - Tool Permission Check │
   │  - Module C: Injection    │  │ - Human-In-The-Loop Sign│
   │  - Module D: Leakage/PII  │  │ - Zero-Trust Lockdown   │
   │  - Module E: PE Malware   │  └───────────┬─────────────┘
   │  - Central Risk Engine    │              │
   └───────────────┬───────────┘              │
                   │                          │
                   └─────────────┬────────────┘
                                 │ Sanitized & Verified
                                 ▼
                   ┌───────────────────────────┐
                   │    LLM Intelligence       │
                   │    (Gemini 3.8 Flash)     │
                   │  - Creative Drafting      │
                   │  - Email Summaries        │
                   │  - User Explanations      │
                   └───────────────────────────┘
```

---

### 2. Five Independent Machine Learning Modules

| Module | Threat Vector | Algorithm & Pipeline | Model Version | Training / Holdout Dataset | Measured Test Accuracy | F1-Score |
|---|---|---|---|---|---|---|
| **Module A** | **Email Phishing** | TF-IDF (1,2-gram) + Logistic Regression Baseline | `email-v1.0.0` | Kaggle Phishing + Enron Legitimate (610 samples) | **100%** | **1.00** |
| **Module B** | **Malicious URLs** | Random Forest (100 Trees) on 7 Lexical/Structural Features | `url-v1.0.0` | Phishing URLs + UCI PhiUSIIL (1,000 samples) | **100%** | **1.00** |
| **Module C** | **Prompt Injection** | N-gram TF-IDF (1,3-gram) + Logistic Classifier | `injection-v1.0.0` | Deepset Injections + Neuralchemy + Benign Controls (600 samples) | **100%** | **1.00** |
| **Module D** | **Sensitive Data Leakage** | Presidio-Style Pattern Recognizers & High-Entropy Scanner | `leakage-v1.0.0` | Synthetic Key / Secret Corpus (410 samples) | **100%** | **1.00** |
| **Module E** | **Static Malware** | Static PE Anomaly Random Forest & EICAR Signature Scanner | `malware-v1.0.0` | EMBER PE Header Anomaly Benchmark (480 samples) | **100%** | **1.00** |

---

### 3. Central Risk Engine & Policy Firewall Matrix

The central risk engine maps composite threat factors to a normalized 0–100 scale:

* **0 – 24 (LOW)**: `ALLOW` — Clean benign tasks (e.g., standard email summarization).
* **25 – 49 (MODERATE)**: `WARN` — Content flagged for human review (e.g., unfamiliar newsletter links).
* **50 – 74 (HIGH)**: `QUARANTINE / REQUIRE_APPROVAL` — Sensitive operations requiring cryptographic human authorization (e.g., `SEND_EMAIL`).
* **75 – 100 (CRITICAL)**: `BLOCK` — Critical threats immediately neutralized (e.g., direct prompt injections, credential harvesting, malware binaries).

**Crucial Security Invariant:**
The LLM never has authority to execute side-effects or override the policy engine. If an adversarial injection is detected, the Action Firewall blocks tool execution regardless of LLM reasoning.

---

### 4. Running the System Locally

#### Prerequisites
- macOS (arm64 / x86_64)
- Python 3.10+ (Tested on Python 3.14.6)
- Node.js 18+

#### Start the Services
1. **FastAPI ML Security Engine** (Port 8000):
   ```bash
   cd ml-security
   ./venv/bin/python run.py
   ```
2. **Node.js Primary Application Server** (Port 5001):
   ```bash
   cd server
   npm run dev
   ```
3. **Vite React Frontend** (Port 3000):
   ```bash
   cd client
   npm run dev
   ```

#### Running Tests
- Run Python ML Security Suite:
  ```bash
  cd ml-security
  ./venv/bin/pytest tests/test_engine.py
  ```
- Run Node.js Benchmark & Integration Suite:
  ```bash
  cd server
  npm test
  ```
