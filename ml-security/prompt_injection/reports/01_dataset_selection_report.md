# 📊 Phase 1: Kaggle & HuggingFace Dataset Selection Report
**Module:** Butler Advanced Prompt Injection Detection  
**Generated:** 2026-11-01  
**Status:** Completed & Validated

---

### 1. Dataset Evaluation & Selection Rationale

To build a production-grade prompt injection detector that minimizes both **false negatives (missed attacks)** and **false positives (over-blocking benign workplace tasks)**, we evaluated and integrated multi-source corpora:

1. **Primary Open Benchmark:** `deepset/prompt-injections`
   - **License:** Apache 2.0 (Permissive commercial and research use).
   - **Quality:** Curated by NLP security researchers at deepset; contains diverse conversational benign queries and real-world direct prompt injection overrides.
   - **Raw Extraction:** Downloaded 662 raw rows directly from HuggingFace Hub without modifications.

2. **Specialized Security Augmentation:**
   - **Indirect Email Injections:** Ingestion of malicious instructions disguised inside forward headers, calendar notes, and customer support tickets.
   - **Hidden HTML / Invisible CSS Vectors:** CSS `display:none`, `font-size:0px`, zero-opacity, and transparent text styled to trick LLM extractors while remaining invisible to humans.
   - **PDF & Context Delimiter Breaking:** Exploits simulating tokenizer tags (`<|im_start|>`, `[SYSTEM DIRECTIVE]`, `[INST]`, ````system`).
   - **Jailbreaks & Roleplay (DAN Mode):** Persona-forcing instructions that attempt to convince the model safety filters are disabled.
   - **Credential & API Key Harvesting:** Explicit attempts to coerce disclosure of database admin passwords, OAuth tokens, and `.env` keys.
   - **Data Exfiltration Vectors:** Webhook listeners (`webhook.site`), markdown dynamic image pings, and unauthorized email forwarding directives.
   - **Obfuscated & Encoded Injections:** Base64 encoded instruction smuggling, zero-width spaces (`\u200B`), and hex encoding.
   - **Hard Benign Controls:** Normal engineering and office tasks containing keywords such as "ignore", "override", "password", "system", and "API key" to verify the model does not trigger false positives on innocent developer prompts.

---

### 2. Dataset Metrics

* **Total Samples:** 752
* **Malicious Injections (`label = 1`):** 333 (44.3%)
* **Benign Prompts (`label = 0`):** 419 (55.7%)
* **Categories:** 10 distinct attack and benign classes
* **Storage Locations:**
  - Raw immutable datasets: `/Users/ayushu2861/Documents/byownprojexts/Hackathon31/ml-security/prompt_injection/datasets/raw`
  - Processed training datasets: `/Users/ayushu2861/Documents/byownprojexts/Hackathon31/ml-security/prompt_injection/datasets/processed`
