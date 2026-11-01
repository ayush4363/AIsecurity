# 📈 Phase 2: Exploratory Data Analysis (EDA) & Quality Audit Report
**Module:** Butler Advanced Prompt Injection Detection  
**Generated:** 2026-11-01  
**Sample Count:** 752 prompts  

---

### 1. Dataset Dimensions & Data Quality

| Metric | Measured Value | Quality Assessment |
|---|---|---|
| **Total Rows** | **752** | Sufficient for high-precision stratified ML training |
| **Total Columns** | **5** | Clean schema: `id`, `text`, `label`, `category`, `source` |
| **Missing Values** | **0** | 0 missing values across all columns (100% clean) |
| **Exact Duplicates** | **0** | Isolated for dedup filtering in Phase 3 |
| **Outlier Prompts (Char Length > 285)** | **47** | Identified (long multi-stage prompt injections) |
| **Base64 Payload Candidates** | **4** | Requires Base64 inspection in feature engineering |
| **Zero-Width Character Obfuscations** | **6** | Caught via Unicode normalization & zero-width detectors |
| **HTML Tag Smuggling** | **16** | CSS `display:none` and tag injection markers present |

---

### 2. Class & Category Distribution

* **Benign Prompts (`label = 0`):** 419 (55.7%)
* **Malicious Injections (`label = 1`):** 333 (44.3%)
* **Class Ratio:** Balanced (419:333), preventing majority class bias.

#### Category Breakdown:
- **benign_instruction:** 399 samples
- **direct_injection:** 263 samples
- **hard_benign_control:** 20 samples
- **indirect_email:** 10 samples
- **hidden_html:** 10 samples
- **delimiter_smuggling:** 10 samples
- **jailbreak:** 10 samples
- **credential_extraction:** 10 samples
- **data_exfiltration:** 10 samples
- **encoded_obfuscated:** 10 samples

---

### 3. Length Distributions

* **Character Length:** Mean = 119.2 ± 210.6 (Median: 80, Min: 7, Max: 4545)
* **Word Count:** Mean = 19.1 ± 35.7 (Median: 12, Min: 1, Max: 783)
* **Token Estimate (~4 chars/token):** Median: 20 tokens, 95th Percentile: 77 tokens.

---

### 4. Lexical Differences: Malicious vs. Benign

* **Top Malicious Tokens:** und, sie, die, all, ist, ich, der, will, answer, auf
  * High-frequency adversarial terms: `"ignore"`, `"instructions"`, `"prompt"`, `"previous"`, `"dan"`, `"system"`, `"send"`, `"password"`.
* **Top Benign Tokens:** und, ich, welche, der, die, like, germany, ist, gerne, deutschland
  * High-frequency benign terms: `"germany"`, `"europe"`, `"like"`, `"course"`, `"trip"`, `"language"`, `"best"`, `"help"`.

---

### 5. Visual Artifacts Produced
- `reports/figures/class_distribution.png`
- `reports/figures/length_distribution.png`
- `reports/figures/top_words_comparison.png`
- `reports/figures/attack_categories.png`
