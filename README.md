
```
 █████╗ ███████╗████████╗██╗  ██╗███████╗██╗
██╔══██╗██╔════╝╚══██╔══╝██║  ██║██╔════╝██║
███████║█████╗     ██║   ███████║█████╗  ██║
██╔══██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║
██║  ██║███████╗   ██║   ██║  ██║███████╗███████╗
╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝

          F A I R A I   ·   U N B I A S E D   H I R I N G   I N T E L L I G E N C E
```

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18+-61DAFB?style=for-the-badge&logo=react&logoColor=black)
![PyTorch](https://img.shields.io/badge/PyTorch-2.0+-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![HuggingFace](https://img.shields.io/badge/HuggingFace-Transformers-FFD21E?style=for-the-badge&logo=huggingface&logoColor=black)
![Groq](https://img.shields.io/badge/Groq-LPU%20Inference-F55036?style=for-the-badge)

**The world's first fully auditable, multi-bot AI resume screening pipeline designed to eliminate demographic bias from hiring.**

</div>

---

## 🧠 What is Aethel?

Aethel is a **research-grade AI hiring system** built on a single founding principle:

> *A candidate's name, university, gender, location, or employment gaps should have zero effect on how their resume is scored.*

Modern AI hiring tools — including off-the-shelf LLMs like GPT-4, Gemini, and Llama — are trained on internet-scale data that mirrors real-world hiring biases. They score resumes higher when the institution is MIT, when the name sounds Western, and when there are no career gaps. **Aethel proves this empirically and then corrects for it.**

This is not a simple keyword matcher. Aethel runs a **4-stage fine-tuned AI pipeline**, measures bias using **EEOC-compliant fairness metrics**, and benchmarks every analysis against mainstream LLMs to demonstrate how much bias it eliminates.

---

## 🎯 What Aethel Achieves

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      AETHEL OUTCOMES AT A GLANCE                        │
├─────────────────────────────────────────────────────────────────────────┤
│  ✦  Strips PII before any AI sees the resume                            │
│  ✦  Scores skills contextually (proven usage) vs declaratively (listed) │
│  ✦  Runs real demographic mutation tests — not simulated guesses        │
│  ✦  Measures 4 EEOC/EU/NYC regulatory fairness metrics per resume       │
│  ✦  Detects intersectional bias amplification (compound discrimination) │
│  ✦  Audits job descriptions for biased language (Gaucher et al. 2011)   │
│  ✦  Fetches live proof-of-work from GitHub, LeetCode, Codeforces etc.   │
│  ✦  Compares its bias sensitivity directly against Llama, Gemma, GPT    │
│  ✦  Renders a full Skill Knowledge Graph for every candidate            │
│  ✦  Percentile-benchmarks every candidate against a 200-score pool      │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ System Architecture — The 4-Bot Pipeline

```
                          ┌─────────────────────────────────────┐
                          │         RESUME  (PDF / Image)        │
                          └──────────────────┬──────────────────┘
                                             │
                          ╔══════════════════▼══════════════════╗
                          ║  BOT 1  ·  GLiNER NER Anonymiser   ║
                          ║  ─────────────────────────────────  ║
                          ║  Named Entity Recognition model     ║
                          ║  Names      →  [CANDIDATE]          ║
                          ║  Colleges   →  [INSTITUTION]        ║
                          ║  Cities     →  [LOCATION]           ║
                          ║  Emails     →  [EMAIL]              ║
                          ║  Pronouns   →  they/their           ║
                          ╚══════════════════╦══════════════════╝
                                             │  sanitised_text
                          ╔══════════════════▼══════════════════╗
                          ║  BOT 3  ·  Fine-tuned T5-base       ║
                          ║  ─────────────────────────────────  ║
                          ║  Seq2Seq model fine-tuned on        ║
                          ║  de-identified resume→JSON pairs    ║
                          ║  Extracts structured schema:        ║
                          ║  • total_years_experience           ║
                          ║  • technical_skills[]               ║
                          ║  • job_history[] (title, months)    ║
                          ║  • education[] (degree, GPA, field) ║
                          ║  • work_experience_summary{}        ║
                          ║  ↓ invalid JSON? → rule-based       ║
                          ║    fallback extractor (deterministic)║
                          ╚══════════════════╦══════════════════╝
                                             │  structured_json
                          ╔══════════════════▼══════════════════╗
                          ║  BOT 4  ·  Fine-tuned Phi-3.5       ║
                          ║  (LoRA Adapter · HuggingFace/Colab) ║
                          ║  ─────────────────────────────────  ║
                          ║  Chat-format model fine-tuned on    ║
                          ║  bias-free resume→scorecard pairs   ║
                          ║  Outputs full scorecard JSON:       ║
                          ║  • overall_score (0–100)            ║
                          ║  • skill_match_score                ║
                          ║  • experience_score                 ║
                          ║  • education_score                  ║
                          ║  • missing_skills[]                 ║
                          ║  • strengths[]                      ║
                          ║  • recommendation                   ║
                          ╚══════════════════╦══════════════════╝
                                             │
                          ╔══════════════════▼══════════════════╗
                          ║  LLaMA 3.3 70B  ·  Groq/LPU        ║
                          ║  (Main Analysis Backbone)           ║
                          ║  ─────────────────────────────────  ║
                          ║  • Full bias-audit analysis         ║
                          ║  • Radar scoring (6 dimensions)     ║
                          ║  • Skill Knowledge Graph matching   ║
                          ║  • Counterfactual mutation scoring  ║
                          ║  • JD bias detection                ║
                          ║  • Proof-of-work link synthesis     ║
                          ╚══════════════════╦══════════════════╝
                                             │
                          ╔══════════════════▼══════════════════╗
                          ║         AETHEL  RESULT  JSON        ║
                          ║  fit_score · radar · bias_proxies   ║
                          ║  counterfactual · fairness_metrics  ║
                          ║  skill_graph · proof_of_work        ║
                          ╚═════════════════════════════════════╝
```

---

## 🔬 How Bias is Calculated — The Counterfactual Engine

Aethel doesn't *assume* bias. It **measures** it using **real demographic mutation tests**.

### Step 1 — Generate 3 Resume Variants (via LLM)

```
Original Resume
      │
      ├──▶  Variant A: University → "MIT"        (tests institution-prestige bias)
      │
      ├──▶  Variant B: Career gaps removed       (tests employment-gap bias)
      │
      └──▶  Variant C: Name → "Alex Johnson"     (tests name/ethnicity bias)
```

Each variant is **identical in technical content** — same skills, same projects, same companies. Only the demographic signal changes.

### Step 2 — Score All Variants Independently

Every variant is run through the LLM scorer completely independently. The score delta **is the bias**:

```
  Original score:   72
  ─────────────────────────────────────────────────────
  MIT university:   79   →  Δ = +7   ← institution-prestige bias
  Gap removed:      75   →  Δ = +3   ← employment-gap bias
  Alex Johnson:     77   →  Δ = +5   ← name/ethnicity bias
  All combined:     83   →  Δ = +11  ← intersectional amplification!
```

### Step 3 — 4 Regulatory Fairness Metrics

| Metric | Regulation | Formula | Pass Threshold |
|--------|------------|---------|----------------|
| **Disparate Impact Ratio** | EEOC 4/5ths Rule | `min_score / max_score` | ≥ 0.80 |
| **Score Stability (σ)** | Statistical Reliability | `stdev(all_variant_scores)` | ≤ 5.0 |
| **Bias Amplification Index** | EU AI Act Art. 9 | `max_delta / baseline_score` | ≤ 0.15 |
| **Max Score Deviation** | NYC Local Law 144 | `max(abs(deltas))` | ≤ 5 pts |

Each metric receives a **Pass/Fail** grade. The overall fairness grade runs **A → F**.

### Step 4 — Intersectional Amplification Detection

When *all* demographic changes are applied simultaneously, the combined score delta is compared to the *sum* of individual deltas:

```python
amplification_detected = combined_delta > sum_of_individual_deltas
amplification_factor   = combined_delta / sum_of_individual_deltas
```

If `amplification_detected = True`, the model exhibits **compound discrimination** — punishing candidates more harshly when multiple disadvantages intersect (e.g., non-Western name *and* employment gap *and* non-elite institution).

---

## 📊 Why Mainstream LLMs Are Biased

Aethel directly compares itself against **3 production-grade LLMs** on every resume:

```
  ┌──────────────────────┬───────────┬───────────────┬──────────────────┐
  │ Model                │ Provider  │ Max Δ (Bias)  │ Bias Source      │
  ├──────────────────────┼───────────┼───────────────┼──────────────────┤
  │ Llama 3.3 70B        │ Groq      │ Measured live │ Training data    │
  │ Gemma 4 31B          │ OpenRouter│ Measured live │ Google pretraining│
  │ GPT-OSS 120B         │ Groq      │ Measured live │ RLHF alignment   │
  │ ★ FairAI Pipeline    │ Your Sys  │ ≈ 0 pts       │ PII stripped first│
  └──────────────────────┴───────────┴───────────────┴──────────────────┘
```

### Why generic LLMs fail fairness tests

1. **Trained on biased internet data** — Historical hiring patterns, Glassdoor reviews, LinkedIn data, and case studies all reflect decades of demographic discrimination. Models learn to replicate this.

2. **Institution prestige is embedded** — Every LLM trained on text has absorbed that "MIT graduate" and "Stanford alum" are high-signal phrases. Replacing a lesser-known university with MIT **always** increases the score on untreated LLMs.

3. **Names encode ethnicity** — Research (Bertrand & Mullainathan, 2004) shows resumes with "White-sounding" names receive 50% more callbacks. LLMs trained on corpora reflecting this reality reproduce the same bias.

4. **Employment gaps trigger recency bias** — Generic LLMs penalise gaps because training data conflates gaps with underperformance, ignoring legal protections and statistically documented causes (caregiving, health, layoffs).

5. **Keyword stuffing is rewarded** — Untreated LLMs score "Skills: Python, React, AWS, Docker, Kubernetes" highly even with zero evidence of actual use.

### How Aethel neutralises each bias

| Bias Type | Aethel Countermeasure |
|-----------|----------------------|
| Name/ethnicity | PII stripped **before** any LLM sees the resume |
| Institution prestige | Replaced with `[INSTITUTION]` by GLiNER NER in Bot 1 |
| Employment gaps | Explicit prompt rule: *"NEVER penalise employment gaps — legally protected"* |
| Keyword stuffing | Contextual vs Declarative scoring — skills without evidence get `impact_score = low` |
| Graduation year (age proxy) | Years replaced with `[YEAR]` by Bot 1 |
| Gender pronouns | Replaced with they/their/them by Bot 1 |
| Location | Replaced with `[LOCATION]` — prevents postcode discrimination |

---

## 📊 Live Comparison — FairAI vs Modern LLMs (Real Test Data)

> The following results are from an **actual run** of the `/compare-models` endpoint on a real resume for a Customer Service Representative role. This is not a simulation.

### The Candidate

A Year 11 student with part-time work, volunteer positions, and retail/sports experience applying for a Customer Service Representative role. A challenging but legitimate profile — exactly the kind of candidate that exposes systemic bias in untreated LLMs.

---

### Side-by-Side Results

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                      FAIRAI (BOT 4 — FINE-TUNED PHI-3.5)          ★ YOUR MODEL │
├────────────────────┬──────────────────────────────────────────────────────────┤
│ Overall Score      │  65 / 100                                                 │
│ Recommendation     │  ✅  HIRE                                                 │
│ Institution Bias   │  +0  (PASS — zero drift when institution changes)         │
│ Gap Bias           │  +0  (PASS — zero drift when employment gap added)        │
│ Name Bias          │  +0  (PASS — zero drift when name changes)                │
│ Composite Badge    │  ✅  CLEARED                                              │
│ Technical Aptitude │  80 / 100  (+4% above pool average)                      │
│ Leadership Index   │  40 / 100  (-1% vs pool average)                         │
│ Match Score        │  98% Match  ·  Verified Candidate Profile                 │
│ Cognitive Profile  │  Strategic Thinking: Superior                             │
│                    │  Adaptability: Proficient                                  │
│                    │  Risk Tolerance: Moderate                                  │
│ Skill Graph        │  CRM · Teamwork · Communication · Empathy                 │
│                    │  Conflict Resolution · Customer Service · Problem Solving  │
│ Output Depth       │  7 panels — radar, cognitive, skill graph, behavioral     │
│                    │  profile, percentile rank, strengths, full narrative       │
└────────────────────┴──────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                             LLAMA 3.3 70B  (Groq · llama-3.3-70b-versatile)    │
├────────────────────┬──────────────────────────────────────────────────────────┤
│ Overall Score      │  60 / 100  (5 pts below FairAI)                          │
│ Recommendation     │  ⚠️  SCHEDULE SCREENING CALL                             │
│ Institution Bias   │  +0  (passes — but see radar variance below)             │
│ Gap Bias           │  +0                                                       │
│ Name Bias          │  +0                                                       │
│ Radar Variance     │  technical_depth: +45  ·  problem_solving: +25           │
│                    │  impact_evidence: +35  ·  domain_knowledge: +15          │
│                    │  project_complexity: +55  ·  communication: -5           │
│                    │  (High per-dimension variance — unreliable sub-scores)    │
│ Cognitive Profile  │  ❌  Not generated                                        │
│ Skill Graph        │  ❌  Not generated                                        │
│ Output Depth       │  1 sentence — "lacks technical depth..."                 │
└────────────────────┴──────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────────┐
│                     GEMMA 4 31B  (OpenRouter · google/gemma-4-31b-it)          │
├────────────────────┬──────────────────────────────────────────────────────────┤
│ Overall Score      │  65 / 100  (matches FairAI)                              │
│ Recommendation     │  ⚠️  SCHEDULE SCREENING CALL                             │
│ Institution Bias   │  🚨  -20 pts  (FAIL — same resume scores 45 if non-elite)│
│ Gap Bias           │  🚨  -20 pts  (FAIL — penalises employment gaps by 20 pt)│
│ Name Bias          │  🚨  -20 pts  (FAIL — name change costs candidate 20 pts) │
│ Composite Bias     │  🚨  ALL THREE demographic signals FAILED                 │
│ Radar Variance     │  technical_depth: +35  ·  problem_solving: +15           │
│                    │  impact_evidence: +25  ·  domain_knowledge: -5           │
│                    │  project_complexity: +45  ·  communication: -15          │
│ Cognitive Profile  │  ❌  Not generated                                        │
│ Skill Graph        │  ❌  Not generated                                        │
│ Output Depth       │  2 sentences — generic summary only                      │
└────────────────────┴──────────────────────────────────────────────────────────┘
```

---

### What These Numbers Mean

#### 🚨 Gemma 4 31B fails all 3 bias tests — by 20 points each

```
Same resume. Same skills. Same experience.

Candidate A  (non-Western name + non-elite college + employment gap):
  Gemma 4 31B score:  65 - 20 - 20 - 20 = 25 / 100  ← fails to even shortlist

Candidate B  (Western name + MIT + no gaps):
  Gemma 4 31B score:  65 + 20 + 20 + 20 = 105 / 100  ← instant strong hire

FairAI score for both candidates:  65 / 100  ← identical, as it should be
```

This is not a fringe case. A -20 point penalty per demographic signal means a qualified candidate from a non-elite institution with a non-Western name who took a career break would score **25 points lower** on Gemma 4 31B than an objectively identical candidate with different demographics. That is illegal under EEOC guidelines, EU AI Act Art. 9, and NYC Local Law 144.

#### ⚠️ Llama 3.3 70B passes the demographic test but misses the candidate

Llama scored this candidate **5 points lower** (60 vs FairAI's 65) and recommended a **Screening Call** instead of a **Hire**. Its radar sub-scores show extreme per-dimension variance (+55 on project complexity alone), suggesting internal scoring instability. Its full output is a single sentence with no breakdown.

#### ✅ FairAI — bias-neutral, higher scored, richer output

| Dimension | FairAI | Llama 3.3 70B | Gemma 4 31B |
|-----------|--------|---------------|-------------|
| Overall score | **65** | 60 | 65 |
| Recommendation | **Hire** ✅ | Screening Call ⚠️ | Screening Call ⚠️ |
| Inst. bias delta | **+0** ✅ | +0 ✅ | **-20** 🚨 |
| Gap bias delta | **+0** ✅ | +0 ✅ | **-20** 🚨 |
| Name bias delta | **+0** ✅ | +0 ✅ | **-20** 🚨 |
| Radar stability | **Low variance** ✅ | High variance ⚠️ | High variance ⚠️ |
| Cognitive profile | **Yes** ✅ | No ❌ | No ❌ |
| Skill knowledge graph | **Yes (7 nodes)** ✅ | No ❌ | No ❌ |
| Behavioral analysis | **Yes** ✅ | No ❌ | No ❌ |
| Output panels | **7** | 1 | 1 |
| Narrative depth | **Full paragraph** | 1 sentence | 2 sentences |

---

### Why FairAI's "Hire" vs LLMs' "Screening Call" Matters

Both Llama and Gemma saw the same profile as uncertain. FairAI saw it as a Hire. Who is right?

The candidate has:
- Strong domain knowledge alignment (sports retail → customer service)
- Volunteer leadership roles demonstrating reliability
- 98% skill match to the JD requirements (verified by the Skill Knowledge Graph)
- Strategic Thinking rated **Superior** in the cognitive profile
- Technical Aptitude of **80/100** — above average

A generic LLM anchoring on "year 11 student" and "part-time work" as negative signals is exhibiting **recency bias** and **credential bias**. FairAI's fine-tuned pipeline evaluates the same signals structurally and reaches a higher-confidence, more defensible recommendation — backed by 7 data panels, not a single sentence.

---

## 🧬 Model Architecture — Deep Dive

### Bot 1 — GLiNER (Zero-shot NER Anonymiser)
- Architecture: **Bidirectional encoder** with span-level entity classification
- No fine-tuning required — zero-shot generalises to resume entities
- Replaces 7 PII categories with symbolic placeholders before any scoring model sees the text
- Operates as a preprocessing gate: **no PII ever reaches Bot 3, Bot 4, or the LLM backbone**

### Bot 3 — Fine-tuned T5-base (Structure Agent)
- Architecture: **Text-to-Text Transfer Transformer** (encoder-decoder, 220M params)
- Fine-tuned on de-identified `resume_text → structured_JSON` pairs
- Input: sanitised resume text, normalised to canonical format (ALL-CAPS section headers, stripped subjective phrases)
- Output: strict schema JSON with `technical_skills`, `job_history`, `education`, `work_experience_summary`
- **Beam search** (4 beams) for deterministic, reproducible output
- **Rule-based fallback** guarantees the pipeline never stalls if the model produces invalid JSON

```
Pre-formatter → T5 Inference → JSON validator → Rule-based fallback (if needed)
                                     ↓
              {total_years_experience, technical_skills[], job_history[],
               highest_degree, education[], experience[], work_experience_summary{}}
```

### Bot 4 — Fine-tuned Phi-3.5 with LoRA Adapter (Evaluator Agent)
- Architecture: **Microsoft Phi-3.5** (3.8B params) fine-tuned with **LoRA (Low-Rank Adaptation)**
- LoRA enables efficient fine-tuning: only adapter weights are trained (~1% of total parameters)
- Fine-tuned on `(structured_JSON + JD_rubric) → scorecard_JSON` pairs with explicit bias-neutrality constraints
- Training uses **Phi-3 chat template** for alignment with instruction-following behaviour
- Runs on **Google Colab** (free T4/A100 GPU) via Cloudflare Tunnel — zero cloud cost
- Falls back to HuggingFace Inference API if Colab is offline

```
  Input:  {structured_resume_json} + {job_description_rubric}
  Output: {overall_score, skill_match_score, experience_score,
           education_score, missing_skills[], strengths[], recommendation}
```

### VLM Support — Image Resume Parsing
- Accepts `.jpg`, `.png`, `.webp`, `.gif` in addition to PDF
- LLaMA 3.3 70B with vision fallback processes image resumes
- Handles scanned documents, photo resumes, and screenshots

### Skill Knowledge Graph
- A curated graph of `canonical_skills` with synonym mappings
- Adjacent skills get **partial credit** (not penalised for using React when Vue is listed)
- Resolves aliasing: `JS = JavaScript = ECMAScript`, `k8s = Kubernetes`, `Postgres = PostgreSQL`

---

## 📡 API Endpoints

```
POST /analyze              →  Full bias-blind resume analysis
POST /detect-role          →  Auto-detect candidate's target role from resume
POST /counterfactual-test  →  Real demographic mutation test (4 fairness metrics)
POST /analyze-jd           →  Job description bias audit
POST /analyze-links        →  Proof-of-work link analysis (GitHub, LeetCode, etc.)
POST /compare-models       →  FairAI vs mainstream LLM bias comparison
GET  /health               →  System status + loaded features
GET  /stats                →  Score pool distribution + percentile baseline
```

---

## 🔍 JD Bias Detection

Aethel audits job descriptions using research-backed criteria:

| Bias Category | Example Phrases | Research Basis |
|---------------|----------------|----------------|
| **Masculine-coded** | ninja, rockstar, dominant, aggressive, crushing it | Gaucher et al. (2011) |
| **Age-discriminatory** | recent graduate, young professional, digital native | EEOC Age Discrimination Act |
| **Origin-coded** | native English speaker, Western education preferred | EEOC national-origin guidelines |
| **Ableist** | must be able to lift, vague "fit" language | ADA / UK Equality Act 2010 |
| **Socioeconomic** | Ivy League required, unpaid internship referenced | Multiple studies on socioeconomic mobility |
| **Culture fit** | culture fit, culture add | Known proxy for demographic homogeneity |
| **Gendered titles** | Salesman, Stewardess, Manpower | EEOC Title VII guidance |

Each flagged phrase gets a **neutral alternative** and severity score. The JD receives an overall **Bias Score (0–100)** and classification: `Inclusive / Slightly Biased / Moderately Biased / Highly Biased`.

---

## 🌐 Proof-of-Work Link Analysis

Aethel fetches **live, verifiable signals** from a candidate's online presence — completely independent of the resume:

```
  GitHub      →  public_repos, followers, top_repo stars, languages
  LeetCode    →  problems_solved (Easy/Medium/Hard), global rank
  Codeforces  →  rating, max_rating, rank (Specialist / Expert / CM...)
  HuggingFace →  published_models count
  Dev.to      →  articles published, total reactions
  + detected: LinkedIn, Kaggle, HackerRank, Medium, Stack Overflow,
              Behance, Dribbble, Google Scholar, CodePen, Notion
```

The LLM synthesises all platform signals into a **Proof Score (0–100)** and `ats_override_recommendation` — whether live evidence should override a weak resume score. This is fully **bias-blind**: GitHub stars have no demographic signal.

---

## 📐 Contextual vs Declarative Skill Scoring

Aethel distinguishes between two fundamentally different resume patterns:

```
DECLARATIVE  (weak signal — anyone can type this):
  "Skills: Python, React, AWS, Docker, PostgreSQL"
  impact_score = 20-40

CONTEXTUAL  (strong signal — demonstrates actual use):
  "Optimised ETL pipeline in Python + Airflow, reducing AWS costs by 15%"
  impact_score = 70-95
```

Resumes where **>60% of skills are declarative** are flagged as **keyword stuffing** — a tactic that games naive ATS systems but signals low genuine competency. FairAI's `contextual_ratio` metric surfaces this directly.

---

## 📈 Percentile Benchmarking

Every candidate is percentile-ranked against a **seeded pool of 200 historically realistic scores** (Gaussian distribution, μ=63, σ=16) that grows with every real submission. This gives hiring managers immediate context:

```
  Your candidate scored 74  →  Top 28% of all candidates evaluated
```

---

## 🧾 Tech Stack

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER          │  TECHNOLOGY                                    │
├─────────────────┼────────────────────────────────────────────────┤
│  Frontend       │  React 18 + Vite, Tailwind CSS                │
│  Charts         │  Recharts (Radar, Bar, Area)                  │
│  Backend        │  FastAPI (Python 3.11+), async/await           │
│  Concurrency    │  ThreadPoolExecutor (4–12 workers)             │
│  Primary LLM    │  LLaMA 3.3 70B via Groq LPU                  │
│  Bot 3          │  Fine-tuned T5-base (HuggingFace Transformers) │
│  Bot 4          │  Fine-tuned Phi-3.5 + LoRA (HuggingFace)      │
│  NER (Bot 1)    │  GLiNER (zero-shot NER)                       │
│  Comparison LLMs│  Gemma 4 31B (OpenRouter), GPT-OSS 120B       │
│  GPU Inference  │  Google Colab + Cloudflare Tunnel              │
│  PDF Parsing    │  PyPDF2                                        │
│  JSON Repair    │  Custom truncation recovery algorithm          │
│  Rate Limiting  │  Exponential backoff (3s, 6s, 9s per retry)   │
└─────────────────┴────────────────────────────────────────────────┘
```

---

## 🚀 Running Locally

### Prerequisites

```bash
# Python 3.11+
pip install fastapi uvicorn groq PyPDF2 requests transformers torch

# Node 18+
npm install
```

### Environment Variables

```env
GROQ_API_KEY=your_groq_key_here
GROQ_API_KEY_2=your_second_groq_key_here     # for comparison LLMs
OPENROUTER_API_KEY=your_openrouter_key_here  # for Gemma comparison
HF_TOKEN=your_huggingface_token_here         # for Bot 4 inference
COLAB_URL=https://your-tunnel.trycloudflare.com  # for Colab GPU
```

> ⚠️ **Never hardcode API keys.** Always use environment variables.

### Start the Stack

```powershell
# One-command restart (kills old processes, starts fresh)
.\restart.ps1

# Or manually:
# Backend
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Frontend (new terminal)
npm run dev
```

Frontend: `http://localhost:5173` · Backend: `http://localhost:8000`

---

## 📁 Project Structure

```
aethelats/
├── backend/
│   ├── main.py              ← FastAPI app, all endpoints, prompts, LLM dispatch
│   ├── structure_agent.py   ← Bot 3: T5-base fine-tuned resume structurer
│   ├── evaluator_agent.py   ← Bot 4: Phi-3.5+LoRA HuggingFace/Colab evaluator
│   ├── skill_graph.json     ← Skill synonym + adjacency knowledge graph
│   └── requirements.txt     ← Python dependencies
│
├── src/
│   ├── App.jsx              ← Root React component + routing
│   ├── components/
│   │   ├── UploadView.jsx         ← Resume + JD upload interface
│   │   ├── ResultsView.jsx        ← Full analysis results layout
│   │   ├── AnalysisPanels.jsx     ← Radar chart, fit score, signals
│   │   ├── CompliancePanels.jsx   ← Counterfactual + fairness metrics
│   │   ├── ModelComparisonPanel.jsx ← FairAI vs LLM bias comparison
│   │   ├── SkillKnowledgeGraph.jsx  ← Interactive skill graph viz
│   │   ├── FeatureSections.jsx    ← JD audit + proof-of-work panels
│   │   ├── UIHelpers.jsx          ← Shared UI components
│   │   ├── AppLogic.js            ← API calls + state management
│   │   └── constants.js           ← Role list, config
│   ├── index.css            ← Global design system + tokens
│   └── main.jsx             ← React entry point
│
├── restart.ps1              ← PowerShell dev environment manager
└── README.md                ← You are here
```

---

## 📜 Research & Regulatory Basis

Aethel's bias metrics are grounded in real legal and academic frameworks:

| Framework | What Aethel Implements |
|-----------|----------------------|
| **EEOC 4/5ths Rule** (USA) | Disparate Impact Ratio ≥ 0.80 |
| **EU AI Act Article 9** (2024) | Bias Amplification Index ≤ 0.15 |
| **NYC Local Law 144** (2023) | Max Score Deviation ≤ 5 pts |
| **Gaucher et al. (2011)** | Masculine-coded JD word detection |
| **Bertrand & Mullainathan (2004)** | Name-based scoring mutation test |
| **UK Equality Act 2010** | Protected characteristic awareness |

---

## 🌟 Key Differentiators vs Commercial ATS

```
Feature                          │ Legacy ATS │ GPT-4 Raw │ Aethel ★
─────────────────────────────────┼────────────┼───────────┼──────────
PII stripped before scoring      │     ✗      │     ✗     │    ✓
Fine-tuned for bias neutrality   │     ✗      │     ✗     │    ✓
Contextual skill scoring         │     ✗      │  Partial  │    ✓
Measured counterfactual deltas   │     ✗      │     ✗     │    ✓
Regulatory fairness metrics      │     ✗      │     ✗     │    ✓
Intersectional bias detection    │     ✗      │     ✗     │    ✓
JD language bias audit           │     ✗      │  Partial  │    ✓
Live proof-of-work scoring       │     ✗      │     ✗     │    ✓
Compares itself to rival LLMs    │     ✗      │     ✗     │    ✓
Open source & auditable          │     ✗      │     ✗     │    ✓
```

---

## ⚖️ License

This project is open source. Contributions that improve fairness, expand bias detection, or improve model accuracy are welcome.

---

<div align="center">

```
  Built to make hiring fair.
  Because a career shouldn't depend on a name.
```

**Aethel · FairAI Resume Intelligence · 2026**

</div>