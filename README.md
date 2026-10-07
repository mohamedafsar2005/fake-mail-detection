# 🛡️ MailGuard AI: AI-Based Fake Mail Detection & Explainable Phishing Analysis System

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.3+-F7931E.svg)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade, explainable cybersecurity web application designed to inspect, classify, and explain suspicious and phishing emails. **MailGuard AI** integrates Machine Learning (TF-IDF + Logistic Regression), deep URL heuristics, linguistic threat pattern extraction, sender domain discrepancy analysis, and an Explainable AI (XAI) reasoning layer powered by Google Gemini (with deterministic rule-based fallback).

---

## 📌 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [System Architecture](#-system-architecture)
4. [Technology Stack](#-technology-stack)
5. [Folder Structure](#-folder-structure)
6. [Installation & Setup](#-installation--setup)
7. [Dataset & Model Training](#-dataset--model-training)
8. [Configuration (.env)](#-configuration-env)
9. [How to Run the Application](#-how-to-run-the-application)
10. [Test Scenarios & Sample Emails](#-test-scenarios--sample-emails)
11. [Output Security Report Format](#-output-security-report-format)
12. [Forensic Audit History (SQLite)](#-forensic-audit-history-sqlite)
13. [Limitations & Future Enhancements](#-limitations--future-enhancements)

---

## 🌟 Project Overview
Phishing remains the #1 initial access vector in cyberattacks. Traditional spam filters often output binary verdicts without giving users or SOC analysts the rationale behind a classification. 

**MailGuard AI** solves this problem by delivering **transparent, multi-vector Explainable Phishing Analysis**:
- Evaluates email text using a trained **Machine Learning classifier**.
- Defangs and audits all embedded **URLs** across 12+ risk indicators (IP hostnames, suspicious TLDs, brand spoofing, open redirects).
- Scans for **psychological manipulation markers** (urgency, account suspension threats, credential harvesting, financial demands).
- Flags **sender display name vs. domain discrepancies** and free email service abuse.
- Fuses all signals into a normalized **0–100 Security Risk Score**.
- Produces **AI-powered reasoning** and actionable defense recommendations.

---

## 🚀 Key Features

- **Dual Ingestion Channels**:
  - **Paste Email**: Paste raw email bodies or full RFC-822 message headers.
  - **Upload .EML**: Upload `.eml` files directly from Gmail, Outlook, Thunderbird, or Apple Mail.
- **Deep RFC-822 Header Parsing**:
  - Automatically extracts `From`, `To`, `Subject`, `Date`, `Reply-To`, `Return-Path`, authentication headers (SPF, DKIM, DMARC), and MIME attachments.
- **URL Threat Intelligence**:
  - Checks HTTP vs HTTPS, IP address hostnames, high-risk TLDs (`.xyz`, `.top`, `.club`), URL shorteners, excessive subdomains/hyphens, brand impersonation, and basic auth `@` spoofing.
- **Linguistic Phishing Heuristics**:
  - Pinpoints coercive patterns: urgency ("within 24 hours"), fear/threats ("account blocked"), credential demands ("enter password and OTP"), and prize baiting.
- **Transparent Multi-Vector Risk Engine**:
  - Weighted fusion: 50% ML Model + 15% URLs + 15% Language + 10% Sender Domain + 10% Credentials.
  - Configurable risk tiers: Low (0–29), Medium (30–59), High (60–79), Critical (80–100).
- **Explainable AI (XAI)**:
  - Generates clear, fact-grounded reasoning using Google Gemini API (`google-genai`).
  - Includes a **100% offline, deterministic rule-based fallback** when no API key is provided.
- **Persistent Local Audit History**:
  - Stores scan metadata, risk scores, and identified indicators in SQLite (`mailguard_history.db`).
- **Executive SOC Dashboard**:
  - Real-time KPI metrics, risk level distributions, and historical trend monitoring.
- **Report Export**:
  - 1-click download of the complete security assessment as clean `.txt` or forensic `.json`.

---

## 🏗️ System Architecture

```
                       Raw Email (.eml or Pasted Text)
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │     Email Parser Engine       │
                     │ (Headers, Body, URLs, Files)  │
                     └───────────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
   ┌───────────────────────────┐           ┌───────────────────────────┐
   │ Linguistic & Domain Engine│           │     TF-IDF Vectorizer     │
   │ • Urgency & Threat Regex  │           │   + Logistic Regression   │
   │ • Sender / Brand Mismatch │           │    (Stratified Split)     │
   │ • Deep URL Heuristics     │           └───────────────────────────┘
   └───────────────────────────┘                         │
                 │                                       │ (Probability & Conf.)
                 └───────────────────┬───────────────────┘
                                     ▼
                     ┌───────────────────────────────┐
                     │   Multi-Vector Risk Engine    │
                     │  (Weighted Signal Fusion)     │
                     └───────────────────────────────┘
                                     │
                                     ▼
                     ┌───────────────────────────────┐
                     │   Explainable AI Layer (XAI)  │
                     │   Gemini LLM / Rule Engine    │
                     └───────────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
   ┌───────────────────────────┐           ┌───────────────────────────┐
   │ Professional Streamlit UI │           │ SQLite Audit Database     │
   │ (Banners, Cards, Badges)  │           │ (Search, Filter, Export)  │
   └───────────────────────────┘           └───────────────────────────┘
```

---

## 💻 Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend UI** | Streamlit, Custom Dark Cybersecurity CSS, Responsive Layout |
| **Backend** | Python 3.11 / 3.12, Modular Architecture |
| **Machine Learning** | scikit-learn, TF-IDF Vectorizer, Logistic Regression, Random Forest |
| **Data Processing** | pandas, numpy, joblib |
| **Email Processing** | Python `email`, `email.parser`, `email.policy` |
| **URL Analysis** | `urllib.parse`, Regular Expressions, Defanging Heuristics |
| **Explainable AI** | Google Gemini API (`google-genai`), Deterministic Fallback Engine |
| **Database** | SQLite3 (`mailguard_history.db`) |
| **Configuration** | `python-dotenv` |

---

## 📁 Folder Structure

```
ai_fake_mail_detector/
│
├── app.py                      # Main Streamlit application and UI router
├── database.py                 # SQLite database storage and telemetry functions
├── requirements.txt            # Python dependencies
├── README.md                   # Complete documentation
├── .env.example                # Template for environment variables
├── .env                        # Local environment configuration
├── .gitignore                  # Git ignore rules
│
├── data/
│   └── email_dataset.csv       # Training dataset (Legitimate + Phishing)
│
├── models/
│   ├── phishing_model.pkl      # Trained Logistic Regression classifier
│   └── tfidf_vectorizer.pkl    # Fitted TF-IDF Vectorizer (10,000 features)
│
├── modules/
│   ├── __init__.py
│   ├── email_parser.py         # Robust RFC-822 and plain text email parser
│   ├── url_analyzer.py         # URL extraction, defanging, and heuristic analyzer
│   ├── feature_extractor.py    # Phishing language, urgency, threat & sender analysis
│   ├── ml_model.py             # Inference wrapper and top feature attribution
│   ├── risk_engine.py          # Multi-vector weighted risk scoring engine
│   ├── llm_analyzer.py         # Gemini LLM explainable AI with rule-based fallback
│   └── report_generator.py     # Section 31 compliant report generators (TXT & JSON)
│
├── training/
│   ├── generate_dataset.py     # Generator for realistic balanced training samples
│   └── train_model.py          # Model training pipeline, metrics & artifact saving
│
├── utils/
│   ├── __init__.py
│   └── helpers.py              # XSS escaping, defanging, test samples & EML builder
│
└── assets/
    └── style.css               # Dark cybersecurity dashboard theme
```

---

## ⚙️ Installation & Setup

### 1. Clone or Navigate to the Project Folder
```powershell
cd C:\Users\admin\.gemini\antigravity\scratch\ai_fake_mail_detector
```

### 2. Create and Activate a Python Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

---

## 🧠 Dataset & Model Training

The project includes an automated dataset generator and training pipeline.

### Step 1: Generate the Training Dataset (if recreating)
```powershell
python training/generate_dataset.py
```
This generates 340+ balanced, realistic email examples in `data/email_dataset.csv`.

### Step 2: Train the ML Model
```powershell
python training/train_model.py
```

**Training Output:**
- Splits dataset 80/20 with stratification (`random_state=42`).
- Vectorizes with `TfidfVectorizer(max_features=10000, ngram_range=(1,2), stop_words="english")`.
- Fits balanced `LogisticRegression(max_iter=1000)`.
- Displays Accuracy, Precision, Recall, F1 Score, and Confusion Matrix.
- Saves `models/phishing_model.pkl` and `models/tfidf_vectorizer.pkl`.

---

## 🔑 Configuration (.env)

Create a `.env` file from `.env.example`:
```ini
GEMINI_API_KEY=your_gemini_api_key_here
```

> **Note:** MailGuard AI is built with **zero external dependencies for core functionality**. If you do not provide a Gemini API key, the system automatically activates its built-in deterministic Explainable AI engine.

---

## 🚀 How to Run the Application

Launch the Streamlit web application:
```powershell
streamlit run app.py
```

The application will start immediately. Open your browser at:
```
http://localhost:8501
```

---

## 🧪 Test Scenarios & Sample Emails

The **Analyze Email** page includes a 1-click sample dropdown pre-loaded with these exact scenarios:

### Test 1 — Phishing (Bank Account Suspension)
```
From: security@sbi-verification-example.com
Subject: Urgent: Your Bank Account Will Be Suspended

Your account will be suspended today.
Click the link below immediately to verify your identity.
http://secure-bank-verification-example.com/login
Enter your username, password and OTP.
```
*Expected Result:* **PHISHING / Critical Risk (80–100%)**

### Test 2 — Legitimate (Monthly Statement)
```
From: statements@chase.com
Subject: Your monthly account statement

Dear Customer,
Your monthly statement is now available through your official banking application.
You can log in securely at https://www.chase.com or use our mobile banking app.
Thank you for banking with us.
```
*Expected Result:* **SAFE / LEGITIMATE (Low Risk 0–29%)**

### Test 3 — Suspicious (Prize / Reward Bait)
```
From: rewards@promotions-club.xyz
Subject: You won a reward!

Congratulations!
You have been selected for a special reward.
Click the link below to claim your prize.
http://special-promo-giveaway.club/claim
Hurry, offer expires in 2 hours!
```
*Expected Result:* **SUSPICIOUS / High Risk (60–79%)**

---

## 📄 Output Security Report Format

When an email is analyzed, MailGuard AI outputs this structured security assessment:

```text
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ EMAIL SECURITY REPORT
Prediction:
🚨 PHISHING EMAIL
Risk Score:
94 / 100
Risk Level:
🔴 CRITICAL RISK
ML Confidence:
91.4%
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️ DETECTED RISKS
• Urgent language detected
• Account suspension threat
• Suspicious URL detected (1 flagged)
• Sensitive credential request (password/OTP/PIN)
• Possible sender / domain mismatch
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔗 URL ANALYSIS
Suspicious URLs:
1
Safe URLs:
0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 AI EXPLANATION
The message combines artificial urgency ('immediately') with punitive threats
('account will be suspended') designed to induce panic. The communication
explicitly solicits confidential credentials ('username, password and OTP').
The embedded link uses an insecure HTTP connection with brand impersonation.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️ RECOMMENDATION
❌ Do not click any links.
❌ Do not enter your credentials.
❌ Do not provide OTP/PIN/password or financial data.
✅ Verify the request through the organization's official website or application.
✅ Report the email as phishing to your security administrator.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 📊 Forensic Audit History (SQLite)

Every analysis is automatically archived in `mailguard_history.db`.
- **Search:** Search across subjects and senders.
- **Filter:** Filter by prediction verdict (`PHISHING`, `SUSPICIOUS`, `LEGITIMATE`) or risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Audit Detail:** View timestamp, extracted indicators, and score breakdown.
- **Privacy:** Email body text is never stored in the database to prevent sensitive data leakage.

---

## 🔮 Limitations & Future Enhancements

### Current Limitations:
1. **DKIM / SPF Validation**: The parser inspects existing authentication headers from the `.eml` file, but does not perform live DNS TXT lookups against the sender domain.
2. **Domain Age**: Requires live WHOIS API queries to check domain registration age (<30 days).

### Future Enhancements:
- [ ] Integration with VirusTotal API for real-time URL reputation lookup.
- [ ] Live DNS and WHOIS domain age inspection.
- [ ] Sandboxed attachment detonation for PDF and Office documents.
- [ ] Browser extension for automatic Chrome/Firefox webmail scanning.

---

## 📜 License
This project is open-source under the MIT License for educational and cybersecurity research purposes.
