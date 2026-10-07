"""
MailGuard AI: AI-Based Fake Mail Detection & Explainable Phishing Analysis System
Main Streamlit Application Dashboard
"""

import os
import sys
import json
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

st.set_page_config(
    page_title="MailGuard AI | Phishing & Fake Mail Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
# Project root directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))




# Load environment variables
load_dotenv(os.path.join(BASE_DIR, ".env"))

# Import system modules
from modules.email_parser import parse_email, parse_eml_bytes, parse_pasted_text
from modules.url_analyzer import analyze_urls, defang_url
from modules.feature_extractor import extract_features
from modules.ml_model import get_classifier
from modules.risk_engine import calculate_risk_score
from modules.llm_analyzer import analyze_with_gemini
from modules.report_generator import generate_text_report, generate_json_report
from database import (
    init_db, save_analysis, get_history, get_dashboard_stats,
    clear_history, get_analysis_by_id
)
from utils.helpers import SAMPLE_EMAILS, escape_text, generate_sample_eml

# Page Configuration
st.set_page_config(
    page_title="MailGuard AI | Phishing & Fake Mail Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# Initialize Database
init_db()

# --- SIDEBAR ---
with st.sidebar:
    st.markdown("## 🛡️ MailGuard AI")
    st.caption("Explainable Phishing & Fake Mail Detection System")
    st.markdown("---")

    navigation = st.radio(
        "Navigation",
        ["🏠 Dashboard", "📧 Analyze Email", "📂 Upload EML", "📊 Analysis History", "ℹ️ About"],
        index=0
    )

    st.markdown("---")
    st.markdown("### ⚙️ LLM Integration")
    env_key = os.getenv("GEMINI_API_KEY", "")
    has_env_key = bool(env_key and env_key != "your_api_key_here")

    api_key_input = st.text_input(
        "Gemini API Key (Optional)",
        value=env_key if has_env_key else "",
        type="password",
        help="If not provided, the system utilizes its built-in deterministic Explainable AI engine."
    )
    active_api_key = api_key_input.strip() if api_key_input.strip() else (env_key if has_env_key else None)

    if active_api_key:
        st.success("🟢 Gemini API Configured", icon="✅")
    else:
        st.info("⚙️ Rule-Based Explainable AI Mode", icon="ℹ️")

    st.markdown("---")
    st.markdown("### 🤖 ML Engine Status")
    classifier = get_classifier()
    if classifier.model is not None:
        st.caption("• **Model:** Logistic Regression (Stratified)")
        st.caption("• **Vectorizer:** TF-IDF (10,000 max features)")
        st.caption("• **Status:** Active & Ready")
    else:
        st.warning("⚠️ Model not loaded. Using heuristic fallback.")

    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: #6b7280; font-size: 0.8rem;'>"
        "MailGuard AI v1.0.0<br>Academic & Security Research Project"
        "</div>",
        unsafe_allow_html=True
    )


# --- CORE PIPELINE RUNNER ---
def run_security_pipeline(raw_input, input_type="Pasted"):
    """Executes the full forensic pipeline on an email input."""
    # 1. Parse Email
    email_data = parse_email(raw_input)
    if email_data.get("error") and not email_data.get("body"):
        st.error(f"⚠️ {email_data.get('error')}")
        return None

    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    combined_text = f"{subject}\n{body}".strip()

    if not combined_text:
        st.warning("⚠️ Please provide email content to analyze.")
        return None

    # 2. URL Analysis
    urls = email_data.get("urls", [])
    url_results = analyze_urls(urls)

    # 3. Phishing Language & Sender Feature Extraction
    features = extract_features(email_data)

    # 4. Machine Learning Inference
    ml_results = classifier.predict(combined_text)

    # 5. Risk Engine Fusion
    risk_results = calculate_risk_score(ml_results, url_results, features)

    # 6. Explainable AI Analysis
    with st.spinner("🤖 Generating explainable AI security reasoning..."):
        llm_results = analyze_with_gemini(
            email_data=email_data,
            ml_result=ml_results,
            url_result=url_results,
            feature_result=features,
            risk_result=risk_results,
            api_key=active_api_key
        )

    # 7. Persist to SQLite
    record_id = save_analysis(
        sender=email_data.get("sender", "Unknown"),
        subject=email_data.get("subject", "(No Subject)"),
        prediction=risk_results.get("classification", "UNKNOWN"),
        risk_score=risk_results.get("risk_score", 0.0),
        risk_level=risk_results.get("risk_level", "LOW"),
        model_confidence=ml_results.get("confidence", 0.0),
        detected_risks=risk_results.get("detected_risks", []),
        urls_count=url_results.get("total_urls", 0),
        suspicious_urls_count=url_results.get("suspicious_count", 0),
        input_type=input_type
    )

    return {
        "record_id": record_id,
        "email_data": email_data,
        "url_results": url_results,
        "features": features,
        "ml_results": ml_results,
        "risk_results": risk_results,
        "llm_results": llm_results
    }


# --- RENDER ANALYSIS RESULT VIEW ---
def render_analysis_view(analysis):
    """Renders the comprehensive, production-grade cybersecurity report."""
    email_data = analysis["email_data"]
    url_results = analysis["url_results"]
    features = analysis["features"]
    ml_results = analysis["ml_results"]
    risk_results = analysis["risk_results"]
    llm_results = analysis["llm_results"]

    risk_score = risk_results.get("risk_score", 0.0)
    risk_level = risk_results.get("risk_level", "LOW")
    classification = risk_results.get("classification", "LEGITIMATE")
    model_conf = ml_results.get("confidence", 0.0)
    pred_tag = risk_results.get("prediction_tag", "LEGITIMATE")

    # Banner Class mapping
    banner_class = "banner-low"
    if risk_level == "CRITICAL":
        banner_class = "banner-critical"
    elif risk_level == "HIGH":
        banner_class = "banner-high"
    elif risk_level == "MEDIUM":
        banner_class = "banner-medium"

    # Main Security Assessment Banner
    st.markdown(f"""
    <div class="security-banner {banner_class}">
        <div class="banner-header">
            <div>
                <span class="badge badge-{risk_level.lower()}">{risk_level} RISK</span>
                <div class="classification-title" style="margin-top: 6px;">
                    { '🚨 PHISHING / FAKE EMAIL' if pred_tag == 'PHISHING' else ('⚠️ SUSPICIOUS EMAIL' if pred_tag == 'SUSPICIOUS' else '🟢 SAFE / LEGITIMATE EMAIL') }
                </div>
            </div>
            <div style="text-align: right;">
                <div style="font-size: 0.85rem; color: #9ca3af; text-transform: uppercase;">Overall Risk Score</div>
                <div class="risk-score-display" style="color: {'#ef4444' if risk_score >= 80 else ('#f97316' if risk_score >= 60 else ('#f59e0b' if risk_score >= 30 else '#10b981'))};">
                    {risk_score} <span style="font-size: 1.2rem; color: #6b7280;">/ 100</span>
                </div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Metrics Summary Row
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.metric(label="Model Confidence", value=f"{model_conf}%")
    with col_m2:
        st.metric(label="ML Base Probability", value=f"{ml_results.get('phishing_probability', 0.0)*100:.1f}%")
    with col_m3:
        st.metric(label="Flagged URLs", value=f"{url_results.get('suspicious_count', 0)} / {url_results.get('total_urls', 0)}")
    with col_m4:
        st.metric(label="Detected Risk Signals", value=len(risk_results.get("detected_risks", [])))

    st.progress(float(risk_score) / 100.0)

    st.markdown("---")

    # Section 17: Reasons Section
    st.markdown("### ⚠️ Key Detected Risk Indicators")
    reasons = features.get("reasons", [])
    if reasons:
        r_cols = st.columns(2)
        for idx, r in enumerate(reasons):
            col_target = r_cols[idx % 2]
            sev_class = "reason-high" if r.get("severity") == "High" else ("reason-medium" if r.get("severity") == "Medium" else "reason-low")
            with col_target:
                st.markdown(f"""
                <div class="reason-card {sev_class}">
                    <div class="reason-title">⚠ {escape_text(r.get('title', ''))}</div>
                    <div class="reason-desc">{escape_text(r.get('description', ''))}</div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.success("✅ No overt phishing indicators, threat language, or domain discrepancies detected.")

    # Section 18: URL Analysis Section
    st.markdown("### 🔗 URL Forensic Analysis")
    url_details = url_results.get("url_details", [])
    if url_details:
        url_rows = []
        for u in url_details:
            url_rows.append({
                "Inspected URL (Defanged)": u.get("defanged_url"),
                "Risk Rating": u.get("risk_level"),
                "Score": f"{u.get('risk_score')}/100",
                "SSL / HTTPS": "✅ Secure (HTTPS)" if u.get("is_https") else "❌ Insecure (HTTP)",
                "Identified Risk Indicators": ", ".join(u.get("indicators", [])) or "None (Clean)"
            })
        st.dataframe(pd.DataFrame(url_rows), use_container_width=True)
        st.warning("🔒 Note: URLs above are automatically defanged (hxxp / [.]) to prevent accidental navigation.")
    else:
        st.info("ℹ️ No URLs were found in this email.")

    # Section 13: Explainable AI / LLM Explanation
    st.markdown("### 🤖 Explainable AI Reasoning")
    st.markdown(f"""
    <div class="ai-box">
        <div class="ai-header">
            <span>🛡️ Forensic Synthesis ({escape_text(llm_results.get('source', 'Explainable AI'))})</span>
        </div>
        <p style="font-size: 1.05rem; line-height: 1.6; color: #f3f4f6;">
            <strong>Executive Summary:</strong> {escape_text(llm_results.get('summary', ''))}
        </p>
        <p style="line-height: 1.5; color: #d1d5db;">
            <strong>Detailed Analysis:</strong> {escape_text(llm_results.get('why_suspicious', ''))}
        </p>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("🔍 Deep Dive: Social Engineering & Infrastructure Notes"):
        col_ai1, col_ai2 = st.columns(2)
        with col_ai1:
            st.markdown("**Manipulative Psychological Tactics Detected:**")
            tactics = llm_results.get("social_engineering", [])
            if isinstance(tactics, list):
                for t in tactics:
                    st.markdown(f"- {escape_text(str(t))}")
            else:
                st.markdown(f"- {escape_text(str(tactics))}")

            st.markdown("**Sender & Identity Evaluation:**")
            st.write(llm_results.get("sender_concerns", "No sender anomalies noted."))

        with col_ai2:
            st.markdown("**URL & Network Observations:**")
            st.write(llm_results.get("url_concerns", "No URL anomalies noted."))

    # Section 20: Recommendations
    st.markdown("### 🛡️ Recommended Security Actions")
    st.markdown(f"""
    <div class="rec-box">
        <div class="rec-title">Standard Operating Procedure:</div>
        <div style="white-space: pre-line; line-height: 1.6; color: #e2e8f0;">
            {escape_text(llm_results.get('recommendations', ''))}
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Section 19: Expandable Email Information
    with st.expander("📋 Extracted Email Metadata"):
        col_e1, col_e2 = st.columns(2)
        with col_e1:
            st.markdown(f"**From:** `{escape_text(email_data.get('sender', 'Not specified'))}`")
            st.markdown(f"**To:** `{escape_text(email_data.get('recipient', 'Not specified'))}`")
            st.markdown(f"**Subject:** `{escape_text(email_data.get('subject', '(No Subject)'))}`")
            st.markdown(f"**Date:** `{escape_text(email_data.get('date', 'Unknown'))}`")
        with col_e2:
            st.markdown(f"**Reply-To:** `{escape_text(email_data.get('reply_to', 'Not specified'))}`")
            st.markdown(f"**Return-Path:** `{escape_text(email_data.get('return_path', 'Not specified'))}`")

    with st.expander("🧾 Authentication & Raw Headers"):
        headers = email_data.get("headers", {})
        if headers:
            st.json(headers)
        else:
            st.info("No RFC-822 headers were found in this input format.")

    with st.expander("📎 Attachments"):
        attachments = email_data.get("attachments", [])
        if attachments:
            st.table(pd.DataFrame(attachments))
        else:
            st.info("No attachments detected.")

    # Export & Download Section (Section 31 Output format)
    st.markdown("---")
    st.markdown("### 📥 Export Forensic Report")
    col_dl1, col_dl2 = st.columns(2)

    text_report = generate_text_report(
        email_data=email_data,
        ml_result=ml_results,
        url_result=url_results,
        feature_result=features,
        risk_result=risk_results,
        llm_result=llm_results
    )

    json_report = generate_json_report(
        email_data=email_data,
        ml_result=ml_results,
        url_result=url_results,
        feature_result=features,
        risk_result=risk_results,
        llm_result=llm_results
    )

    with col_dl1:
        st.download_button(
            label="📄 Download Security Report (TXT)",
            data=text_report,
            file_name=f"mailguard_report_{analysis.get('record_id', 'scan')}.txt",
            mime="text/plain",
            use_container_width=True
        )
    with col_dl2:
        st.download_button(
            label="💾 Download Forensic Data (JSON)",
            data=json_report,
            file_name=f"mailguard_forensics_{analysis.get('record_id', 'scan')}.json",
            mime="application/json",
            use_container_width=True
        )


# ==========================================
# PAGE ROUTING
# ==========================================

# 1. 🏠 DASHBOARD
if navigation == "🏠 Dashboard":
    st.title("🛡️ Executive Cybersecurity Dashboard")
    st.caption("Real-time threat monitoring and email security telemetry")

    stats = get_dashboard_stats()

    # Section 15 KPI Cards
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">📧</div>
            <div class="metric-value">{stats['total_analyzed']}</div>
            <div class="metric-label">Emails Analyzed</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">🚨</div>
            <div class="metric-value" style="color: #f87171;">{stats['phishing_detected']}</div>
            <div class="metric-label">Phishing Detected</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">🟢</div>
            <div class="metric-value" style="color: #34d399;">{stats['safe_emails']}</div>
            <div class="metric-label">Safe Emails</div>
        </div>
        """, unsafe_allow_html=True)

    with kpi4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-icon">🔴</div>
            <div class="metric-value" style="color: #ef4444;">{stats['high_risk_emails']}</div>
            <div class="metric-label">High / Critical Risk</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts Row
    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.markdown("#### 📊 Risk Distribution Breakdown")
        dist_data = stats["risk_distribution"]
        df_dist = pd.DataFrame({
            "Risk Level": list(dist_data.keys()),
            "Email Count": list(dist_data.values())
        })
        st.bar_chart(df_dist.set_index("Risk Level"), color="#0284c7")

    with chart_col2:
        st.markdown("#### 🎯 Classification Ratio")
        tot = stats["total_analyzed"]
        if tot > 0:
            df_pie = pd.DataFrame({
                "Category": ["Phishing", "Safe", "Other/Suspicious"],
                "Count": [
                    stats["phishing_detected"],
                    stats["safe_emails"],
                    max(0, tot - stats["phishing_detected"] - stats["safe_emails"])
                ]
            })
            st.dataframe(df_pie, use_container_width=True, hide_index=True)
            st.caption(f"Average System Risk Score: **{stats['avg_risk_score']} / 100**")
        else:
            st.info("No emails analyzed yet. Run your first analysis from the 'Analyze Email' tab!")

    # Recent Scans Table
    st.markdown("#### 🕒 Recent Threat Analyses")
    recent = stats["recent_scans"]
    if recent:
        df_recent = pd.DataFrame(recent)[["id", "timestamp", "sender", "subject", "prediction", "risk_score", "risk_level"]]
        st.dataframe(df_recent, use_container_width=True, hide_index=True)
    else:
        st.info("No scan history recorded. Go to 'Analyze Email' to begin testing!")


# 2. 📧 ANALYZE EMAIL
elif navigation == "📧 Analyze Email":
    st.title("🛡️ AI Email Security Analyzer")
    st.caption("AI-powered phishing and fake email detection")

    # Sample Selection bar for easy 1-click testing
    st.markdown("#### ⚡ 1-Click Sample Test Emails")
    sample_choice = st.selectbox(
        "Load a realistic test scenario:",
        ["-- Select a Sample --"] + list(SAMPLE_EMAILS.keys())
    )

    default_text = ""
    if sample_choice != "-- Select a Sample --":
        sample = SAMPLE_EMAILS[sample_choice]
        default_text = sample["body"]
        st.info(f"💡 Loaded **{sample_choice}** (Expected Result: {sample['expected']})")

    # Input method selection
    input_method = st.radio("Choose Input Method:", ["Option A — Paste Email Content", "Option B — Upload .eml File"], horizontal=True)

    analyzed_result = None

    if "Paste" in input_method:
        user_text = st.text_area(
            "Paste suspicious email here...",
            value=default_text,
            height=240,
            placeholder="Paste raw email text or headers and body here...\n\nExample:\nYour SBI account will be blocked today.\nClick the link below immediately to verify your account.\nhttp://sbi-security-verification-example.com\nEnter your username and password."
        )

        col_b1, col_b2 = st.columns([1, 4])
        with col_b1:
            analyze_clicked = st.button("🔍 ANALYZE EMAIL", use_container_width=True)

        if analyze_clicked:
            if not user_text.strip():
                st.warning("⚠️ Please enter an email before analyzing.")
            else:
                analyzed_result = run_security_pipeline(user_text, input_type="Pasted")

    else:
        uploaded_file = st.file_uploader("Upload an .eml email file", type=["eml"])
        
        # Helper to let user test upload without having an eml file on hand
        col_up1, col_up2 = st.columns([2, 2])
        with col_up1:
            st.download_button(
                label="📥 Download Sample Phishing .eml for Testing",
                data=generate_sample_eml("Test 1 — Phishing (Bank Account Suspension)"),
                file_name="sample_phishing_test.eml",
                mime="message/rfc822"
            )

        if uploaded_file is not None:
            st.info(f"File uploaded: **{uploaded_file.name}** ({uploaded_file.size} bytes)")
            if st.button("🔍 ANALYZE UPLOADED EML", use_container_width=True):
                eml_bytes = uploaded_file.read()
                analyzed_result = run_security_pipeline(eml_bytes, input_type="EML Upload")

    if analyzed_result:
        st.markdown("---")
        render_analysis_view(analyzed_result)


# 3. 📂 UPLOAD EML (DEDICATED EML INSPECTOR)
elif navigation == "📂 Upload EML":
    st.title("📂 Deep .EML File Inspector")
    st.caption("RFC-822 forensic file parsing and header integrity audit")

    st.markdown("Upload any `.eml` file exported from Outlook, Gmail, Apple Mail, or Thunderbird.")
    
    col_eml_dl, _ = st.columns([2, 2])
    with col_eml_dl:
        st.download_button(
            label="📥 Download Test Phishing .eml",
            data=generate_sample_eml(),
            file_name="test_phishing_alert.eml",
            mime="message/rfc822"
        )

    eml_file = st.file_uploader("Select .eml file to audit", type=["eml"], key="eml_deep_uploader")

    if eml_file is not None:
        file_bytes = eml_file.read()
        parsed = parse_eml_bytes(file_bytes)

        st.success(f"Parsed `{eml_file.name}` successfully!")

        tab1, tab2, tab3 = st.tabs(["📧 Message Overview", "🧾 Headers & Authentication", "📎 Attachments & URLs"])
        
        with tab1:
            st.markdown(f"**From:** `{escape_text(parsed.get('sender', ''))}`")
            st.markdown(f"**To:** `{escape_text(parsed.get('recipient', ''))}`")
            st.markdown(f"**Subject:** `{escape_text(parsed.get('subject', ''))}`")
            st.markdown(f"**Date:** `{escape_text(parsed.get('date', ''))}`")
            st.text_area("Extracted Body Content", value=parsed.get("body", ""), height=200, disabled=True)

        with tab2:
            st.markdown("#### Authentication Headers:")
            auth = parsed.get("auth_headers", {})
            if auth:
                st.json(auth)
            else:
                st.warning("No explicit SPF/DKIM/DMARC headers found in this message.")

            st.markdown("#### Full Header Table:")
            st.json(parsed.get("headers", {}))

        with tab3:
            st.markdown("#### URLs Extracted:")
            st.write(parsed.get("urls", []))
            st.markdown("#### Attachments:")
            st.write(parsed.get("attachments", []))

        st.markdown("---")
        if st.button("🚀 RUN FULL AI PHISHING ASSESSMENT ON THIS FILE"):
            res = run_security_pipeline(file_bytes, input_type="EML Upload")
            if res:
                render_analysis_view(res)


# 4. 📊 ANALYSIS HISTORY
elif navigation == "📊 Analysis History":
    st.title("📊 Analysis History & Audit Log")
    st.caption("Searchable local audit log of all email evaluations stored in SQLite")

    # Search & Filter Controls
    col_s1, col_s2, col_s3 = st.columns([2, 1, 1])
    with col_s1:
        search_query = st.text_input("🔍 Search by Sender or Subject", "")
    with col_s2:
        filter_pred = st.selectbox("Filter Prediction", ["ALL", "PHISHING / FAKE", "SUSPICIOUS", "SAFE / LEGITIMATE"])
    with col_s3:
        filter_risk = st.selectbox("Filter Risk Level", ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

    history_records = get_history(
        search_query=search_query,
        filter_prediction=filter_pred if filter_pred != "ALL" else None,
        filter_risk_level=filter_risk if filter_risk != "ALL" else None
    )

    if history_records:
        df_hist = pd.DataFrame(history_records)
        cols_to_show = ["id", "timestamp", "sender", "subject", "prediction", "risk_score", "risk_level", "model_confidence", "input_type"]
        st.dataframe(df_hist[cols_to_show], use_container_width=True, hide_index=True)

        # Inspection viewer
        st.markdown("#### 🔎 View Past Record Details")
        selected_id = st.selectbox("Select Record ID to inspect:", [r["id"] for r in history_records])
        rec = get_analysis_by_id(selected_id)
        if rec:
            st.json(rec)

        # Clear History Option
        st.markdown("---")
        col_c1, _ = st.columns([1, 4])
        with col_c1:
            if st.button("🗑️ Clear Scan History"):
                clear_history()
                st.success("Analysis history cleared successfully.")
                st.rerun()
    else:
        st.info("No records match your filter criteria.")


# 5. ℹ️ ABOUT
elif navigation == "ℹ️ About":
    st.title("ℹ️ About MailGuard AI")
    st.caption("AI-Based Fake Mail Detection & Explainable Phishing Analysis System")

    st.markdown("""
    ### 🎯 System Architecture
    MailGuard AI uses a multi-layered, hybrid defense-in-depth pipeline:
    
    ```
    Raw Email (.eml or Pasted)
            │
            ▼
    ┌───────────────────────┐
    │  Email Parser Engine  │ ──► Headers, Sender, Body, URLs, Attachments
    └───────────────────────┘
            │
            ├─────────────────────────────────────────────────┐
            ▼                                                 ▼
    ┌─────────────────────────┐                     ┌─────────────────────────┐
    │   Linguistic & Domain   │                     │    TF-IDF Vectorizer    │
    │    Feature Extractor    │                     │  + Logistic Regression  │
    └─────────────────────────┘                     └─────────────────────────┘
            │                                                 │
            │ (Urgency, Threats, Mismatches)                 │ (ML Probability & Conf.)
            ▼                                                 ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                 Multi-Vector Security Risk Engine                       │
    │  • ML Model (50%)     • Language (15%)       • Sender Mismatch (10%)    │
    │  • URLs (15%)         • Credentials (10%)    • Normalized 0-100 Score   │
    └─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │          Explainable AI Layer (Gemini LLM / Rule Heuristic)             │
    │   Explains the 'Why': Context, Tactics, URL & Sender Threat Evidence    │
    └─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                      Final Cybersecurity Report                         │
    │      Risk Level + Reasons + URL Forensic Table + Recommendations        │
    └─────────────────────────────────────────────────────────────────────────┘
    ```
    
    ### 🔬 Machine Learning Model Details
    - **Classifier:** Logistic Regression with balanced class weights
    - **Vectorizer:** TF-IDF with `ngram_range=(1,2)` and `max_features=10000`
    - **Cross-validation Metric:** Evaluated with Stratified 80/20 train/test split
    - **Artifacts:** Stored via `joblib` in `models/` directory
    
    ### 🛡️ Multi-Signal Risk Scoring Weights
    | Component | Weight | Description |
    | :--- | :--- | :--- |
    | **ML Prediction** | 50% | Logistic Regression classification probability |
    | **URL Risk** | 15% | Heuristics on IP, TLD, length, keywords, shorteners |
    | **Language Risk** | 15% | Urgency keywords, suspension threats, calls to action |
    | **Sender / Domain** | 10% | Display name spoofing, brand mismatch, free email check |
    | **Credentials & Finance** | 10% | Password, OTP, PIN, bank transfer, CVV solicitations |
    
    ### 🔐 Security & Privacy
    - Analysis is performed locally on your machine.
    - Full email bodies are not retained in the SQLite database to preserve data privacy.
    - Suspicious URLs are defanged to prevent accidental clicking.
    """)
