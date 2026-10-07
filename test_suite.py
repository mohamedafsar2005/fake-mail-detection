"""
Automated Test Suite for MailGuard AI
Validates all pipeline stages: Email Parser, URL Analyzer, Feature Extractor,
ML Model, Risk Engine, Explainable AI, Database, and Report Generator.
"""

import os
import sys

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from modules.email_parser import parse_email, parse_eml_bytes, parse_pasted_text
from modules.url_analyzer import analyze_urls, analyze_single_url, defang_url
from modules.feature_extractor import extract_features
from modules.ml_model import get_classifier
from modules.risk_engine import calculate_risk_score
from modules.llm_analyzer import generate_rule_based_explanation, analyze_with_gemini
from modules.report_generator import generate_text_report, generate_json_report
from database import init_db, save_analysis, get_history, get_dashboard_stats, get_analysis_by_id
from utils.helpers import SAMPLE_EMAILS, generate_sample_eml

def run_tests():
    print("=" * 60)
    print("[*] STARTING MAILGUARD AI VERIFICATION SUITE")
    print("=" * 60)
    passed = 0
    total = 0

    # TEST 1: URL Analyzer & Defanging
    total += 1
    print("\n[Test 1] URL Analyzer Heuristics & Defanging...")
    test_url = "http://secure-sbi-login-verification-example.com/login"
    url_res = analyze_single_url(test_url)
    assert url_res["risk_level"] in ("High", "Medium"), f"Expected High/Medium, got {url_res['risk_level']}"
    assert "Insecure HTTP protocol" in url_res["indicators"][0], "Expected HTTP flag"
    assert "hxxp://" in url_res["defanged_url"], "Expected defanged protocol"
    print(f"  -> Risk Level: {url_res['risk_level']}, Score: {url_res['risk_score']}")
    print(f"  -> Defanged URL: {url_res['defanged_url']}")
    print(f"  -> Indicators: {url_res['indicators']}")
    print("  [PASS] URL Analyzer functioning accurately.")
    passed += 1

    # TEST 2: Email Parser (Text & EML bytes)
    total += 1
    print("\n[Test 2] Email Parser (Text & RFC-822 EML)...")
    sample_phish = SAMPLE_EMAILS["Test 1 — Phishing (Bank Account Suspension)"]
    parsed_text = parse_email(sample_phish["body"])
    assert "sbi-verification-example.com" in parsed_text["sender"], "Failed to extract sender"
    assert len(parsed_text["urls"]) >= 1, "Failed to extract URLs from text"
    
    # Test EML bytes parser
    eml_bytes = generate_sample_eml()
    parsed_eml = parse_eml_bytes(eml_bytes)
    assert parsed_eml["subject"] == "Urgent: Your Bank Account Will Be Suspended", "EML subject mismatch"
    assert len(parsed_eml["urls"]) >= 1, "EML url extraction failed"
    print(f"  -> Parsed Sender: {parsed_text['sender']}")
    print(f"  -> Parsed Subject: {parsed_text['subject']}")
    print(f"  -> Extracted URLs: {parsed_text['urls']}")
    print("  [PASS] Email Parser successfully parsed text and .eml bytes.")
    passed += 1

    # TEST 3: Feature Extractor (Urgency, Threat, Credential, Sender Mismatch)
    total += 1
    print("\n[Test 3] Feature Extractor & Phishing Indicators...")
    features = extract_features(parsed_text)
    assert len(features["urgency_matches"]) > 0 or len(features["threat_matches"]) > 0, "Failed to detect urgency/threat"
    assert len(features["credential_matches"]) > 0, "Failed to detect credential requests (password/OTP)"
    print(f"  -> Urgency Matches: {features['urgency_matches']}")
    print(f"  -> Threat Matches: {features['threat_matches']}")
    print(f"  -> Credential Matches: {features['credential_matches']}")
    print(f"  -> Sender Mismatch: {features['sender_analysis']['mismatch_detected']}")
    print("  [PASS] Feature Extractor captured all phishing signals.")
    passed += 1

    # TEST 4: ML Inference & Model Confidence
    total += 1
    print("\n[Test 4] ML Model Inference (Logistic Regression)...")
    clf = get_classifier()
    ml_res_phish = clf.predict(sample_phish["body"])
    assert ml_res_phish["prediction"] == "PHISHING", f"Expected PHISHING, got {ml_res_phish['prediction']}"
    assert ml_res_phish["confidence"] >= 50.0, f"Confidence too low: {ml_res_phish['confidence']}%"
    print(f"  -> Phishing Prediction: {ml_res_phish['prediction']}")
    print(f"  -> Phishing Probability: {ml_res_phish['phishing_probability']}")
    print(f"  -> Model Confidence: {ml_res_phish['confidence']}%")
    print(f"  -> Top Attributed Features: {ml_res_phish['top_features']}")

    # Test Legitimate Email Prediction
    sample_legit = SAMPLE_EMAILS["Test 2 — Legitimate (Monthly Statement)"]
    ml_res_legit = clf.predict(sample_legit["body"])
    assert ml_res_legit["prediction"] == "LEGITIMATE", f"Expected LEGITIMATE, got {ml_res_legit['prediction']}"
    print(f"  -> Legitimate Prediction: {ml_res_legit['prediction']} (Conf: {ml_res_legit['confidence']}%)")
    print("  [PASS] Machine Learning Model predictions verified.")
    passed += 1

    # TEST 5: Risk Engine Scoring & Overrides
    total += 1
    print("\n[Test 5] Multi-Vector Risk Engine...")
    urls_res = analyze_urls(parsed_text["urls"])
    risk_res_phish = calculate_risk_score(ml_res_phish, urls_res, features)
    assert risk_res_phish["risk_score"] >= 80.0, f"Expected Critical Risk (>=80), got {risk_res_phish['risk_score']}"
    assert risk_res_phish["risk_level"] == "CRITICAL", f"Expected CRITICAL, got {risk_res_phish['risk_level']}"
    print(f"  -> Overall Risk Score: {risk_res_phish['risk_score']}/100")
    print(f"  -> Risk Level: {risk_res_phish['risk_level']} ({risk_res_phish['risk_badge']})")
    print(f"  -> Detected Risks: {risk_res_phish['detected_risks']}")
    print("  [PASS] Risk Engine normalized score and correctly assigned Critical Risk.")
    passed += 1

    # TEST 6: Explainable AI (Rule-Based Fallback when API key is missing)
    total += 1
    print("\n[Test 6] Explainable AI Fallback Engine (No API Key)...")
    llm_res = analyze_with_gemini(
        email_data=parsed_text,
        ml_result=ml_res_phish,
        url_result=urls_res,
        feature_result=features,
        risk_result=risk_res_phish,
        api_key=None  # Missing API key scenario
    )
    assert "summary" in llm_res and len(llm_res["summary"]) > 10, "Summary generation failed"
    assert "why_suspicious" in llm_res and len(llm_res["why_suspicious"]) > 10, "Reasoning generation failed"
    assert len(llm_res["social_engineering"]) > 0, "Failed to extract social engineering tactics"
    print(f"  -> Source: {llm_res['source']}")
    print(f"  -> Summary: {llm_res['summary'][:90]}...")
    print(f"  -> Social Engineering: {llm_res['social_engineering']}")
    print("  [PASS] Explainable AI generated grounded, deterministic explanation.")
    passed += 1

    # TEST 7: Report Generation (Section 31 Format)
    total += 1
    print("\n[Test 7] Report Generator (Section 31 Output Format)...")
    text_rep = generate_text_report(
        email_data=parsed_text,
        ml_result=ml_res_phish,
        url_result=urls_res,
        feature_result=features,
        risk_result=risk_res_phish,
        llm_result=llm_res
    )
    assert "EMAIL SECURITY REPORT" in text_rep
    assert "PHISHING" in text_rep
    assert "RECOMMENDATION" in text_rep
    print("  [PASS] Section 31 report format generated correctly.")
    passed += 1

    # TEST 8: SQLite Database Operations
    total += 1
    print("\n[Test 8] SQLite Database (Save, Query, Telemetry)...")
    rec_id = save_analysis(
        sender=parsed_text["sender"],
        subject=parsed_text["subject"],
        prediction=risk_res_phish["classification"],
        risk_score=risk_res_phish["risk_score"],
        risk_level=risk_res_phish["risk_level"],
        model_confidence=ml_res_phish["confidence"],
        detected_risks=risk_res_phish["detected_risks"],
        urls_count=urls_res["total_urls"],
        suspicious_urls_count=urls_res["suspicious_count"],
        input_type="Pasted"
    )
    assert rec_id > 0, "Failed to insert record into SQLite"
    rec = get_analysis_by_id(rec_id)
    assert rec is not None, "Failed to retrieve record by ID"
    assert rec["sender"] == parsed_text["sender"], "Record sender mismatch"
    
    stats = get_dashboard_stats()
    assert stats["total_analyzed"] >= 1, "Dashboard stats failed"
    print(f"  -> Inserted Record ID: {rec_id}")
    print(f"  -> Total Analyzed in DB: {stats['total_analyzed']}")
    print(f"  -> Phishing Count: {stats['phishing_detected']}")
    print("  [PASS] Database module verified.")
    passed += 1

    print("\n" + "=" * 60)
    print(f"[ALL TESTS PASSED] {passed}/{total} stages verified successfully!")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
