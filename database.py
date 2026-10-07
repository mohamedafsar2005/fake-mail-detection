"""
Database Module for MailGuard AI
Maintains analysis history using SQLite.
Stores audit metadata (timestamp, sender, subject, prediction, risk score, confidence)
without storing full sensitive email bodies by default.
"""

import os
import sqlite3
import datetime
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "mailguard_history.db")

def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Returns a SQLite connection configured with Row factory."""
    path = db_path or DEFAULT_DB_PATH
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Optional[str] = None):
    """Initializes the SQLite schema."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    sender TEXT,
                    subject TEXT,
                    prediction TEXT NOT NULL,
                    risk_score REAL NOT NULL,
                    risk_level TEXT NOT NULL,
                    model_confidence REAL NOT NULL,
                    detected_risks_json TEXT,
                    urls_count INTEGER DEFAULT 0,
                    suspicious_urls_count INTEGER DEFAULT 0,
                    input_type TEXT DEFAULT 'Pasted'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scan_history(timestamp DESC)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prediction ON scan_history(prediction)")
    finally:
        conn.close()

def save_analysis(
    sender: str,
    subject: str,
    prediction: str,
    risk_score: float,
    risk_level: str,
    model_confidence: float,
    detected_risks: List[str] = None,
    urls_count: int = 0,
    suspicious_urls_count: int = 0,
    input_type: str = "Pasted",
    db_path: Optional[str] = None
) -> int:
    """Saves a single email evaluation record to SQLite."""
    import json
    init_db(db_path)
    conn = get_connection(db_path)
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risks_json = json.dumps(detected_risks or [])

    try:
        with conn:
            cursor = conn.execute("""
                INSERT INTO scan_history (
                    timestamp, sender, subject, prediction,
                    risk_score, risk_level, model_confidence,
                    detected_risks_json, urls_count, suspicious_urls_count,
                    input_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now_str,
                (sender or "Unknown")[:255],
                (subject or "(No Subject)")[:255],
                prediction,
                float(risk_score),
                risk_level,
                float(model_confidence),
                risks_json,
                int(urls_count),
                int(suspicious_urls_count),
                input_type
            ))
            return cursor.lastrowid
    finally:
        conn.close()

def get_history(
    search_query: Optional[str] = None,
    filter_prediction: Optional[str] = None,
    filter_risk_level: Optional[str] = None,
    limit: int = 100,
    db_path: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Fetches scan history with optional search and filtering."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        query = "SELECT * FROM scan_history WHERE 1=1"
        params = []

        if search_query and search_query.strip():
            sq = f"%{search_query.strip()}%"
            query += " AND (subject LIKE ? OR sender LIKE ?)"
            params.extend([sq, sq])

        if filter_prediction and filter_prediction != "ALL":
            query += " AND prediction = ?"
            params.append(filter_prediction)

        if filter_risk_level and filter_risk_level != "ALL":
            query += " AND risk_level = ?"
            params.append(filter_risk_level)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(query, params)
        rows = cursor.fetchall()
        import json
        results = []
        for r in rows:
            d = dict(r)
            try:
                d["detected_risks"] = json.loads(d.get("detected_risks_json") or "[]")
            except Exception:
                d["detected_risks"] = []
            results.append(d)
        return results
    finally:
        conn.close()

def get_analysis_by_id(record_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Retrieves a single record by its primary key ID."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("SELECT * FROM scan_history WHERE id = ?", (record_id,))
        row = cursor.fetchone()
        if not row:
            return None
        import json
        d = dict(row)
        try:
            d["detected_risks"] = json.loads(d.get("detected_risks_json") or "[]")
        except Exception:
            d["detected_risks"] = []
        return d
    finally:
        conn.close()

def get_dashboard_stats(db_path: Optional[str] = None) -> Dict[str, Any]:
    """Calculates summary statistics for the executive dashboard."""
    init_db(db_path)
    conn = get_connection(db_path)
    try:
        cursor = conn.execute("""
            SELECT 
                COUNT(*) as total_count,
                SUM(CASE WHEN prediction LIKE '%PHISHING%' THEN 1 ELSE 0 END) as phishing_count,
                SUM(CASE WHEN prediction LIKE '%LEGITIMATE%' OR prediction LIKE '%SAFE%' THEN 1 ELSE 0 END) as safe_count,
                SUM(CASE WHEN risk_level IN ('HIGH', 'CRITICAL') THEN 1 ELSE 0 END) as high_risk_count,
                AVG(risk_score) as avg_score
            FROM scan_history
        """)
        row = cursor.fetchone()
        total = row["total_count"] or 0
        phishing = row["phishing_count"] or 0
        safe = row["safe_count"] or 0
        high_risk = row["high_risk_count"] or 0
        avg_score = round(float(row["avg_score"] or 0.0), 1)

        # Risk distribution breakdown
        cur_dist = conn.execute("""
            SELECT risk_level, COUNT(*) as cnt 
            FROM scan_history 
            GROUP BY risk_level
        """)
        dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for r in cur_dist.fetchall():
            if r["risk_level"] in dist:
                dist[r["risk_level"]] = r["cnt"]

        # Recent 5 entries
        recent = get_history(limit=5, db_path=db_path)

        return {
            "total_analyzed": total,
            "phishing_detected": phishing,
            "safe_emails": safe,
            "high_risk_emails": high_risk,
            "avg_risk_score": avg_score,
            "risk_distribution": dist,
            "recent_scans": recent
        }
    finally:
        conn.close()

def delete_analysis(record_id: int, db_path: Optional[str] = None):
    """Deletes an analysis entry by ID."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM scan_history WHERE id = ?", (record_id,))
    finally:
        conn.close()

def clear_history(db_path: Optional[str] = None):
    """Purges all stored analysis records."""
    conn = get_connection(db_path)
    try:
        with conn:
            conn.execute("DELETE FROM scan_history")
    finally:
        conn.close()
