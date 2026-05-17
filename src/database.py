# src/database.py

"""
database.py

Production-Grade Merchant Risk Database Layer V3

Upgraded from V2:
- JSON-safe findings storage
- Better transaction safety
- Rollback protection
- Performance indexes
- Faster merchant lookup
- Safer alert persistence
- Cleaner production behavior

Core Principle:

A strong merchant-risk system is database-first.

This module supports:

1. Merchant assessment history
2. Real-time compliance alerts
3. Analyst audit trail
4. Merchant repeat intelligence
5. Streamlit dashboard support
6. Production-safe persistence
"""

import sqlite3
import json
from datetime import datetime
from pprint import pprint


# =========================================================
# CONFIGURATION
# =========================================================

DATABASE_NAME = "merchant_risk.db"


# =========================================================
# CONNECTION
# =========================================================

def get_connection():
    """
    Safe SQLite connection
    """
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def safe_json_dump(data):
    """
    Safe JSON conversion for findings / payloads
    """
    try:
        return json.dumps(data, default=str)
    except Exception:
        return json.dumps([])


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():
    """
    Create production-grade tables + indexes
    """

    conn = get_connection()
    cursor = conn.cursor()

    try:
        # =================================================
        # TABLE 1 — Merchant Assessments
        # =================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merchant_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                merchant_url TEXT NOT NULL,

                risk_score INTEGER,
                risk_rating TEXT,
                recommended_action TEXT,

                verification_score INTEGER,
                verification_status TEXT,

                priority TEXT,
                compliance_queue TEXT,
                operational_action TEXT,

                findings_json TEXT,

                review_status TEXT DEFAULT 'PENDING',

                created_at TEXT,
                updated_at TEXT
            )
        """)

        # =================================================
        # TABLE 2 — Alerts
        # =================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                merchant_url TEXT NOT NULL,

                risk_score INTEGER,
                risk_rating TEXT,

                verification_score INTEGER,
                verification_status TEXT,

                priority TEXT,
                compliance_queue TEXT,

                recommended_action TEXT,
                operational_action TEXT,

                triggered_findings_json TEXT,

                is_resolved INTEGER DEFAULT 0,

                assigned_to TEXT,
                analyst_notes TEXT,

                created_at TEXT,
                resolved_at TEXT
            )
        """)

        # =================================================
        # TABLE 3 — Analyst Actions
        # =================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS analyst_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                merchant_url TEXT NOT NULL,

                action_taken TEXT,
                action_by TEXT,

                previous_status TEXT,
                new_status TEXT,

                action_reason TEXT,

                created_at TEXT
            )
        """)

        # =================================================
        # TABLE 4 — Merchant History
        # =================================================

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS merchant_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,

                merchant_url TEXT NOT NULL UNIQUE,

                first_seen TEXT,
                last_seen TEXT,

                scan_count INTEGER DEFAULT 1,

                previous_risk_rating TEXT,
                current_risk_rating TEXT
            )
        """)

        # =================================================
        # PERFORMANCE INDEXES
        # =================================================

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_assessment_url
            ON merchant_assessments (merchant_url)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_assessment_rating
            ON merchant_assessments (risk_rating)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_resolved
            ON alerts (is_resolved)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_created
            ON alerts (created_at)
        """)

        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_history_url
            ON merchant_history (merchant_url)
        """)

        conn.commit()
        print("Database initialized successfully.")

    except Exception as e:
        conn.rollback()
        print(f"Database initialization failed: {str(e)}")

    finally:
        conn.close()


# =========================================================
# SAVE ASSESSMENT
# =========================================================

def save_assessment(
    merchant_url,
    risk_result,
    verification_result,
    alert_payload,
    findings
):
    """
    Save final merchant assessment safely
    """

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    findings_json = safe_json_dump(findings)

    try:
        cursor.execute("""
            INSERT INTO merchant_assessments (
                merchant_url,

                risk_score,
                risk_rating,
                recommended_action,

                verification_score,
                verification_status,

                priority,
                compliance_queue,
                operational_action,

                findings_json,

                review_status,

                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            merchant_url,

            risk_result.get("risk_score"),
            risk_result.get("risk_rating"),
            risk_result.get("recommended_action"),

            verification_result.get("verification_score"),
            verification_result.get("verification_status"),

            alert_payload.get("priority"),
            alert_payload.get("compliance_queue"),
            alert_payload.get("operational_action"),

            findings_json,

            "PENDING",

            now,
            now
        ))

        conn.commit()

        print(
            f"Assessment saved successfully: {merchant_url}"
        )

    except Exception as e:
        conn.rollback()
        print(
            f"Assessment save failed: {str(e)}"
        )

    finally:
        conn.close()


# =========================================================
# SAVE ALERT
# =========================================================

def save_alert(payload):
    """
    Save real-time alert for dashboard
    """

    conn = get_connection()
    cursor = conn.cursor()

    findings_json = safe_json_dump(
        payload.get("triggered_findings", [])
    )

    try:
        cursor.execute("""
            INSERT INTO alerts (
                merchant_url,

                risk_score,
                risk_rating,

                verification_score,
                verification_status,

                priority,
                compliance_queue,

                recommended_action,
                operational_action,

                triggered_findings_json,

                is_resolved,

                assigned_to,
                analyst_notes,

                created_at,
                resolved_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            payload.get("merchant_url"),

            payload.get("risk_score"),
            payload.get("risk_rating"),

            payload.get("verification_score"),
            payload.get("verification_status"),

            payload.get("priority"),
            payload.get("compliance_queue"),

            payload.get("recommended_action"),
            payload.get("operational_action"),

            findings_json,

            0,
            None,
            None,

            payload.get("timestamp"),
            None
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print(
            f"Alert save failed: {str(e)}"
        )

    finally:
        conn.close()


# =========================================================
# RESOLVE ALERT
# =========================================================

def resolve_alert(
    alert_id,
    analyst_name,
    analyst_notes
):
    """
    Resolve compliance alert
    """

    conn = get_connection()
    cursor = conn.cursor()

    resolved_time = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:
        cursor.execute("""
            UPDATE alerts
            SET
                is_resolved = 1,
                assigned_to = ?,
                analyst_notes = ?,
                resolved_at = ?
            WHERE id = ?
        """, (
            analyst_name,
            analyst_notes,
            resolved_time,
            alert_id
        ))

        conn.commit()

        print(
            f"Alert resolved successfully: {alert_id}"
        )

    except Exception as e:
        conn.rollback()
        print(
            f"Alert resolve failed: {str(e)}"
        )

    finally:
        conn.close()


# =========================================================
# ANALYST AUDIT TRAIL
# =========================================================

def log_analyst_action(
    merchant_url,
    action_taken,
    action_by,
    previous_status,
    new_status,
    action_reason
):
    """
    Save analyst action trail
    """

    conn = get_connection()
    cursor = conn.cursor()

    created_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:
        cursor.execute("""
            INSERT INTO analyst_actions (
                merchant_url,
                action_taken,
                action_by,
                previous_status,
                new_status,
                action_reason,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            merchant_url,
            action_taken,
            action_by,
            previous_status,
            new_status,
            action_reason,
            created_at
        ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print(
            f"Audit trail save failed: {str(e)}"
        )

    finally:
        conn.close()


# =========================================================
# MERCHANT HISTORY
# =========================================================

def update_merchant_history(
    merchant_url,
    current_risk_rating
):
    """
    Track repeat merchant behavior
    """

    conn = get_connection()
    cursor = conn.cursor()

    now = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    try:
        cursor.execute("""
            SELECT *
            FROM merchant_history
            WHERE merchant_url = ?
        """, (merchant_url,))

        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE merchant_history
                SET
                    last_seen = ?,
                    scan_count = scan_count + 1,
                    previous_risk_rating = current_risk_rating,
                    current_risk_rating = ?
                WHERE merchant_url = ?
            """, (
                now,
                current_risk_rating,
                merchant_url
            ))

        else:
            cursor.execute("""
                INSERT INTO merchant_history (
                    merchant_url,
                    first_seen,
                    last_seen,
                    scan_count,
                    previous_risk_rating,
                    current_risk_rating
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                merchant_url,
                now,
                now,
                1,
                None,
                current_risk_rating
            ))

        conn.commit()

    except Exception as e:
        conn.rollback()
        print(
            f"Merchant history update failed: {str(e)}"
        )

    finally:
        conn.close()


# =========================================================
# FETCH FUNCTIONS
# =========================================================

def fetch_live_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM alerts
        WHERE is_resolved = 0
        ORDER BY created_at DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows


def fetch_all_assessments():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM merchant_assessments
        ORDER BY created_at DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return rows


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    print("\n========== DATABASE V3 TEST ==========\n")

    initialize_database()

    sample_payload = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "merchant_url": "https://highriskmerchant.com",
        "risk_score": 88,
        "risk_rating": "HIGH",
        "recommended_action":
            "Immediate Compliance Investigation Required",
        "verification_score": 42,
        "verification_status": "LOW TRUST",
        "priority": "P1",
        "compliance_queue":
            "Critical Compliance Review Queue",
        "operational_action":
            "Immediate Merchant Block Recommendation",
        "triggered_findings": [
            "Very new domain",
            "Crypto payment detected"
        ]
    }

    save_alert(sample_payload)

    alerts = fetch_live_alerts()

    print("\n========== LIVE ALERTS ==========\n")

    for row in alerts:
        pprint(dict(row))