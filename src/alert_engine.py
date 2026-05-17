# src/alert_engine.py

"""
alert_engine.py

Production-Grade Merchant Risk Alert Engine V3

Built from:
- Your strong V2 alert workflow
- Cleaner integration with database.py
- JSON-safe findings support
- Better priority routing
- Reduced duplicate DB logic
- Stronger fraud override handling
- Trusted merchant suppression protection

Core Principle:

Scorer decides risk.
Alert engine decides operational action.

Bad alert logic causes:
- good merchants blocked
- fraud merchants missed
- compliance queue overload
- analyst inefficiency
"""

from datetime import datetime
from pprint import pprint

from database import save_alert


# =========================================================
# CONFIGURATION
# =========================================================

FORCE_BLOCK_SIGNALS = [
    "very_new_domain",
    "crypto_payment_detected",
    "critical_fraud_pattern",
    "fake_identity_pattern",
    "high_risk_tld",
    "missing_business_email",
    "missing_physical_address"
]

SAFE_MERCHANT_SIGNALS = [
    "enterprise_trust_signal",
    "old_domain_trust"
]


# =========================================================
# HELPERS
# =========================================================

def normalize_findings(findings):
    """
    Supports both:

    [
        "Very new domain"
    ]

    and

    [
        {
            "signal": "very_new_domain",
            "finding": "...",
            "severity": "CRITICAL"
        }
    ]
    """

    normalized = []

    if not findings:
        return normalized

    for item in findings:
        if isinstance(item, dict):
            normalized.append({
                "signal": item.get("signal", ""),
                "finding": item.get(
                    "finding",
                    "Unknown finding"
                )
            })
        else:
            normalized.append({
                "signal": "",
                "finding": str(item)
            })

    return normalized


def has_force_block_signals(findings):
    findings = normalize_findings(findings)

    detected = {
        item.get("signal", "")
        for item in findings
    }

    return len(
        set(FORCE_BLOCK_SIGNALS).intersection(
            detected
        )
    ) >= 1


def has_safe_merchant_signals(findings):
    findings = normalize_findings(findings)

    detected = {
        item.get("signal", "")
        for item in findings
    }

    return len(
        set(SAFE_MERCHANT_SIGNALS).intersection(
            detected
        )
    ) >= 1


def extract_triggered_findings(findings):
    """
    Clean readable findings for dashboard/reporting
    """

    findings = normalize_findings(findings)

    output = []

    for item in findings:
        output.append(
            item.get(
                "finding",
                "Unknown finding"
            )
        )

    return output


# =========================================================
# PRIORITY MATRIX
# =========================================================

def get_alert_priority(
    risk_score,
    risk_rating,
    verification_status,
    findings
):
    """
    True underwriting escalation matrix
    """

    risk_rating = str(risk_rating).upper()
    verification_status = str(
        verification_status
    ).upper()

    force_block = has_force_block_signals(
        findings
    )

    safe_merchant = has_safe_merchant_signals(
        findings
    )

    # =====================================================
    # P1 — Immediate Block
    # =====================================================

    if (
        risk_rating == "CRITICAL"
        or (
            force_block
            and verification_status == "LOW TRUST"
        )
    ):
        return {
            "priority": "P1",
            "action":
                "Immediate Merchant Block Recommendation",
            "queue":
                "Critical Compliance Review Queue"
        }

    # =====================================================
    # P2 — High Risk Compliance Review
    # =====================================================

    if (
        risk_rating == "HIGH"
        and verification_status in [
            "LOW TRUST",
            "MODERATE TRUST"
        ]
    ):
        return {
            "priority": "P2",
            "action":
                "Immediate Compliance Investigation Required",
            "queue":
                "High Risk Compliance Queue"
        }

    # =====================================================
    # P3 — Enhanced Due Diligence
    # =====================================================

    if (
        risk_rating == "MEDIUM"
        and verification_status == "LOW TRUST"
    ):
        return {
            "priority": "P3",
            "action":
                "Enhanced Due Diligence Required",
            "queue":
                "EDD Review Queue"
        }

    # =====================================================
    # Safe Merchant Protection
    # =====================================================

    if (
        safe_merchant
        and verification_status in [
            "HIGH TRUST",
            "MODERATE TRUST"
        ]
        and risk_score <= 35
    ):
        return {
            "priority": "P4",
            "action":
                "Standard Onboarding",
            "queue":
                "Normal Merchant Queue"
        }

    # =====================================================
    # Default Standard Review
    # =====================================================

    return {
        "priority": "P4",
        "action":
            "Proceed with Standard Monitoring",
        "queue":
            "Normal Merchant Queue"
    }


# =========================================================
# PAYLOAD BUILDER
# =========================================================

def build_alert_payload(
    merchant_url,
    risk_score,
    risk_rating,
    recommended_action,
    verification_result,
    findings
):
    verification_score = verification_result.get(
        "verification_score",
        0
    )

    verification_status = verification_result.get(
        "verification_status",
        "UNKNOWN"
    )

    escalation = get_alert_priority(
        risk_score=risk_score,
        risk_rating=risk_rating,
        verification_status=verification_status,
        findings=findings
    )

    payload = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "merchant_url": merchant_url,

        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "recommended_action": recommended_action,

        "verification_score": verification_score,
        "verification_status": verification_status,

        "priority": escalation["priority"],
        "compliance_queue": escalation["queue"],
        "operational_action": escalation["action"],

        "triggered_findings":
            extract_triggered_findings(findings)
    }

    return payload


# =========================================================
# CHANNEL PLACEHOLDERS
# =========================================================

def send_email_alert(payload):
    print("\n[EMAIL ALERT]")
    print(
        f"Merchant: {payload['merchant_url']}"
    )
    print(
        f"Priority: {payload['priority']}"
    )


def send_slack_alert(payload):
    print("\n[SLACK ALERT]")
    print(
        f"Risk Rating: {payload['risk_rating']}"
    )
    print(
        f"Queue: {payload['compliance_queue']}"
    )


def send_telegram_alert(payload):
    print("\n[TELEGRAM ALERT]")
    print(
        f"Action: "
        f"{payload['operational_action']}"
    )


# =========================================================
# MAIN ENGINE
# =========================================================

def trigger_alerts(
    merchant_url,
    risk_score,
    risk_rating,
    recommended_action,
    verification_result,
    findings
):
    """
    Full operational escalation engine
    """

    payload = build_alert_payload(
        merchant_url=merchant_url,
        risk_score=risk_score,
        risk_rating=risk_rating,
        recommended_action=recommended_action,
        verification_result=verification_result,
        findings=findings
    )

    # Single source of truth → database.py
    save_alert(payload)

    priority = payload["priority"]

    if priority in ["P1", "P2", "P3"]:

        print("\n" + "=" * 60)
        print("ALERT ENGINE ACTIVATED")
        print("=" * 60)

        pprint(payload)

        if priority in ["P1", "P2"]:
            send_email_alert(payload)
            send_slack_alert(payload)
            send_telegram_alert(payload)

        print(
            "\nMerchant moved to compliance workflow."
        )
        print("=" * 60)

    else:
        print(
            "\nNo alert required for standard onboarding merchant."
        )

    return payload


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    sample_findings = [
        {
            "signal": "very_new_domain",
            "finding": "Very new domain detected",
            "severity": "CRITICAL"
        },
        {
            "signal": "crypto_payment_detected",
            "finding": "Crypto payment detected",
            "severity": "CRITICAL"
        },
        {
            "signal": "missing_business_email",
            "finding": "No business email found",
            "severity": "HIGH"
        }
    ]

    sample_verification_result = {
        "verification_score": 35,
        "verification_status": "LOW TRUST"
    }

    result = trigger_alerts(
        merchant_url="https://high-risk-merchant.com",
        risk_score=88,
        risk_rating="HIGH",
        recommended_action=(
            "Immediate Compliance Investigation Required"
        ),
        verification_result=sample_verification_result,
        findings=sample_findings
    )

    print("\nFinal Alert Payload:")
    pprint(result)

