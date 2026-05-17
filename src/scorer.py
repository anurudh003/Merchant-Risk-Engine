"""
scorer.py

Production-grade Merchant Risk Scoring Engine V7

Built for:
- AML / Compliance underwriting
- False positive reduction
- Enterprise trust suppression
- Fraud escalation logic
- Merchant category-aware decisions
- Queue routing intelligence

Design Principle:

rules.py -> DETECT findings
scorer.py -> DECIDE final business outcome

This version fixes:
- Microsoft falsely becoming HIGH risk
- weak findings forcing escalation
- lack of trust suppression
- poor fraud escalation control
"""

from pprint import pprint

from signals_registry import SIGNALS
from combination_engine import detect_risk_combinations


# =========================================================
# CONFIGURATION
# =========================================================

SEVERITY_WEIGHTS = {
    "LOW": 3,
    "MEDIUM": 8,
    "HIGH": 18,
    "CRITICAL": 35
}

# Safe enterprise ceiling
TRUST_CEILING_SCORE = 20

# Hard fraud floor
FRAUD_FLOOR_SCORE = 80

# Unknown merchants should not auto-pass
NEUTRAL_REVIEW_FLOOR = 25


# =========================================================
# COMPLIANCE MAPPINGS
# =========================================================

HIGH_RISK_SIGNALS = {
    "crypto_payment_detected",
    "crypto_payment",
    "very_new_domain",
    "new_domain",
    "high_risk_tld",
    "missing_business_email",
    "weak_contact_identity",
    "high_risk_industry",
    "upi_only_payment",
    "upi_only"
}

TRUST_SIGNALS = {
    "enterprise_trust_signal",
    "enterprise_trust_verified",
    "old_domain_trust"
}

BLOCK_SIGNALS = {
    "crypto_payment_detected",
    "crypto_payment",
    "very_new_domain"
}


# =========================================================
# HELPERS
# =========================================================

def normalize_confidence(confidence):
    if confidence is None:
        return 0.50

    try:
        confidence = float(confidence)
    except Exception:
        return 0.50

    if confidence < 0:
        return 0.50

    if confidence > 1:
        return 1.0

    return confidence


def get_signal_score(signal_name):
    if signal_name in SIGNALS:
        return SIGNALS[signal_name]["score"]
    return 0


def merchant_category_classifier(detected_signals):
    """
    Simple merchant category routing.
    Can be upgraded later with ML/LLM.
    """

    if "crypto_payment_detected" in detected_signals \
            or "crypto_payment" in detected_signals:
        return "CRYPTO"

    if "high_risk_industry" in detected_signals:
        return "HIGH_RISK_INDUSTRY"

    if "enterprise_trust_signal" in detected_signals \
            or "enterprise_trust_verified" in detected_signals:
        return "ENTERPRISE"

    return "STANDARD"


def queue_router(risk_rating, merchant_category):
    """
    Compliance workflow routing
    """

    if risk_rating == "CRITICAL":
        return "Immediate Fraud Block Queue"

    if merchant_category == "CRYPTO":
        return "AML Enhanced Due Diligence Queue"

    if merchant_category == "HIGH_RISK_INDUSTRY":
        return "High Risk Compliance Queue"

    if risk_rating == "HIGH":
        return "Compliance Investigation Queue"

    if risk_rating == "MEDIUM":
        return "Manual Compliance Review Queue"

    return "Standard Monitoring Queue"


def priority_mapper(risk_rating):
    if risk_rating == "CRITICAL":
        return "P1"

    if risk_rating == "HIGH":
        return "P2"

    if risk_rating == "MEDIUM":
        return "P3"

    return "P4"


# =========================================================
# MAIN ENGINE
# =========================================================

def calculate_risk_score(findings):
    """
    Input format:

    findings = [
        {
            "signal": "missing_business_email",
            "finding": "No business email found",
            "severity": "HIGH",
            "confidence": 0.90
        }
    ]
    """

    # =====================================================
    # SAFE DEFAULT
    # =====================================================

    if not findings:
        return {
            "risk_score": 25,
            "risk_rating": "MEDIUM",
            "recommended_action": "Manual Compliance Review Required",
            "priority": "P3",
            "compliance_queue": "Manual Compliance Review Queue",
            "top_risk_drivers": [],
            "combination_alerts": [],
            "merchant_category": "STANDARD"
        }

    total_score = 0
    top_risk_drivers = []
    detected_signals = set()

    critical_count = 0
    high_count = 0
    trust_signal_count = 0

    # =====================================================
    # STEP 1 — SCORE INDIVIDUAL FINDINGS
    # =====================================================

    for item in findings:
        signal = item.get("signal")
        finding = item.get("finding", "Unknown finding")

        severity = str(
            item.get("severity", "LOW")
        ).upper()

        confidence = normalize_confidence(
            item.get("confidence", 0.50)
        )

        if not signal:
            continue

        if signal in detected_signals:
            continue

        detected_signals.add(signal)

        registry_score = get_signal_score(signal)

        if registry_score != 0:
            base_weight = abs(registry_score)
        else:
            base_weight = SEVERITY_WEIGHTS.get(
                severity,
                SEVERITY_WEIGHTS["LOW"]
            )

        impact_score = round(
            base_weight * confidence
        )

        # ----------------------------------------------
        # TRUST REDUCTION
        # ----------------------------------------------

        if registry_score < 0 or signal in TRUST_SIGNALS:
            reduction_score = max(8, impact_score)

            total_score -= reduction_score
            trust_signal_count += 1

            top_risk_drivers.append({
                "finding": finding,
                "signal": signal,
                "severity": "TRUST_REDUCTION",
                "confidence": round(confidence, 2),
                "impact_score": -reduction_score
            })

            continue

        # ----------------------------------------------
        # NORMAL RISK ADDITION
        # ----------------------------------------------

        if severity == "CRITICAL":
            critical_count += 1

        if severity == "HIGH":
            high_count += 1

        total_score += impact_score

        top_risk_drivers.append({
            "finding": finding,
            "signal": signal,
            "severity": severity,
            "confidence": round(confidence, 2),
            "impact_score": impact_score
        })

    # =====================================================
    # STEP 2 — COMBINATION ENGINE
    # =====================================================

    combination_alerts = detect_risk_combinations(findings)

    for combo in combination_alerts:
        combo_score = combo.get("score", 0)

        # combinations should dominate
        total_score += combo_score

        top_risk_drivers.append({
            "finding": combo.get("reason"),
            "signal": combo.get("signal"),
            "severity": combo.get("severity"),
            "confidence": 1.0,
            "impact_score": combo_score
        })

    # =====================================================
    # STEP 3 — HARD FRAUD PATTERN DETECTION
    # =====================================================

    forced_rating = None

    fraud_pattern = {
        "crypto_payment_detected",
        "crypto_payment",
        "very_new_domain",
        "missing_business_email"
    }

    if len(fraud_pattern.intersection(detected_signals)) >= 2:
        total_score = max(
            total_score,
            FRAUD_FLOOR_SCORE
        )
        forced_rating = "CRITICAL"

    # =====================================================
    # STEP 4 — FALSE POSITIVE SUPPRESSION
    # =====================================================

    trusted_merchant = len(
        TRUST_SIGNALS.intersection(detected_signals)
    ) >= 1

    weak_negative_only = (
        trusted_merchant
        and critical_count == 0
        and "high_risk_industry" not in detected_signals
        and "crypto_payment_detected" not in detected_signals
        and "crypto_payment" not in detected_signals
    )

    if weak_negative_only:
        total_score = min(
            total_score,
            TRUST_CEILING_SCORE
        )
        forced_rating = "LOW"

    # =====================================================
    # STEP 5 — NEUTRAL REVIEW FLOOR
    # =====================================================

    if (
        not trusted_merchant
        and total_score < NEUTRAL_REVIEW_FLOOR
        and forced_rating is None
    ):
        total_score = NEUTRAL_REVIEW_FLOOR

    # =====================================================
    # STEP 6 — FINAL RISK SCORE
    # =====================================================

    risk_score = min(
        max(total_score, 0),
        100
    )

    # =====================================================
    # STEP 7 — FINAL CLASSIFICATION
    # =====================================================

    if forced_rating == "CRITICAL":
        risk_rating = "CRITICAL"
        recommended_action = \
            "Block Merchant and Escalate Immediately"

    elif forced_rating == "LOW":
        risk_rating = "LOW"
        recommended_action = \
            "Proceed with Standard Monitoring"

    else:
        if risk_score >= 75:
            risk_rating = "CRITICAL"
            recommended_action = \
                "Block Merchant and Escalate Immediately"

        elif risk_score >= 50:
            risk_rating = "HIGH"
            recommended_action = \
                "Immediate Compliance Investigation Required"

        elif risk_score >= 25:
            risk_rating = "MEDIUM"
            recommended_action = \
                "Manual Compliance Review Required"

        else:
            risk_rating = "LOW"
            recommended_action = \
                "Proceed with Standard Monitoring"

    # =====================================================
    # STEP 8 — CATEGORY + QUEUE + PRIORITY
    # =====================================================

    merchant_category = merchant_category_classifier(
        detected_signals
    )

    compliance_queue = queue_router(
        risk_rating,
        merchant_category
    )

    priority = priority_mapper(
        risk_rating
    )

    # =====================================================
    # STEP 9 — SORT TOP DRIVERS
    # =====================================================

    top_risk_drivers = sorted(
        top_risk_drivers,
        key=lambda x: abs(
            x["impact_score"]
        ),
        reverse=True
    )

    return {
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "recommended_action": recommended_action,
        "priority": priority,
        "compliance_queue": compliance_queue,
        "merchant_category": merchant_category,
        "top_risk_drivers": top_risk_drivers[:7],
        "combination_alerts": combination_alerts,
        "detected_signals": list(detected_signals)
    }


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    sample_findings = [
        {
            "signal": "new_domain",
            "finding": "New domain detected",
            "severity": "HIGH",
            "confidence": 0.85
        },
        {
            "signal": "missing_business_email",
            "finding": "No business email found",
            "severity": "MEDIUM",
            "confidence": 0.80
        }
    ]

    result = calculate_risk_score(
        sample_findings
    )

    print("\n========== SCORER V7 TEST ==========\n")
    pprint(result)