"""
combination_engine.py

V2 — Stronger fraud combination detection

Purpose:
Fraud is rarely identified by one signal alone.
This engine detects dangerous combinations of signals
that should trigger stronger escalation.

Used by:
- scorer_v5.py

Rule:
Single finding = warning
Multiple connected findings = underwriting risk
"""


def detect_risk_combinations(findings):
    """
    Expected findings format:

    [
        {
            "signal": "very_new_domain",
            "finding": "Very new domain detected",
            "severity": "CRITICAL"
        }
    ]
    """

    detected_signals = set()

    # --------------------------------------------
    # Extract unique signal IDs
    # --------------------------------------------
    for item in findings:
        signal = item.get("signal")

        if signal:
            detected_signals.add(signal)

    combination_alerts = []

    # =================================================
    # COMBINATION 1
    # Very new domain + crypto + no business email
    # = Critical fraud onboarding pattern
    # =================================================

    if {
        "very_new_domain",
        "crypto_payment_detected",
        "missing_business_email"
    }.issubset(detected_signals):

        combination_alerts.append({
            "signal": "critical_fraud_pattern",
            "severity": "CRITICAL",
            "score": 30,
            "reason": (
                "Very new domain + crypto payment + "
                "missing business email detected"
            )
        })

    # =================================================
    # COMBINATION 2
    # New domain + no contact details
    # = High onboarding risk
    # =================================================

    if {
        "new_domain",
        "missing_contact_details"
    }.issubset(detected_signals):

        combination_alerts.append({
            "signal": "high_onboarding_risk",
            "severity": "HIGH",
            "score": 18,
            "reason": (
                "New domain + missing contact details detected"
            )
        })

    # =================================================
    # COMBINATION 3
    # UPI only + no about page
    # = Suspicious low trust merchant
    # =================================================

    if {
        "upi_only_payment",
        "no_about_page"
    }.issubset(detected_signals):

        combination_alerts.append({
            "signal": "suspicious_low_trust_pattern",
            "severity": "HIGH",
            "score": 15,
            "reason": (
                "UPI-only payment + no About page detected"
            )
        })

    # =================================================
    # COMBINATION 4
    # No HTTPS + suspicious payment
    # = Strong payment fraud signal
    # =================================================

    if {
        "no_https_security",
        "crypto_payment_detected"
    }.issubset(detected_signals):

        combination_alerts.append({
            "signal": "payment_fraud_pattern",
            "severity": "CRITICAL",
            "score": 25,
            "reason": (
                "No HTTPS security + suspicious payment detected"
            )
        })

    # =================================================
    # COMBINATION 5
    # No business email + no physical address
    # = Fake identity risk
    # =================================================

    if {
        "missing_business_email",
        "missing_physical_address"
    }.issubset(detected_signals):

        combination_alerts.append({
            "signal": "fake_identity_pattern",
            "severity": "HIGH",
            "score": 20,
            "reason": (
                "Missing business email + missing physical address detected"
            )
        })

    return combination_alerts