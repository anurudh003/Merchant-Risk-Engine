"""
signals_registry.py

Single source of truth for all merchant risk signals.
Avoid duplicate scoring across verifier, detector, rules, scorer.
"""

SIGNALS = {
    # Identity Risks
    "missing_business_email": {
        "severity": "HIGH",
        "score": 12,
        "category": "identity"
    },

    "missing_contact_details": {
        "severity": "MEDIUM",
        "score": 8,
        "category": "identity"
    },

    "no_about_page": {
        "severity": "MEDIUM",
        "score": 6,
        "category": "identity"
    },

    # Payment Risks
    "crypto_payment_detected": {
        "severity": "CRITICAL",
        "score": 25,
        "category": "payment"
    },

    "upi_only_payment": {
        "severity": "HIGH",
        "score": 15,
        "category": "payment"
    },

    # Domain Risks
    "new_domain": {
        "severity": "HIGH",
        "score": 18,
        "category": "domain"
    },

    "very_new_domain": {
        "severity": "CRITICAL",
        "score": 25,
        "category": "domain"
    },

    # Trust Signals (negative score = bonus)
    "enterprise_trust_signal": {
        "severity": "SAFE",
        "score": -20,
        "category": "trust"
    },

    "old_domain_trust": {
        "severity": "SAFE",
        "score": -10,
        "category": "trust"
    }
}