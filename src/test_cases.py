"""
test_cases.py

Merchant Risk Engine Calibration Test Suite

Purpose:
Validate that:
- trusted merchants stay LOW risk
- suspicious merchants become HIGH / CRITICAL
- edge cases behave correctly
- false positives are reduced

This helps production calibration before deployment.
"""

from pprint import pprint

from rules import detect_risk_findings
from scorer import calculate_risk_score
from trusted_merchant_detector import detect_trusted_merchant


# =========================================================
# TEST CASES
# =========================================================

TEST_CASES = [

    # =====================================================
    # CASE 1 — Trusted Enterprise Merchant
    # Expected: LOW
    # =====================================================

    {
        "name": "Microsoft - Trusted Enterprise",
        "expected_risk": "LOW",
        "merchant_data": {
            "url": "https://www.microsoft.com/",
            "email": "support@microsoft.com",
            "phone": "+1-800-642-7676",
            "address": "Redmond, Washington, USA",
            "about_page": True,
            "payment_text": "Visa Mastercard PayPal",
            "page_text": """
                Microsoft Corporation
                Investor Relations
                Careers
                Enterprise Solutions
                Privacy Policy
                Terms and Conditions
                Press Release
                Corporate Office
            """,
            "domain_age_days": 12000
        }
    },

    # =====================================================
    # CASE 2 — Crypto Scam Merchant
    # Expected: CRITICAL
    # =====================================================

    {
        "name": "Crypto Scam Merchant",
        "expected_risk": "CRITICAL",
        "merchant_data": {
            "url": "https://fastcryptoprofit.online/",
            "email": "",
            "phone": "",
            "address": "",
            "about_page": False,
            "payment_text": "Send BTC / USDT to wallet address",
            "page_text": """
                Fast crypto returns
                instant withdrawals
                wallet payment only
            """,
            "domain_age_days": 8
        }
    },

    # =====================================================
    # CASE 3 — Mid-size Normal Merchant
    # Expected: MEDIUM
    # =====================================================

    {
        "name": "Normal Business Merchant",
        "expected_risk": "MEDIUM",
        "merchant_data": {
            "url": "https://example-consulting.com/",
            "email": "info@example-consulting.com",
            "phone": "+91-9876543210",
            "address": "Bangalore, India",
            "about_page": True,
            "payment_text": "Bank transfer and invoice payments",
            "page_text": """
                Consulting services
                business operations
                customer support
            """,
            "domain_age_days": 250
        }
    },

    # =====================================================
    # CASE 4 — Trusted SaaS Merchant
    # Expected: LOW
    # =====================================================

    {
        "name": "Zoho - Trusted SaaS",
        "expected_risk": "LOW",
        "merchant_data": {
            "url": "https://www.zoho.com/",
            "email": "support@zoho.com",
            "phone": "+1-888-900-9646",
            "address": "Chennai, India",
            "about_page": True,
            "payment_text": "Visa Mastercard Stripe",
            "page_text": """
                Zoho Corporation
                Investor Relations
                Enterprise Business Software
                Privacy Policy
                Careers
                Press Release
            """,
            "domain_age_days": 7000
        }
    },

    # =====================================================
    # CASE 5 — Suspicious Shell Merchant
    # Expected: HIGH / CRITICAL
    # =====================================================

    {
        "name": "Suspicious Shell Merchant",
        "expected_risk": "HIGH_OR_CRITICAL",
        "merchant_data": {
            "url": "https://globaltrade-support.xyz/",
            "email": "globaltrade@gmail.com",
            "phone": "",
            "address": "",
            "about_page": False,
            "payment_text": "UPI only accepted",
            "page_text": """
                instant approval
                fast processing
                whatsapp onboarding
            """,
            "domain_age_days": 20
        }
    }
]


# =========================================================
# HELPERS
# =========================================================

def inject_trust_signal(findings, trust_result):
    """
    Add trust signal before scoring
    """

    if trust_result.get("enterprise_trust_signal"):
        findings.append({
            "signal": "enterprise_trust_signal",
            "finding": "Trusted enterprise merchant verified",
            "severity": "LOW",
            "confidence": 0.95
        })

    return findings


def is_test_passed(expected, actual):
    """
    Flexible pass validation
    """

    if expected == "HIGH_OR_CRITICAL":
        return actual in ["HIGH", "CRITICAL"]

    return expected == actual


# =========================================================
# MAIN TEST RUNNER
# =========================================================

def run_tests():
    print("\n" + "=" * 80)
    print("MERCHANT RISK ENGINE CALIBRATION TESTS")
    print("=" * 80)

    passed = 0
    failed = 0

    for case in TEST_CASES:
        print("\n" + "-" * 80)
        print(f"TEST: {case['name']}")
        print("-" * 80)

        merchant_data = case["merchant_data"]
        expected = case["expected_risk"]

        # Step 1 — Trust Detection
        trust_result = detect_trusted_merchant(
            merchant_data
        )

        # Step 2 — Rule Detection
        findings = detect_risk_findings(
            merchant_data
        )

        # Step 3 — Inject Trust Signal
        findings = inject_trust_signal(
            findings,
            trust_result
        )

        # Step 4 — Final Scoring
        final_result = calculate_risk_score(
            findings
        )

        actual = final_result.get("risk_rating")

        print(f"Expected Risk: {expected}")
        print(f"Actual Risk:   {actual}")
        print(
            f"Risk Score:    "
            f"{final_result.get('risk_score')}"
        )
        print(
            f"Trust Score:   "
            f"{trust_result.get('trust_score')}"
        )

        if is_test_passed(expected, actual):
            print("RESULT: PASS")
            passed += 1
        else:
            print("RESULT: FAIL")
            failed += 1

        print("\nTop Risk Drivers:")
        pprint(final_result.get("top_risk_drivers", []))

    print("\n" + "=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)
    print(f"PASSED: {passed}")
    print(f"FAILED: {failed}")
    print(f"TOTAL : {len(TEST_CASES)}")
    print("=" * 80)


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":
    run_tests()