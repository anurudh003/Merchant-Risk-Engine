import sys
import os
# Resolve absolute paths inside the src package
src_dir = os.path.dirname(os.path.abspath(__file__))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from pprint import pprint

from scraper import scrape_website
from verifier import verify_business_legitimacy

from rules import detect_risk_findings
from scorer import calculate_risk_score
from trusted_merchant_detector import detect_trusted_merchant

from ai_analyzer import run_ai_analysis
from alert_engine import trigger_alerts
from report_generator import generate_reports

from database import (
    initialize_database,
    save_assessment,
    update_merchant_history,
    fetch_all_assessments
)

"""
pipeline.py

Production-grade Merchant Risk Intelligence Pipeline V6

UPDATED FIX:
* Live scan support from Streamlit
* Dynamic merchant URL input
* Fixed ai_analyzer integration
* New compliance-grounded AI flow
* No hallucination AI
* Proper findings → scorer → verification → AI architecture
* Trusted merchant safe path preserved
* Cleaner production-grade orchestration

Core Principle:
Rules detect risk
Scorer decides risk
AI explains risk
"""

# =========================================================
# CONFIG
# =========================================================

FORCE_RESCAN = True
AI_TRIGGER_THRESHOLD = 40

# =========================================================
# HELPERS
# =========================================================

def already_scanned(url):
    """
    Prevent duplicate heavy scans
    """
    try:
        previous = fetch_all_assessments()

        for row in previous:
            row_dict = dict(row)

            if row_dict.get("merchant_url") == url:
                return True

        return False

    except Exception as e:
        print(f"Duplicate check warning: {str(e)}")
        return False


def build_safe_ai_result():
    """
    Skip unnecessary AI for verified safe merchants
    """
    return {
        "ai_summary": "AI skipped due to trusted merchant verification",
        "escalation_justified": False,
        "ai_confidence": 1.0,
        "analyst_recommendation": "Proceed with Standard Monitoring"
    }


def inject_trust_signal(findings, trust_result):
    """
    Add enterprise trust signal ONLY if not already present
    Prevent duplicate trust findings
    """
    if not trust_result.get("enterprise_trust_signal"):
        return findings

    existing_signals = {
        item.get("signal")
        for item in findings
    }

    if (
        "enterprise_trust_signal" not in existing_signals
        and "enterprise_trust_verified" not in existing_signals
    ):
        findings.append({
            "signal": "enterprise_trust_signal",
            "finding": "Trusted enterprise merchant verified",
            "severity": "LOW",
            "confidence": 0.95
        })

    return findings


def should_skip_ai(final_result, trust_result):
    """
    AI skipped only for clearly safe trusted merchants
    """
    risk_score = final_result.get("risk_score", 0)
    risk_rating = final_result.get("risk_rating", "")

    trusted = trust_result.get(
        "enterprise_trust_signal",
        False
    )

    if (
        trusted
        and risk_rating == "LOW"
        and risk_score <= AI_TRIGGER_THRESHOLD
    ):
        return True

    return False


def print_final_report(
    url,
    findings,
    trust_result,
    verification_result,
    final_result,
    ai_result,
    alert_payload
):
    """
    Final readable console report
    """
    print("\n" + "=" * 80)
    print("FINAL MERCHANT RISK ASSESSMENT")
    print("=" * 80)

    print(f"\nMerchant URL: {url}")

    print("\n========== TRUST DETECTOR ==========")
    print(
        f"Enterprise Trust Signal: "
        f"{trust_result.get('enterprise_trust_signal')}"
    )
    print(
        f"Trust Score: "
        f"{trust_result.get('trust_score')}"
    )

    print("\n========== VERIFICATION ==========")
    print(
        f"Verification Score: "
        f"{verification_result.get('verification_score')}"
    )
    print(
        f"Verification Status: "
        f"{verification_result.get('verification_status')}"
    )

    print("\n========== FINAL RISK ==========")
    print(
        f"Risk Score: "
        f"{final_result.get('risk_score')}"
    )
    print(
        f"Risk Rating: "
        f"{final_result.get('risk_rating')}"
    )
    print(
        f"Recommended Action: "
        f"{final_result.get('recommended_action')}"
    )

    print("\n========== AI ANALYSIS ==========")
    print(
        f"AI Summary: "
        f"{ai_result.get('ai_summary')}"
    )
    print(
        f"Analyst Recommendation: "
        f"{ai_result.get('analyst_recommendation')}"
    )

    print("\n========== ALERT ENGINE ==========")
    print(
        f"Priority: "
        f"{alert_payload.get('priority')}"
    )
    print(
        f"Queue: "
        f"{alert_payload.get('compliance_queue')}"
    )

    print("\n========== FINDINGS ==========")

    for item in findings:
        print(
            f"- {item.get('finding')} "
            f"({item.get('severity')})"
        )

    print("\n" + "=" * 80)


# =========================================================
# MAIN PIPELINE
# =========================================================

def process_merchant(url):
    """
    Full merchant onboarding evaluation
    """
    print("\n" + "=" * 80)
    print(f"Scanning Merchant: {url}")
    print("=" * 80)

    try:
        # -------------------------------------------------
        # Duplicate protection
        # -------------------------------------------------
        if not FORCE_RESCAN and already_scanned(url):
            print(
                "\nMerchant already scanned previously. Skipping."
            )
            return

        if FORCE_RESCAN:
            print(
                "\nFORCE_RESCAN=True -> Fresh scan enabled"
            )

        # -------------------------------------------------
        # STEP 1: Scrape Website
        # -------------------------------------------------
        print("\n[STEP 1] Scraping merchant website...")
        scraped_data = scrape_website(url)

        if not scraped_data:
            raise Exception(
                "Scraping failed or empty response"
            )

        if scraped_data.get("error"):
            raise Exception(
                scraped_data.get("error")
            )

        # Ensure URL exists for downstream systems
        scraped_data["url"] = url

        # -------------------------------------------------
        # STEP 2: Verification Layer
        # -------------------------------------------------
        print("\n[STEP 2] Business legitimacy verification...")
        verification_result = verify_business_legitimacy(
            scraped_data
        )

        # -------------------------------------------------
        # STEP 3: Trusted Merchant Detector
        # -------------------------------------------------
        print("\n[STEP 3] Trusted merchant detection...")
        trust_result = detect_trusted_merchant(
            scraped_data
        )

        # -------------------------------------------------
        # STEP 4: Rules Engine
        # -------------------------------------------------
        print("\n[STEP 4] Risk findings detection...")
        findings = detect_risk_findings(
            scraped_data
        )

        # -------------------------------------------------
        # STEP 5: Trust Injection
        # -------------------------------------------------
        findings = inject_trust_signal(
            findings,
            trust_result
        )

        # -------------------------------------------------
        # STEP 6: Final Scoring
        # -------------------------------------------------
        print("\n[STEP 5] Final risk scoring...")
        final_result = calculate_risk_score(
            findings
        )

        # -------------------------------------------------
        # STEP 7: AI Explainability Layer
        # -------------------------------------------------
        print("\n[STEP 6] AI escalation review...")
        if should_skip_ai(
            final_result,
            trust_result
        ):
            print(
                "Trusted merchant -> AI skipped"
            )
            ai_result = build_safe_ai_result()
        else:
            print(
                "Running AI compliance analysis..."
            )
            ai_result = run_ai_analysis(
                merchant_url=url,
                findings=findings,
                scoring_result=final_result,
                verification_result=verification_result,
                trusted_merchant=trust_result.get(
                    "enterprise_trust_signal",
                    False
                )
            )

        # -------------------------------------------------
        # STEP 8: Alert Engine
        # -------------------------------------------------
        print("\n[STEP 7] Triggering alerts...")
        alert_payload = trigger_alerts(
            merchant_url=url,
            risk_score=final_result["risk_score"],
            risk_rating=final_result["risk_rating"],
            recommended_action=final_result[
                "recommended_action"
            ],
            verification_result=verification_result,
            findings=findings
        )

        # -------------------------------------------------
        # STEP 9: Save Database
        # -------------------------------------------------
        print("\n[STEP 8] Saving assessment...")
        save_assessment(
            merchant_url=url,
            risk_result=final_result,
            verification_result=verification_result,
            alert_payload=alert_payload,
            findings=findings
        )

        update_merchant_history(
            merchant_url=url,
            current_risk_rating=final_result[
                "risk_rating"
            ]
        )

        # -------------------------------------------------
        # STEP 10: Report Generation
        # -------------------------------------------------
        print("\n[STEP 9] Generating reports...")
        generate_reports(
            merchant_url=url,
            risk_score=final_result["risk_score"],
            risk_rating=final_result["risk_rating"],
            recommended_action=final_result[
                "recommended_action"
            ],
            findings=findings
        )

        # -------------------------------------------------
        # STEP 11: Final Summary
        # -------------------------------------------------
        print("\n[STEP 10] Final summary...")
        print_final_report(
            url=url,
            findings=findings,
            trust_result=trust_result,
            verification_result=verification_result,
            final_result=final_result,
            ai_result=ai_result,
            alert_payload=alert_payload
        )

    except Exception as e:
        print("\nPIPELINE EXECUTION FAILED")
        print(f"Merchant: {url}")
        print(f"Reason: {str(e)}")
        print("=" * 80)


# =========================================================
# ENTRY POINT
# =========================================================

def main():
    initialize_database()

    # -----------------------------------------
    # Dynamic URL from Streamlit / Terminal
    # -----------------------------------------
    if len(sys.argv) > 1:
        merchant_url = sys.argv[1]
        print(f"\nLIVE SCAN MODE -> {merchant_url}")
        process_merchant(merchant_url)
    else:
        print(
            "\nNo merchant URL provided."
            "\nUsage:"
            "\npython src/pipeline.py https://example.com"
        )


def run_pipeline():
    """
    Alias for main entry point to support main.py integration
    """
    main()


if __name__ == "__main__":
    main()
