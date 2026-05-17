# src/report_generator.py

"""
report_generator.py

Production-Grade Merchant Risk Report Generator V3

Built from:
- Your existing strong PDF + JSON reporting logic
- Improved analyst readability
- JSON-safe findings handling
- Better compliance summary
- Supports structured findings from rules/scorer
- Cleaner audit-ready output

Outputs:
1. JSON report (system/API use)
2. PDF report (analyst/compliance use)

Core Principle:
Reports should explain WHY a merchant was scored,
not just show the final score.
"""

import json
import os
from datetime import datetime

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    ListFlowable,
    ListItem
)
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4


# =========================================================
# DIRECTORY SETUP
# =========================================================

REPORT_FOLDER = "reports"

if not os.path.exists(REPORT_FOLDER):
    os.makedirs(REPORT_FOLDER)


# =========================================================
# HELPERS
# =========================================================

def safe_findings_list(findings):
    """
    Support both:
    [
        "Missing email"
    ]

    and

    [
        {
            "signal": "...",
            "finding": "...",
            "severity": "HIGH"
        }
    ]
    """

    clean_findings = []

    if not findings:
        return clean_findings

    for item in findings:
        if isinstance(item, dict):
            finding = item.get(
                "finding",
                "Unknown finding"
            )

            severity = item.get(
                "severity",
                "UNKNOWN"
            )

            signal = item.get(
                "signal",
                "unknown_signal"
            )

            formatted = (
                f"{finding} "
                f"(Severity: {severity}, "
                f"Signal: {signal})"
            )

            clean_findings.append(formatted)

        else:
            clean_findings.append(str(item))

    return clean_findings


def get_compliance_recommendation(risk_rating):
    """
    Human-readable compliance decision
    """

    risk_rating = str(risk_rating).upper()

    if risk_rating == "CRITICAL":
        return (
            "Merchant must be blocked immediately and "
            "escalated to senior compliance review."
        )

    elif risk_rating == "HIGH":
        return (
            "Merchant requires immediate compliance "
            "investigation before onboarding approval."
        )

    elif risk_rating == "MEDIUM":
        return (
            "Merchant requires enhanced due diligence "
            "and mandatory analyst review."
        )

    return (
        "Merchant qualifies for standard onboarding "
        "with routine transaction monitoring."
    )


# =========================================================
# JSON REPORT
# =========================================================

def generate_json_report(
    merchant_url,
    risk_score,
    risk_rating,
    recommended_action,
    findings
):
    """
    Generate structured JSON report
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    findings = safe_findings_list(findings)

    report_data = {
        "timestamp": timestamp,
        "merchant_url": merchant_url,
        "risk_score": risk_score,
        "risk_rating": risk_rating,
        "recommended_action": recommended_action,
        "compliance_summary":
            get_compliance_recommendation(
                risk_rating
            ),
        "triggered_findings": findings
    }

    filename = (
        f"{REPORT_FOLDER}/report_{timestamp}.json"
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            report_data,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"\nJSON Report Generated: {filename}"
    )

    return filename


# =========================================================
# PDF REPORT
# =========================================================

def generate_pdf_report(
    merchant_url,
    risk_score,
    risk_rating,
    recommended_action,
    findings
):
    """
    Generate professional PDF report
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )

    filename = (
        f"{REPORT_FOLDER}/report_{timestamp}.pdf"
    )

    findings = safe_findings_list(findings)

    doc = SimpleDocTemplate(
        filename,
        pagesize=A4
    )

    styles = getSampleStyleSheet()
    story = []

    # =====================================================
    # TITLE
    # =====================================================

    story.append(
        Paragraph(
            "MERCHANT RISK ASSESSMENT REPORT",
            styles["Title"]
        )
    )

    story.append(Spacer(1, 20))

    # =====================================================
    # BASIC INFO
    # =====================================================

    basic_info = [
        f"<b>Generated On:</b> {timestamp}",
        f"<b>Merchant URL:</b> {merchant_url}",
        f"<b>Risk Score:</b> {risk_score}",
        f"<b>Risk Rating:</b> {risk_rating}",
        f"<b>Recommended Action:</b> "
        f"{recommended_action}"
    ]

    for item in basic_info:
        story.append(
            Paragraph(
                item,
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 20))

    # =====================================================
    # FINDINGS
    # =====================================================

    story.append(
        Paragraph(
            "<b>Triggered Findings:</b>",
            styles["Heading3"]
        )
    )

    story.append(Spacer(1, 10))

    if findings:
        bullet_items = []

        for item in findings:
            bullet_items.append(
                ListItem(
                    Paragraph(
                        item,
                        styles["Normal"]
                    )
                )
            )

        story.append(
            ListFlowable(
                bullet_items,
                bulletType="bullet"
            )
        )

    else:
        story.append(
            Paragraph(
                "No major risk indicators detected.",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 20))

    # =====================================================
    # COMPLIANCE RECOMMENDATION
    # =====================================================

    story.append(
        Paragraph(
            "<b>Compliance Recommendation:</b>",
            styles["Heading3"]
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            get_compliance_recommendation(
                risk_rating
            ),
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 20))

    # =====================================================
    # AUDIT NOTE
    # =====================================================

    story.append(
        Paragraph(
            "<b>Audit Note:</b>",
            styles["Heading3"]
        )
    )

    story.append(Spacer(1, 10))

    story.append(
        Paragraph(
            (
                "This report was generated by the "
                "Merchant Risk Intelligence Engine. "
                "Final onboarding decisions must be "
                "validated by compliance analysts "
                "for HIGH and CRITICAL risk merchants."
            ),
            styles["Normal"]
        )
    )

    # =====================================================
    # BUILD PDF
    # =====================================================

    doc.build(story)

    print(
        f"\nPDF Report Generated: {filename}"
    )

    return filename


# =========================================================
# MASTER FUNCTION
# =========================================================

def generate_reports(
    merchant_url,
    risk_score,
    risk_rating,
    recommended_action,
    findings
):
    """
    Generate:
    - JSON report
    - PDF report
    """

    json_file = generate_json_report(
        merchant_url=merchant_url,
        risk_score=risk_score,
        risk_rating=risk_rating,
        recommended_action=recommended_action,
        findings=findings
    )

    pdf_file = generate_pdf_report(
        merchant_url=merchant_url,
        risk_score=risk_score,
        risk_rating=risk_rating,
        recommended_action=recommended_action,
        findings=findings
    )

    return {
        "json_report": json_file,
        "pdf_report": pdf_file
    }


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    sample_findings = [
        {
            "signal": "missing_business_email",
            "finding": "No business email found",
            "severity": "HIGH"
        },
        {
            "signal": "very_new_domain",
            "finding": "Very new domain detected",
            "severity": "CRITICAL"
        },
        {
            "signal": "crypto_payment_detected",
            "finding": "Crypto payment detected",
            "severity": "CRITICAL"
        }
    ]

    reports = generate_reports(
        merchant_url="https://example-highrisk-merchant.com",
        risk_score=88,
        risk_rating="HIGH",
        recommended_action=(
            "Immediate Compliance Investigation Required"
        ),
        findings=sample_findings
    )

    print("\nGenerated Files:")
    print(reports)