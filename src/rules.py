# ================================
# FILE 2: rules.py
# ================================

from urllib.parse import urlparse
from trusted_merchant_detector import detect_trusted_merchant


# =========================================================
# CONFIGURATION
# =========================================================

HIGH_RISK_TLDS = [
    ".online",
    ".xyz",
    ".top",
    ".shop",
    ".live",
    ".site",
    ".store",
    ".click",
    ".buzz",
    ".loan",
    ".monster",
    ".support"
]

FREE_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "protonmail.com"
]

HIGH_RISK_INDUSTRIES = [
    "crypto",
    "bitcoin",
    "wallet",
    "casino",
    "betting",
    "gambling",
    "forex",
    "adult",
    "escort",
    "loan",
    "payday",
    "pharmacy",
    "miracle cure",
    "get rich quick"
]

PAYMENT_RISK_SIGNALS = [
    "crypto",
    "usdt",
    "bitcoin",
    "ethereum",
    "wallet payment"
]

UPI_ONLY_SIGNALS = [
    "upi",
    "gpay",
    "google pay",
    "phonepe",
    "paytm"
]


# =========================================================
# HELPERS
# =========================================================

def safe_text(value):
    if not value:
        return ""
    return str(value).lower()


def build_finding(signal, finding, severity, confidence):
    return {
        "signal": signal,
        "finding": finding,
        "severity": severity,
        "confidence": confidence
    }


def contains_keywords(text, keywords):
    text = safe_text(text)
    return any(keyword.lower() in text for keyword in keywords)


def is_free_email(email):
    email = safe_text(email)
    return any(domain in email for domain in FREE_EMAIL_DOMAINS)


def get_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def is_high_risk_tld(url):
    domain = get_domain(url)
    return any(domain.endswith(tld) for tld in HIGH_RISK_TLDS)


def domain_age_signal(domain_age_days):
    try:
        age = int(domain_age_days)
    except Exception:
        return None

    if age <= 30:
        return "very_new"

    if age <= 180:
        return "new"

    if age >= 730:
        return "old_trusted"

    return None


# =========================================================
# MAIN ENGINE
# =========================================================

def detect_risk_findings(merchant_data):
    """
    Returns:
    findings = [
        {
            "signal": "...",
            "finding": "...",
            "severity": "...",
            "confidence": 0.95
        }
    ]
    """

    findings = []

    url = merchant_data.get("url", "")
    email = merchant_data.get("email", "")
    phone = merchant_data.get("phone", "")
    address = merchant_data.get("address", "")
    about_page = merchant_data.get("about_page", False)
    page_text = merchant_data.get("page_text", "")
    payment_text = merchant_data.get("payment_text", "")
    domain_age_days = merchant_data.get("domain_age_days")

    combined = f"{page_text} {payment_text}"

    # Trust detector
    trust_result = detect_trusted_merchant(merchant_data)
    trusted_enterprise = trust_result["enterprise_trust_signal"]

    # =====================================================
    # 1. High-risk TLD
    # =====================================================

    if is_high_risk_tld(url) and not trusted_enterprise:
        findings.append(build_finding(
            "high_risk_tld",
            "High-risk domain TLD detected",
            "HIGH",
            0.92
        ))

    # =====================================================
    # 2. Email checks
    # =====================================================

    if not email and not trusted_enterprise:
        findings.append(build_finding(
            "missing_business_email",
            "No business email found",
            "MEDIUM",
            0.75
        ))

    elif is_free_email(email):
        findings.append(build_finding(
            "free_email_only",
            "Only free email provider detected",
            "MEDIUM",
            0.72
        ))

    # =====================================================
    # 3. Contact checks
    # =====================================================

    if not phone:
        findings.append(build_finding(
            "missing_phone",
            "No phone number found",
            "LOW",
            0.60
        ))

    if not address and not trusted_enterprise:
        findings.append(build_finding(
            "missing_address",
            "No physical address found",
            "MEDIUM",
            0.70
        ))

    if not phone and not address and not trusted_enterprise:
        findings.append(build_finding(
            "weak_contact_identity",
            "No phone and no physical address found",
            "HIGH",
            0.88
        ))

    # =====================================================
    # 4. Missing About Page
    # =====================================================

    if not about_page and not trusted_enterprise:
        findings.append(build_finding(
            "missing_about_page",
            "Missing About page",
            "LOW",
            0.55
        ))

    # =====================================================
    # 5. High-risk Industry
    # =====================================================

    if contains_keywords(combined, HIGH_RISK_INDUSTRIES):
        findings.append(build_finding(
            "high_risk_industry",
            "High-risk merchant industry detected",
            "CRITICAL",
            0.95
        ))

    # =====================================================
    # 6. Payment Risk
    # =====================================================

    if contains_keywords(combined, PAYMENT_RISK_SIGNALS):
        findings.append(build_finding(
            "crypto_payment",
            "Crypto payment detected",
            "CRITICAL",
            0.96
        ))

    elif contains_keywords(combined, UPI_ONLY_SIGNALS):
        findings.append(build_finding(
            "upi_only",
            "UPI-heavy payment behavior detected",
            "MEDIUM",
            0.70
        ))

    # =====================================================
    # 7. Domain Age
    # =====================================================

    age_signal = domain_age_signal(domain_age_days)

    if age_signal == "very_new":
        findings.append(build_finding(
            "very_new_domain",
            "Very new domain detected",
            "CRITICAL",
            0.95
        ))

    elif age_signal == "new":
        findings.append(build_finding(
            "new_domain",
            "New domain detected",
            "HIGH",
            0.85
        ))

    elif age_signal == "old_trusted":
        findings.append(build_finding(
            "old_domain_trust",
            "Old trusted domain detected",
            "LOW",
            0.90
        ))

    # =====================================================
    # 8. Enterprise Trust Override
    # =====================================================

    if trusted_enterprise:
        findings.append(build_finding(
            "enterprise_trust_verified",
            "Trusted enterprise merchant verified",
            "LOW",
            0.98
        ))

    return findings


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":
    sample = {
        "url": "https://www.microsoft.com/",
        "email": "",
        "phone": "",
        "address": "",
        "about_page": True,
        "payment_text": "Visa Mastercard",
        "page_text": """
            Microsoft investor relations
            privacy policy
            careers
            enterprise solutions
            corporate office
        """,
        "domain_age_days": 12000
    }

    result = detect_risk_findings(sample)
    print(result)