# ================================
# FILE 1: trusted_merchant_detector.py
# ================================

from urllib.parse import urlparse


# =========================================================
# CONFIGURATION
# =========================================================

KNOWN_ENTERPRISE_BRANDS = [
    "microsoft",
    "google",
    "amazon",
    "aws",
    "shopify",
    "zoho",
    "freshworks",
    "salesforce",
    "oracle",
    "adobe",
    "stripe",
    "paypal",
    "razorpay",
    "sap",
    "ibm",
    "intel",
    "cisco",
    "dell"
]

TRUST_SIGNALS = [
    "investor relations",
    "privacy policy",
    "terms and conditions",
    "refund policy",
    "registered office",
    "corporate office",
    "gst",
    "compliance",
    "legal notice",
    "press release",
    "leadership team",
    "board of directors",
    "careers",
    "annual report",
    "enterprise solutions"
]

FREE_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com",
    "protonmail.com"
]


# =========================================================
# HELPERS
# =========================================================

def safe_text(value):
    if not value:
        return ""
    return str(value).lower()


def count_keywords(text, keywords):
    text = safe_text(text)
    return sum(1 for keyword in keywords if keyword.lower() in text)


def get_domain(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def is_known_enterprise(url):
    domain = get_domain(url)
    return any(brand in domain for brand in KNOWN_ENTERPRISE_BRANDS)


def domain_age_signal(domain_age_days):
    try:
        age = int(domain_age_days)
    except Exception:
        return None

    if age >= 730:
        return "old_trusted"

    return None


# =========================================================
# MAIN ENGINE
# =========================================================

def detect_trusted_merchant(merchant_data):
    """
    Returns:
    {
        "enterprise_trust_signal": True/False,
        "trust_score": int,
        "trust_reasons": [...]
    }
    """

    url = merchant_data.get("url", "")
    page_text = merchant_data.get("page_text", "")
    payment_text = merchant_data.get("payment_text", "")
    email = merchant_data.get("email", "")
    phone = merchant_data.get("phone", "")
    address = merchant_data.get("address", "")
    domain_age_days = merchant_data.get("domain_age_days", 0)

    combined = f"{page_text} {payment_text} {email} {address}"

    trust_score = 0
    trust_reasons = []

    # 1. Strong enterprise domain
    if is_known_enterprise(url):
        trust_score += 5
        trust_reasons.append("Known enterprise domain detected")

    # 2. Multiple legal/compliance signals
    trust_hits = count_keywords(combined, TRUST_SIGNALS)
    if trust_hits >= 3:
        trust_score += 3
        trust_reasons.append("Multiple corporate trust signals detected")

    # 3. Strong contact infrastructure
    if email and phone and address:
        trust_score += 2
        trust_reasons.append("Strong business contact infrastructure detected")

    # 4. Old domain trust
    if domain_age_signal(domain_age_days) == "old_trusted":
        trust_score += 3
        trust_reasons.append("Old trusted domain detected")

    # Final trust decision
    enterprise_trust_signal = trust_score >= 5

    return {
        "enterprise_trust_signal": enterprise_trust_signal,
        "trust_score": trust_score,
        "trust_reasons": trust_reasons
    }


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":
    sample = {
        "url": "https://www.microsoft.com/",
        "email": "",
        "phone": "",
        "address": "",
        "page_text": """
            Microsoft investor relations
            privacy policy
            careers
            enterprise solutions
            corporate office
        """,
        "payment_text": "Visa Mastercard",
        "domain_age_days": 12000
    }

    result = detect_trusted_merchant(sample)
    print(result)