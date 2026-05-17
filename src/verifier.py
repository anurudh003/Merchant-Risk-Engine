"""
Enterprise Merchant Verification Engine V3
(Fraud Defensive + Weighted Verification + False Positive Reduction)

Core Principle:
Verification must prove legitimacy.

Do NOT assume merchants are safe.

Start from neutral score (50),
then move upward or downward based on evidence.
"""

from pprint import pprint
from urllib.parse import urlparse


# =========================================================
# CONFIGURATION
# =========================================================

TRUSTED_PAYMENT_PROVIDERS = [
    "stripe",
    "paypal",
    "razorpay",
    "shopify",
    "adyen",
    "braintree",
    "authorize.net",
    "square"
]

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
    ".loan"
]

ENTERPRISE_TRUST_SIGNALS = [
    "linkedin company page",
    "investor relations",
    "press release",
    "enterprise customer",
    "iso certified",
    "google partner",
    "microsoft partner",
    "aws partner",
    "salesforce partner",
    "private limited",
    "pvt ltd",
    "corporate office",
    "verified gst",
    "registered company"
]

HIGH_RISK_BUSINESS_PATTERNS = [
    "crypto",
    "forex",
    "casino",
    "gambling",
    "betting",
    "adult",
    "instant loan",
    "payday loan",
    "binary options",
    "high return investment"
]


# =========================================================
# HELPERS
# =========================================================

def text_contains_any(text, keywords):
    if not text:
        return False

    text = str(text).lower()

    for keyword in keywords:
        if keyword.lower() in text:
            return True

    return False


def list_contains_any(items, keywords):
    combined = " ".join(
        [str(item).lower() for item in items]
    )

    return text_contains_any(combined, keywords)


def is_high_risk_tld(url):
    if not url:
        return False

    domain = urlparse(url).netloc.lower()

    for tld in HIGH_RISK_TLDS:
        if domain.endswith(tld):
            return True

    return False


# =========================================================
# MAIN ENGINE
# =========================================================

def verify_business_legitimacy(scraped_data):
    """
    Output:

    {
        "verification_score": 72,
        "verification_status": "MODERATE TRUST",
        "verification_flags": [...],
        "trust_signals_detected": [...],
        "recommendation": "..."
    }
    """

    # ============================================
    # START FROM NEUTRAL — NOT PERFECT
    # ============================================

    verification_score = 50

    verification_flags = []
    trust_signals_detected = []

    # ============================================
    # EXTRACT DATA
    # ============================================

    merchant_url = scraped_data.get("url", "")

    emails = scraped_data.get("emails", [])
    phones = scraped_data.get("phones", [])
    links = scraped_data.get("all_links", [])

    domain_age = scraped_data.get("domain_age_days")
    has_https = scraped_data.get("has_https", False)

    has_privacy_policy = scraped_data.get(
        "has_privacy_policy",
        False
    )

    has_contact_page = scraped_data.get(
        "has_contact_page",
        False
    )

    has_about_page = scraped_data.get(
        "has_about_page",
        False
    )

    text_content = scraped_data.get(
        "text_content",
        ""
    )

    payment_signals = scraped_data.get(
        "payment_signals",
        []
    )

    combined_links_text = " ".join(links)
    combined_text = f"{text_content} {combined_links_text}".lower()

    # ============================================
    # 1. HIGH-RISK TLD CHECK
    # ============================================

    if is_high_risk_tld(merchant_url):
        verification_score -= 20
        verification_flags.append(
            "High-risk domain TLD detected"
        )

    # ============================================
    # 2. BUSINESS CONTACT AUTHENTICITY
    # ============================================

    if emails:
        verification_score += 8
        trust_signals_detected.append(
            "Business email available"
        )
    else:
        verification_score -= 12
        verification_flags.append(
            "No official business email found"
        )

    if phones:
        verification_score += 6
        trust_signals_detected.append(
            "Support phone available"
        )
    else:
        verification_score -= 8
        verification_flags.append(
            "No support phone found"
        )

    # ============================================
    # 3. DOMAIN TRUST VALIDATION
    # ============================================

    if domain_age is None:
        verification_score -= 8
        verification_flags.append(
            "WHOIS data unavailable"
        )

    elif domain_age < 30:
        verification_score -= 25
        verification_flags.append(
            "Very new domain detected"
        )

    elif domain_age < 180:
        verification_score -= 15
        verification_flags.append(
            "New domain detected"
        )

    elif domain_age > 730:
        verification_score += 15
        trust_signals_detected.append(
            "Mature domain detected"
        )

    if has_https:
        verification_score += 5
        trust_signals_detected.append(
            "HTTPS security enabled"
        )
    else:
        verification_score -= 20
        verification_flags.append(
            "Website not secured with HTTPS"
        )

    # ============================================
    # 4. COMPLIANCE VISIBILITY
    # ============================================

    if has_privacy_policy:
        verification_score += 3
    else:
        verification_score -= 5
        verification_flags.append(
            "Missing privacy policy"
        )

    if has_contact_page:
        verification_score += 4
    else:
        verification_score -= 8
        verification_flags.append(
            "Missing contact page"
        )

    if has_about_page:
        verification_score += 2
    else:
        verification_score -= 3
        verification_flags.append(
            "Missing about page"
        )

    # ============================================
    # 5. ENTERPRISE TRUST INFRASTRUCTURE
    # ============================================

    if text_contains_any(
        combined_text,
        ENTERPRISE_TRUST_SIGNALS
    ):
        verification_score += 12
        trust_signals_detected.append(
            "Enterprise trust infrastructure detected"
        )

    if "linkedin" in combined_text:
        verification_score += 5
        trust_signals_detected.append(
            "LinkedIn presence detected"
        )

    # ============================================
    # 6. PAYMENT ECOSYSTEM
    # ============================================

    if list_contains_any(
        payment_signals,
        TRUSTED_PAYMENT_PROVIDERS
    ):
        verification_score += 8
        trust_signals_detected.append(
            "Trusted payment gateway detected"
        )

    if text_contains_any(
        combined_text,
        HIGH_RISK_BUSINESS_PATTERNS
    ):
        verification_score -= 15
        verification_flags.append(
            "High-risk business behavior detected"
        )

    # ============================================
    # 7. SOCIAL PRESENCE
    # ============================================

    social_platforms = [
        "linkedin",
        "facebook",
        "instagram",
        "twitter",
        "youtube"
    ]

    has_social_presence = any(
        any(
            platform in link.lower()
            for platform in social_platforms
        )
        for link in links
    )

    if has_social_presence:
        verification_score += 4
        trust_signals_detected.append(
            "Social presence detected"
        )
    else:
        verification_score -= 4
        verification_flags.append(
            "Limited visible social presence"
        )

    # ============================================
    # 8. STRICT ENTERPRISE OVERRIDE
    # ============================================

    if (
        len(trust_signals_detected) >= 5
        and domain_age is not None
        and domain_age > 730
        and has_https
        and not is_high_risk_tld(merchant_url)
    ):
        verification_score += 8
        trust_signals_detected.append(
            "Trusted enterprise override applied"
        )

    # ============================================
    # SAFETY BOUNDS
    # ============================================

    if verification_score < 0:
        verification_score = 0

    if verification_score > 100:
        verification_score = 100

    # ============================================
    # FINAL CLASSIFICATION
    # ============================================

    if verification_score >= 80:
        verification_status = "HIGH TRUST"
        recommendation = "Proceed with Standard Monitoring"

    elif verification_score >= 55:
        verification_status = "MODERATE TRUST"
        recommendation = "Manual Review Recommended"

    else:
        verification_status = "LOW TRUST"
        recommendation = "Enhanced Due Diligence Required"

    # ============================================
    # FINAL OUTPUT
    # ============================================

    return {
        "verification_score": verification_score,
        "verification_status": verification_status,
        "verification_flags": verification_flags,
        "trust_signals_detected": trust_signals_detected,
        "recommendation": recommendation
    }


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":

    sample_scraped_data = {
        "url": "https://zylotechindia.online/",
        "emails": ["support@company.com"],
        "phones": [],
        "has_privacy_policy": True,
        "has_contact_page": True,
        "has_about_page": False,
        "domain_age_days": 120,
        "has_https": True,
        "all_links": [
            "https://linkedin.com/company/test"
        ],
        "payment_signals": [],
        "text_content": """
        Business consulting services.
        Private Limited company.
        """
    }

    result = verify_business_legitimacy(
        sample_scraped_data
    )

    print("\n========== VERIFIER V3 RESULT ==========\n")
    pprint(result)