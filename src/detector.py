"""
Enterprise Merchant Risk Intelligence Engine V5
(Fraud Defensive + Strong Detection Layer + Enterprise Safe Calibration)

Core Principle:
Detection quality drives underwriting quality.

Good merchants must be protected.
Bad merchants must be surfaced.

Never trust:
homepage cosmetics

Always trust:
behavior + identity + structure
"""

from pprint import pprint


# =========================================================
# CATEGORY INTELLIGENCE
# =========================================================

HIGH_RISK_CATEGORIES = [
    "crypto",
    "forex",
    "binary options",
    "casino",
    "gambling",
    "betting",
    "adult",
    "adult services",
    "payday loan",
    "instant loan",
    "investment scheme",
    "trading platform",
    "high return investment",
    "guaranteed profit",
    "double your money",
    "investment return"
]

MEDIUM_RISK_CATEGORIES = [
    "ecommerce",
    "marketplace",
    "dropshipping",
    "affiliate marketing",
    "travel booking",
    "aggregator",
    "reseller"
]

LOW_RISK_CATEGORIES = [
    "saas",
    "software",
    "crm",
    "enterprise software",
    "cloud platform",
    "consulting",
    "professional services",
    "analytics platform",
    "education platform",
    "b2b"
]

ENTERPRISE_TRUST_SIGNALS = [
    "careers",
    "investor relations",
    "press release",
    "case study",
    "enterprise customer",
    "partner ecosystem",
    "private limited",
    "pvt ltd",
    "inc.",
    "llp",
    "gst",
    "corporate office",
    "iso certified",
    "registered company",
    "linkedin",
    "contact sales",
    "support center",
    "help center",
    "google business",
    "microsoft partner",
    "aws partner",
    "salesforce partner"
]

SUSPICIOUS_BRAND_PATTERNS = [
    "global solution",
    "india solution",
    "trading company",
    "investment group",
    "wealth partner",
    "profit guaranteed",
    "guaranteed return",
    "crypto investment",
    "forex expert"
]


# =========================================================
# HELPERS
# =========================================================

def contains_any(text, items):
    if not text:
        return False

    text = str(text).lower()

    for item in items:
        if item.lower() in text:
            return True

    return False


def create_finding(label):
    return label


def get_combined_text(scraped_data):
    text = scraped_data.get(
        "text_content",
        ""
    )

    links = " ".join(
        scraped_data.get(
            "all_links",
            []
        )
    )

    enterprise = " ".join(
        scraped_data.get(
            "enterprise_signals",
            []
        )
    )

    suspicious = " ".join(
        scraped_data.get(
            "suspicious_patterns",
            []
        )
    )

    return (
        str(text).lower()
        + " "
        + str(links).lower()
        + " "
        + str(enterprise).lower()
        + " "
        + str(suspicious).lower()
    )


# =========================================================
# DETECTOR 1
# MERCHANT CATEGORY
# =========================================================

def detect_merchant_category(scraped_data):
    findings = []

    combined = get_combined_text(
        scraped_data
    )

    # HIGH RISK FIRST
    if contains_any(
        combined,
        HIGH_RISK_CATEGORIES
    ):
        findings.append(
            create_finding(
                "High-risk merchant category detected"
            )
        )
        return findings

    # LOW RISK TRUST MODEL
    if contains_any(
        combined,
        LOW_RISK_CATEGORIES
    ):
        findings.append(
            create_finding(
                "Trusted merchant model detected"
            )
        )

    # MEDIUM RISK
    elif contains_any(
        combined,
        MEDIUM_RISK_CATEGORIES
    ):
        findings.append(
            create_finding(
                "Medium-risk merchant category detected"
            )
        )

    return findings


# =========================================================
# DETECTOR 2
# TRUST INFRASTRUCTURE
# =========================================================

def detect_trust_infrastructure(scraped_data):
    findings = []

    combined = get_combined_text(
        scraped_data
    )

    if contains_any(
        combined,
        ENTERPRISE_TRUST_SIGNALS
    ):
        findings.append(
            "Enterprise trust signal detected"
        )

    return findings


# =========================================================
# DETECTOR 3
# BUSINESS IDENTITY
# =========================================================

def detect_identity_signals(scraped_data):
    findings = []

    emails = scraped_data.get(
        "emails",
        []
    )

    phones = scraped_data.get(
        "phones",
        []
    )

    has_contact_form = scraped_data.get(
        "has_contact_form",
        False
    )

    trust_exists = (
        "Enterprise trust signal detected"
        in detect_trust_infrastructure(
            scraped_data
        )
    )

    # BUSINESS EMAIL
    if not emails and not has_contact_form:
        findings.append(
            "No business email found"
        )

    # PHONE
    if (
        not phones
        and not trust_exists
    ):
        findings.append(
            "No phone number found"
        )

    # ADDRESS CHECK
    text = scraped_data.get(
        "text_content",
        ""
    ).lower()

    address_signals = [
        "head office",
        "corporate office",
        "registered office",
        "address:",
        "our office"
    ]

    if (
        not contains_any(
            text,
            address_signals
        )
        and not trust_exists
    ):
        findings.append(
            "No physical address found"
        )

    return findings


# =========================================================
# DETECTOR 4
# DOMAIN INTELLIGENCE
# =========================================================

def detect_domain_signals(scraped_data):
    findings = []

    trust_exists = (
        "Enterprise trust signal detected"
        in detect_trust_infrastructure(
            scraped_data
        )
    )

    domain_age = scraped_data.get(
        "domain_age_days"
    )

    high_risk_tld = scraped_data.get(
        "high_risk_tld",
        False
    )

    suspicious_patterns = scraped_data.get(
        "suspicious_patterns",
        []
    )

    if high_risk_tld:
        findings.append(
            "High-risk domain TLD detected"
        )

    if (
        domain_age is None
        and not trust_exists
    ):
        findings.append(
            "WHOIS unavailable"
        )

    elif (
        domain_age is not None
        and domain_age < 180
    ):
        findings.append(
            "Very new domain"
        )

    elif (
        domain_age is not None
        and domain_age < 365
    ):
        findings.append(
            "New domain"
        )

    if suspicious_patterns:
        findings.append(
            "Suspicious business naming pattern detected"
        )

    return findings


# =========================================================
# DETECTOR 5
# LEGAL + COMPLIANCE
# =========================================================

def detect_compliance_signals(scraped_data):
    findings = []

    trust_exists = (
        "Enterprise trust signal detected"
        in detect_trust_infrastructure(
            scraped_data
        )
    )

    if (
        not scraped_data.get(
            "has_privacy_policy",
            False
        )
        and not trust_exists
    ):
        findings.append(
            "Missing privacy policy"
        )

    if not scraped_data.get(
        "has_refund_policy",
        False
    ):
        findings.append(
            "Missing refund policy"
        )

    if (
        not scraped_data.get(
            "has_terms_conditions",
            False
        )
        and not trust_exists
    ):
        findings.append(
            "Missing terms and conditions"
        )

    if not scraped_data.get(
        "has_contact_page",
        False
    ):
        findings.append(
            "Missing contact page"
        )

    if not scraped_data.get(
        "has_cancellation_policy",
        False
    ):
        findings.append(
            "Missing cancellation policy"
        )

    if not scraped_data.get(
        "has_about_page",
        False
    ):
        findings.append(
            "Missing about page"
        )

    return findings


# =========================================================
# DETECTOR 6
# PAYMENT + TECHNICAL
# =========================================================

def detect_payment_and_technical(scraped_data):
    findings = []

    payment_flags = scraped_data.get(
        "payment_signals",
        []
    )

    risky_flags = []

    for item in payment_flags:
        item_lower = str(item).lower()

        if item_lower in [
            "crypto",
            "bitcoin",
            "usdt",
            "casino",
            "gambling",
            "betting",
            "investment plan",
            "payday loan",
            "forex"
        ]:
            risky_flags.append(item)

    if risky_flags:
        findings.append(
            "Suspicious payment indicators"
        )

    iframe_count = scraped_data.get(
        "iframes_count",
        0
    )

    if iframe_count > 10:
        findings.append(
            "Heavy iframe usage detected"
        )

    if not scraped_data.get(
        "has_https",
        False
    ):
        findings.append(
            "No HTTPS/TLS security"
        )

    return findings


# =========================================================
# MAIN DETECTOR
# =========================================================

def detect_risk_signals(scraped_data):
    findings = []

    findings.extend(
        detect_merchant_category(
            scraped_data
        )
    )

    findings.extend(
        detect_trust_infrastructure(
            scraped_data
        )
    )

    findings.extend(
        detect_identity_signals(
            scraped_data
        )
    )

    findings.extend(
        detect_domain_signals(
            scraped_data
        )
    )

    findings.extend(
        detect_compliance_signals(
            scraped_data
        )
    )

    findings.extend(
        detect_payment_and_technical(
            scraped_data
        )
    )

    # remove duplicates
    findings = list(
        dict.fromkeys(findings)
    )

    return findings


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":
    from scraper import scrape_website

    test_url = "https://zylotechindia.online/"

    scraped_data = scrape_website(
        test_url
    )

    findings = detect_risk_signals(
        scraped_data
    )

    print(
        "\n========== DETECTOR V5 OUTPUT ==========\n"
    )

    pprint(findings)