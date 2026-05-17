"""
Enterprise Merchant Website Extraction Engine V5
(Production Grade + Fraud Defensive + Strong Enterprise Detection)

UPDATED:
- Fixed About Page Detection professionally
- Removed false positives caused by weak "company" matching
- Strong anchor + href detection
- Better legal page detection accuracy

Core Principle:
Good scoring requires good inputs.
"""

from playwright.sync_api import sync_playwright
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
from pprint import pprint
import whois
import re


# =========================================================
# CONFIG
# =========================================================

MAX_TEXT_LENGTH = 25000
MAX_LINKS = 300
SECONDARY_PAGE_LIMIT = 10
PAGE_TIMEOUT = 25000

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
    ".support"
]

LEGAL_PAGE_PATTERNS = {
    "privacy": [
        "privacy",
        "privacy-policy",
        "privacy statement",
        "data protection"
    ],
    "refund": [
        "refund",
        "return",
        "returns",
        "refund policy"
    ],
    "terms": [
        "terms",
        "terms-and-conditions",
        "terms of service",
        "terms of use",
        "legal"
    ],
    "contact": [
        "contact",
        "contact-us",
        "support",
        "help center",
        "contact sales",
        "sales inquiry",
        "customer support"
    ],
    "about": [
        "about",
        "about-us",
        "about us",
        "who we are",
        "our story",
        "company profile",
        "corporate profile",
        "our company",
        "leadership",
        "team"
    ],
    "cancellation": [
        "cancel",
        "cancellation",
        "subscription cancellation"
    ],
    "shipping": [
        "shipping",
        "delivery",
        "dispatch",
        "shipping policy"
    ]
}

TRUSTED_PAYMENT_INFRA = [
    "stripe",
    "paypal",
    "razorpay",
    "adyen",
    "shopify payments",
    "braintree",
    "square",
    "authorize.net"
]

RISKY_PAYMENT_INDICATORS = [
    "crypto",
    "bitcoin",
    "usdt",
    "wallet payment",
    "instant payment",
    "subscription",
    "recurring billing",
    "auto renewal",
    "trial offer",
    "forex",
    "casino",
    "betting",
    "gambling",
    "adult services",
    "investment plan",
    "instant loan",
    "payday loan",
    "guaranteed returns",
    "100% profit",
    "double your money",
    "high return investment",
    "no refund"
]

ENTERPRISE_CONTACT_INDICATORS = [
    "contact sales",
    "talk to sales",
    "sales inquiry",
    "enterprise support",
    "customer support",
    "support center",
    "help center",
    "request demo",
    "book demo",
    "talk to expert",
    "contact us"
]

ENTERPRISE_TRUST_SIGNALS = [
    "linkedin",
    "investor relations",
    "press release",
    "case study",
    "enterprise customer",
    "partner ecosystem",
    "iso certified",
    "aws partner",
    "google partner",
    "microsoft partner",
    "salesforce partner",
    "private limited",
    "pvt ltd",
    "llp",
    "inc.",
    "registered company",
    "verified gst",
    "corporate office",
    "google business"
]

SUSPICIOUS_BRAND_PATTERNS = [
    "global solution",
    "india solution",
    "trading company",
    "investment group",
    "wealth partner",
    "crypto investment",
    "forex expert",
    "profit guaranteed"
]


# =========================================================
# HELPERS
# =========================================================

def extract_domain(url):
    return urlparse(url).netloc.replace(
        "www.", ""
    ).strip().lower()


def is_high_risk_tld(domain):
    for tld in HIGH_RISK_TLDS:
        if domain.endswith(tld):
            return True
    return False


def get_domain_age(domain):
    try:
        info = whois.whois(domain)
        creation_date = info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (
                datetime.now() - creation_date
            ).days
        else:
            age_days = None

        return {
            "domain_age_days": age_days,
            "registrant": getattr(
                info,
                "registrant_name",
                "Unknown"
            ),
            "country": getattr(
                info,
                "country",
                "Unknown"
            ),
            "creation_date": (
                str(creation_date)
                if creation_date else "Unknown"
            )
        }

    except Exception:
        return {
            "domain_age_days": None,
            "registrant": "Unknown",
            "country": "Unknown",
            "creation_date": "Unknown"
        }


def normalize_links(base_url, links):
    cleaned = []

    for link in links:
        if not link:
            continue

        if link.startswith("mailto:") or link.startswith("tel:"):
            cleaned.append(link)
            continue

        try:
            full = urljoin(base_url, link)

            if full.startswith("http"):
                cleaned.append(full)

        except Exception:
            continue

    return list(set(cleaned))


def discover_priority_pages(all_links):
    priority = []

    for link in all_links:
        link_lower = link.lower()

        for group in LEGAL_PAGE_PATTERNS.values():
            if any(keyword in link_lower for keyword in group):
                priority.append(link)
                break

    return list(dict.fromkeys(priority))[:SECONDARY_PAGE_LIMIT]


def extract_contacts(text, links):
    emails = re.findall(
        r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        text
    )

    phones = re.findall(
        r"(?:\+?\d{1,3}[-\s]?)?(?:\(?\d{2,5}\)?[-\s]?)?\d{6,12}",
        text
    )

    combined = (
        text.lower()
        + " "
        + " ".join(links).lower()
    )

    has_contact_form = any(
        item in combined
        for item in ENTERPRISE_CONTACT_INDICATORS
    )

    if has_contact_form and not emails:
        emails.append(
            "enterprise-contact-form-detected"
        )

    return {
        "emails": list(set(emails)),
        "phones": list(set(phones)),
        "has_contact_form": has_contact_form
    }


# =========================================================
#  ABOUT PAGE DETECTION
# =========================================================

def detect_about_page(soup, links):
    """
    Strong about page detection
    Prevent false negatives like:
    manifestwaresoftware.com

    Checks:
    - anchor text
    - href values
    - normalized links
    """

    about_keywords = [
        "about",
        "about-us",
        "about us",
        "who we are",
        "our story",
        "company profile",
        "corporate profile",
        "our company",
        "leadership",
        "team",
        "Learn More",
        "learnmore",
        "Learn More"
    ]

    # 1. Direct anchor check
    for a in soup.find_all("a", href=True):
        text = a.get_text(strip=True).lower()
        href = a.get("href", "").lower()

        combined = f"{text} {href}"

        for keyword in about_keywords:
            if keyword in combined:
                return True

    # 2. Fallback on normalized links
    for link in links:
        link = str(link).lower()

        for keyword in about_keywords:
            if keyword in link:
                return True

    return False


def detect_policy_pages(text, links, soup):
    combined = (
        text.lower()
        + " "
        + " ".join(links).lower()
    )

    def contains_any(items):
        return any(
            item.lower() in combined
            for item in items
        )

    return {
        "has_privacy_policy": contains_any(
            LEGAL_PAGE_PATTERNS["privacy"]
        ),
        "has_refund_policy": contains_any(
            LEGAL_PAGE_PATTERNS["refund"]
        ),
        "has_terms_conditions": contains_any(
            LEGAL_PAGE_PATTERNS["terms"]
        ),
        "has_contact_page": contains_any(
            LEGAL_PAGE_PATTERNS["contact"]
        ),

        # FIXED HERE
        "has_about_page": detect_about_page(
            soup,
            links
        ),

        "has_cancellation_policy": contains_any(
            LEGAL_PAGE_PATTERNS["cancellation"]
        ),
        "has_shipping_policy": contains_any(
            LEGAL_PAGE_PATTERNS["shipping"]
        )
    }


def detect_payment_signals(text):
    text = text.lower()
    found = []

    for item in RISKY_PAYMENT_INDICATORS:
        if item in text:
            found.append(item)

    for item in TRUSTED_PAYMENT_INFRA:
        if item in text:
            found.append(item)

    return list(set(found))


def detect_enterprise_signals(text, links):
    combined = (
        text.lower()
        + " "
        + " ".join(links).lower()
    )

    found = []

    for item in ENTERPRISE_TRUST_SIGNALS:
        if item in combined:
            found.append(item)

    return list(set(found))


def detect_suspicious_patterns(text, domain):
    combined = text.lower() + " " + domain.lower()

    findings = []

    if is_high_risk_tld(domain):
        findings.append("high-risk-tld")

    for item in SUSPICIOUS_BRAND_PATTERNS:
        if item in combined:
            findings.append(item)

    return list(set(findings))


# =========================================================
# MAIN ENGINE
# =========================================================

def extract_site_data(url):
    domain = extract_domain(url)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True
        )

        page = browser.new_page()

        try:
            page.goto(
                url,
                timeout=PAGE_TIMEOUT,
                wait_until="domcontentloaded"
            )

            html = page.content()
            homepage_text = page.inner_text("body")

            soup = BeautifulSoup(
                html,
                "html.parser"
            )

            raw_links = [
                a.get("href")
                for a in soup.find_all(
                    "a",
                    href=True
                )
            ]

            all_links = normalize_links(
                url,
                raw_links
            )

            priority_pages = discover_priority_pages(
                all_links
            )

            secondary_text = ""

            for link in priority_pages:
                try:
                    sub = browser.new_page()

                    sub.goto(
                        link,
                        timeout=15000,
                        wait_until="domcontentloaded"
                    )

                    secondary_text += (
                        " "
                        + sub.inner_text("body")[:5000]
                    )

                    sub.close()

                except Exception:
                    continue

            combined_text = (
                homepage_text[:MAX_TEXT_LENGTH]
                + " "
                + secondary_text[:MAX_TEXT_LENGTH]
            )

            contacts = extract_contacts(
                combined_text,
                all_links
            )

            policies = detect_policy_pages(
                combined_text,
                all_links,
                soup
            )

            payment_signals = detect_payment_signals(
                combined_text
            )

            enterprise_signals = detect_enterprise_signals(
                combined_text,
                all_links
            )

            suspicious_patterns = detect_suspicious_patterns(
                combined_text,
                domain
            )

            domain_data = get_domain_age(domain)

            result = {
                "url": url,
                "domain": domain,
                "text_content":
                    combined_text[:MAX_TEXT_LENGTH],
                "all_links":
                    all_links[:MAX_LINKS],
                "payment_signals":
                    payment_signals,
                "enterprise_signals":
                    enterprise_signals,
                "suspicious_patterns":
                    suspicious_patterns,
                "forms_count":
                    len(soup.find_all("form")),
                "images_count":
                    len(soup.find_all("img")),
                "iframes_count":
                    len(soup.find_all("iframe")),
                "has_https":
                    url.startswith("https"),
                "high_risk_tld":
                    is_high_risk_tld(domain),

                **contacts,
                **policies,
                **domain_data
            }

            browser.close()
            return result

        except Exception as e:
            browser.close()

            return {
                "error": str(e),
                "url": url
            }


def scrape_website(url):
    return extract_site_data(url)


# =========================================================
# LOCAL TEST
# =========================================================

if __name__ == "__main__":
    test_url = "https://manifestwaresoftware.com/web/"

    result = scrape_website(test_url)

    print(
        "\n========== SCRAPER V5 OUTPUT ==========\n"
    )

    pprint(result)