from urllib.parse import urlparse
import re


def analyze_url(url):
    """
    Analyze a URL for common suspicious characteristics.
    This is a prototype security analysis engine.
    """

    parsed = urlparse(url)

    domain = parsed.netloc
    scheme = parsed.scheme

    score = 0
    reasons = []

    # Remove username/password portion if present
    clean_domain = domain.split("@")[-1]

    # -----------------------------------
    # 1. HTTPS check
    # -----------------------------------

    if scheme != "https":
        score += 10
        reasons.append("URL does not use HTTPS.")

    # -----------------------------------
    # 2. IP address instead of domain
    # -----------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, clean_domain):
        score += 25
        reasons.append(
            "URL uses an IP address instead of a domain name."
        )

    # -----------------------------------
    # 3. @ symbol
    # -----------------------------------

    if "@" in url:
        score += 20
        reasons.append(
            "URL contains an @ symbol."
        )

    # -----------------------------------
    # 4. Very long URL
    # -----------------------------------

    if len(url) > 100:
        score += 10
        reasons.append(
            "URL is unusually long."
        )

    # -----------------------------------
    # 5. Suspicious keywords
    # -----------------------------------

    suspicious_words = [
        "login",
        "verify",
        "verification",
        "password",
        "account",
        "secure",
        "update",
        "confirm",
        "payment",
        "bank"
    ]

    found_words = []

    url_lower = url.lower()

    for word in suspicious_words:
        if word in url_lower:
            found_words.append(word)

    if found_words:
        score += min(len(found_words) * 5, 20)

        reasons.append(
            "Suspicious keywords found: "
            + ", ".join(found_words)
        )

    # -----------------------------------
    # 6. Final classification
    # -----------------------------------

    if score >= 50:
        classification = "HIGH RISK"

    elif score >= 25:
        classification = "SUSPICIOUS"

    else:
        classification = "LOW RISK"

    return {
        "url": url,
        "domain": clean_domain,
        "risk_score": min(score, 100),
        "classification": classification,
        "reasons": reasons
    }


def analyze_urls(urls):
    """
    Analyze multiple URLs.
    """

    results = []

    for url in urls:
        results.append(analyze_url(url))

    return results