import re


def detect_threat(email_data):
    """
    Prototype email threat detection engine.
    Calculates a risk score using multiple suspicious indicators.
    """

    score = 0
    reasons = []

    subject = email_data.get("subject", "").lower()
    body = email_data.get("body", "").lower()
    sender = email_data.get("sender", "").lower()
    urls = email_data.get("urls", [])
    headers = email_data.get("headers", {})

    text = subject + " " + body

    # ==========================================
    # 1. Suspicious Keywords
    # ==========================================

    suspicious_keywords = [
        "urgent",
        "verify your account",
        "verify account",
        "password",
        "login",
        "suspended",
        "click here",
        "confirm your account",
        "security alert",
        "immediately",
        "payment required",
        "account blocked"
    ]

    found_keywords = []

    for keyword in suspicious_keywords:
        if keyword in text:
            found_keywords.append(keyword)

    if found_keywords:
        score += min(len(found_keywords) * 5, 30)

        reasons.append(
            "Suspicious keywords detected: "
            + ", ".join(found_keywords)
        )

    # ==========================================
    # 2. URL Detection
    # ==========================================

    if len(urls) > 0:

        score += 15

        reasons.append(
            f"{len(urls)} URL(s) detected in the email."
        )

    # ==========================================
    # 3. IP Address in URL
    # ==========================================

    ip_url_found = False

    for url in urls:

        if re.search(
            r"https?://(?:\d{1,3}\.){3}\d{1,3}",
            url
        ):

            ip_url_found = True
            break

    if ip_url_found:

        score += 20

        reasons.append(
            "URL contains a direct IP address."
        )

    # ==========================================
    # 4. SPF Authentication
    # ==========================================

    auth_results = headers.get(
        "Authentication-Results",
        []
    )

    auth_text = " ".join(
        auth_results
    ).lower()

    if "spf=fail" in auth_text:

        score += 15

        reasons.append(
            "SPF authentication failed."
        )

    # ==========================================
    # 5. DKIM Authentication
    # ==========================================

    if "dkim=fail" in auth_text:

        score += 15

        reasons.append(
            "DKIM authentication failed."
        )

    # ==========================================
    # 6. DMARC Authentication
    # ==========================================

    if "dmarc=fail" in auth_text:

        score += 15

        reasons.append(
            "DMARC authentication failed."
        )

    # ==========================================
    # 7. Reply-To Mismatch
    # ==========================================

    reply_to = email_data.get(
        "reply_to",
        ""
    ).lower()

    if reply_to and sender:

        sender_domain = re.findall(
            r"@([a-zA-Z0-9.-]+)",
            sender
        )

        reply_domain = re.findall(
            r"@([a-zA-Z0-9.-]+)",
            reply_to
        )

        if sender_domain and reply_domain:

            if sender_domain[0] != reply_domain[0]:

                score += 20

                reasons.append(
                    "Sender domain and Reply-To "
                    "domain do not match."
                )

    # ==========================================
    # Final Classification
    # ==========================================

    score = min(score, 100)

    if score >= 70:

        classification = "MALICIOUS"
        risk_level = "HIGH"

    elif score >= 40:

        classification = "SUSPICIOUS"
        risk_level = "MEDIUM"

    else:

        classification = "SAFE"
        risk_level = "LOW"

    # ==========================================
    # Return Result
    # ==========================================

    return {
        "risk_score": score,
        "classification": classification,
        "risk_level": risk_level,
        "reasons": reasons
    }