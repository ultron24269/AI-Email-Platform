from datetime import datetime


def build_forensic_timeline(email_data, ip_results, threat_result):
    """
    Build a digital forensic investigation timeline
    from the analyzed email evidence.
    """

    timeline = []

    # ==========================================
    # EMAIL DATE
    # ==========================================

    email_date = email_data.get(
        "date",
        "Unknown"
    )

    timeline.append({
        "event": "Email Received",
        "timestamp": email_date,
        "evidence": (
            "Email date extracted from message headers."
        )
    })

    # ==========================================
    # SENDER
    # ==========================================

    sender = email_data.get(
        "sender",
        "Unknown"
    )

    timeline.append({
        "event": "Sender Identified",
        "timestamp": email_date,
        "evidence": sender
    })

    # ==========================================
    # REPLY-TO
    # ==========================================

    reply_to = email_data.get(
        "reply_to",
        "Not Available"
    )

    if reply_to != "Not Available":

        timeline.append({
            "event": "Reply-To Identified",
            "timestamp": email_date,
            "evidence": reply_to
        })

    # ==========================================
    # URL EVIDENCE
    # ==========================================

    urls = email_data.get(
        "urls",
        []
    )

    for url in urls:

        timeline.append({
            "event": "URL Extracted",
            "timestamp": email_date,
            "evidence": url
        })

    # ==========================================
    # IP EVIDENCE
    # ==========================================

    for ip_result in ip_results:

        timeline.append({
            "event": "IP Address Extracted",
            "timestamp": email_date,
            "evidence": (
                f"{ip_result['ip']} "
                f"({ip_result['status']})"
            )
        })

    # ==========================================
    # AUTHENTICATION RESULTS
    # ==========================================

    headers = email_data.get(
        "headers",
        {}
    )

    auth_results = headers.get(
        "Authentication-Results",
        []
    )

    for auth in auth_results:

        timeline.append({
            "event": "Authentication Result",
            "timestamp": email_date,
            "evidence": auth
        })

    # ==========================================
    # THREAT CLASSIFICATION
    # ==========================================

    timeline.append({
        "event": "Threat Analysis Completed",
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "evidence": (
            f"{threat_result['classification']} | "
            f"Risk Score: "
            f"{threat_result['risk_score']}/100"
        )
    })

    return timeline