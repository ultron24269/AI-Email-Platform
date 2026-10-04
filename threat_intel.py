import os
import ipaddress
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv


# Load variables from .env
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY"
)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def analyze_with_virustotal(indicator):
    """
    Check an IP address, domain, or URL
    using VirusTotal API v3.
    """

    if not VIRUSTOTAL_API_KEY:
        return {
            "indicator": indicator,
            "type": "Unknown",
            "risk": "ERROR",
            "score": 0,
            "reason": "VirusTotal API key not configured."
        }

    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    indicator = indicator.strip()

    # ==========================================
    # DETERMINE INDICATOR TYPE
    # ==========================================

    try:
        ipaddress.ip_address(indicator)
        indicator_type = "IP Address"
        endpoint = f"{VT_BASE_URL}/ip/{indicator}"

    except ValueError:

        if indicator.startswith(
            ("http://", "https://")
        ):
            parsed = urlparse(indicator)
            domain = parsed.netloc.split("@")[-1]
            domain = domain.split(":")[0]

            indicator_type = "URL"
            endpoint = f"{VT_BASE_URL}/domains/{domain}"

        else:
            indicator_type = "Domain"
            endpoint = f"{VT_BASE_URL}/domains/{indicator}"

    # ==========================================
    # API REQUEST
    # ==========================================

    try:

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=10
        )

        # --------------------------------------
        # NOT FOUND
        # --------------------------------------

        if response.status_code == 404:

            return {
                "indicator": indicator,
                "type": indicator_type,
                "risk": "UNKNOWN",
                "score": 0,
                "reason": "Indicator not found in VirusTotal."
            }

        # --------------------------------------
        # RATE LIMIT
        # --------------------------------------

        if response.status_code == 429:

            return {
                "indicator": indicator,
                "type": indicator_type,
                "risk": "RATE LIMITED",
                "score": 0,
                "reason": "VirusTotal API rate limit reached."
            }

        # --------------------------------------
        # AUTHENTICATION ERROR
        # --------------------------------------

        if response.status_code in [401, 403]:

            return {
                "indicator": indicator,
                "type": indicator_type,
                "risk": "API ERROR",
                "score": 0,
                "reason": "VirusTotal API key is invalid or unavailable."
            }

        response.raise_for_status()

        data = response.json()

        attributes = data.get(
            "data",
            {}
        ).get(
            "attributes",
            {}
        )

        # ======================================
        # REPUTATION
        # ======================================

        reputation = attributes.get(
            "reputation",
            0
        )

        # ======================================
        # LAST ANALYSIS STATISTICS
        # ======================================

        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious = stats.get(
            "malicious",
            0
        )

        suspicious = stats.get(
            "suspicious",
            0
        )

        harmless = stats.get(
            "harmless",
            0
        )

        undetected = stats.get(
            "undetected",
            0
        )

        total_engines = (
            malicious
            + suspicious
            + harmless
            + undetected
        )

        # ======================================
        # CALCULATE PROJECT RISK SCORE
        # ======================================

        if malicious >= 3:

            risk = "HIGH"

            score = min(
                100,
                70 + malicious * 3
            )

            reason = (
                f"{malicious} security engine(s) "
                "flagged this indicator as malicious."
            )

        elif malicious > 0 or suspicious > 0:

            risk = "MEDIUM"

            score = min(
                100,
                40
                + malicious * 10
                + suspicious * 5
            )

            reason = (
                f"VirusTotal detected "
                f"{malicious} malicious and "
                f"{suspicious} suspicious result(s)."
            )

        else:

            risk = "LOW"

            score = 10

            reason = (
                "No malicious or suspicious "
                "detections reported."
            )

        # ======================================
        # RETURN RESULT
        # ======================================

        return {
            "indicator": indicator,
            "type": indicator_type,
            "risk": risk,
            "score": score,
            "reason": reason,
            "reputation": reputation,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total_engines": total_engines
        }

    except requests.exceptions.RequestException as error:

        return {
            "indicator": indicator,
            "type": indicator_type,
            "risk": "API ERROR",
            "score": 0,
            "reason": str(error)
        }

    except Exception as error:

        return {
            "indicator": indicator,
            "type": indicator_type,
            "risk": "ERROR",
            "score": 0,
            "reason": str(error)
        }


def analyze_indicator(indicator):
    """
    Analyze an indicator using VirusTotal.
    """

    indicator = indicator.strip()

    if not indicator:

        return {
            "indicator": "",
            "type": "Unknown",
            "risk": "LOW",
            "score": 0,
            "reason": "Empty indicator."
        }

    return analyze_with_virustotal(
        indicator
    )


def analyze_indicators(indicators):
    """
    Analyze multiple indicators.
    """

    results = []

    for indicator in indicators:

        if indicator.strip():

            results.append(
                analyze_indicator(
                    indicator
                )
            )

    return results
    