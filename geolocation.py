import ipaddress
import re
import requests


def extract_ip_addresses(headers):
    """
    Extract IPv4 addresses from email headers.
    """

    ip_addresses = []

    for header, values in headers.items():

        for value in values:

            found_ips = re.findall(
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                value
            )

            for ip in found_ips:

                try:
                    ip_obj = ipaddress.ip_address(ip)

                    if ip_obj.version == 4:
                        ip_addresses.append(ip)

                except ValueError:
                    pass

    return list(dict.fromkeys(ip_addresses))


def get_ip_location(ip):
    """
    Get IP geolocation.

    Private, loopback and reserved/test IPs
    are handled locally.

    Public IPs are looked up using ipapi.co.
    """

    try:

        ip_obj = ipaddress.ip_address(ip)

        # ==========================================
        # PRIVATE IP
        # ==========================================

        if ip_obj.is_private:

            return {
                "ip": ip,
                "status": "PRIVATE",
                "country": "Local Network",
                "city": "Not Available",
                "region": "Not Available",
                "latitude": "Not Available",
                "longitude": "Not Available",
                "timezone": "Not Available",
                "organization": "Private Network",
                "asn": "Not Available"
            }

        # ==========================================
        # LOOPBACK IP
        # ==========================================

        if ip_obj.is_loopback:

            return {
                "ip": ip,
                "status": "LOOPBACK",
                "country": "Localhost",
                "city": "Not Available",
                "region": "Not Available",
                "latitude": "Not Available",
                "longitude": "Not Available",
                "timezone": "Not Available",
                "organization": "Local Machine",
                "asn": "Not Available"
            }

        # ==========================================
        # RESERVED / TEST IP
        # ==========================================

        if ip_obj.is_reserved:

            return {
                "ip": ip,
                "status": "RESERVED / TEST",
                "country": "Not Available",
                "city": "Not Available",
                "region": "Not Available",
                "latitude": "Not Available",
                "longitude": "Not Available",
                "timezone": "Not Available",
                "organization": "Documentation/Test Network",
                "asn": "Not Available"
            }

        # ==========================================
        # PUBLIC IP GEOLOCATION
        # ==========================================

        api_url = f"https://ipapi.co/{ip}/json/"

        response = requests.get(
            api_url,
            timeout=5
        )

        response.raise_for_status()

        data = response.json()

        # ==========================================
        # API ERROR
        # ==========================================

        if data.get("error"):

            return {
                "ip": ip,
                "status": "LOOKUP FAILED",
                "country": "Not Available",
                "city": "Not Available",
                "region": "Not Available",
                "latitude": "Not Available",
                "longitude": "Not Available",
                "timezone": "Not Available",
                "organization": "Not Available",
                "asn": "Not Available"
            }

        # ==========================================
        # PUBLIC IP RESULT
        # ==========================================

        return {
            "ip": ip,
            "status": "PUBLIC",
            "country": data.get(
                "country_name",
                "Not Available"
            ),
            "city": data.get(
                "city",
                "Not Available"
            ),
            "region": data.get(
                "region",
                "Not Available"
            ),
            "latitude": data.get(
                "latitude",
                "Not Available"
            ),
            "longitude": data.get(
                "longitude",
                "Not Available"
            ),
            "timezone": data.get(
                "timezone",
                "Not Available"
            ),
            "organization": data.get(
                "org",
                "Not Available"
            ),
            "asn": data.get(
                "asn",
                "Not Available"
            )
        }

    # ==============================================
    # INTERNET / API ERROR
    # ==============================================

    except requests.exceptions.RequestException as error:

        return {
            "ip": ip,
            "status": "API ERROR",
            "country": "Not Available",
            "city": "Not Available",
            "region": "Not Available",
            "latitude": "Not Available",
            "longitude": "Not Available",
            "timezone": "Not Available",
            "organization": str(error),
            "asn": "Not Available"
        }

    # ==============================================
    # INVALID IP
    # ==============================================

    except ValueError:

        return {
            "ip": ip,
            "status": "INVALID",
            "country": "Not Available",
            "city": "Not Available",
            "region": "Not Available",
            "latitude": "Not Available",
            "longitude": "Not Available",
            "timezone": "Not Available",
            "organization": "Not Available",
            "asn": "Not Available"
        }


def analyze_ips(headers):
    """
    Extract and analyze IP addresses from
    email headers.
    """

    ips = extract_ip_addresses(headers)

    results = []

    for ip in ips:

        results.append(
            get_ip_location(ip)
        )

    return results