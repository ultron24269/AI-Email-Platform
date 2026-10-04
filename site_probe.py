"""
Live website inspection: DNS, TLS certificate, HTTP redirects, HSTS, domain age.

Two safety rules apply to everything in this file:

1. SSRF guard. The platform is often hosted on a server, and the URLs it is
   asked to inspect come from strangers (an attacker chooses the links in a
   phishing email). A link such as https://192.168.0.1/ or https://localhost/
   must never make OUR server probe ITS OWN network. Every host is resolved
   first and refused if any address is private, loopback, link-local,
   multicast or reserved. `allow_private=True` exists only for the unit tests.

2. Passive by default. The certificate check performs a TLS handshake and
   reads the certificate; it never sends an HTTP request. Only the explicit
   "deep" URL scan follows redirects, and it never downloads a page body.
"""

import ipaddress
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

try:                                    # requests is only needed for deep scans
    import requests
except Exception:                       # pragma: no cover
    requests = None

USER_AGENT = "AI-Email-Threat-Platform/2.0 (+security-scanner; no-body-download)"


# --------------------------------------------------------------------------
# DNS + SSRF guard
# --------------------------------------------------------------------------

def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def resolve_host(host, port=443):
    """Return the list of unique IP strings for a host, or [] if it does not
    resolve."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def guard(host, port=443, allow_private=False):
    """Resolve + SSRF-check. Returns (ips, blocked_reason)."""
    ips = resolve_host(host, port)
    if not ips:
        return [], "no_dns"
    if not allow_private and not all(is_public_ip(ip) for ip in ips):
        return ips, "private_target"
    return ips, None


# --------------------------------------------------------------------------
# Certificate parsing
# --------------------------------------------------------------------------

def _utc(dt):
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cert_times(cert):
    try:
        return cert.not_valid_before_utc, cert.not_valid_after_utc
    except AttributeError:              # older cryptography releases
        return _utc(cert.not_valid_before), _utc(cert.not_valid_after)


def _attr(name, oid):
    try:
        vals = name.get_attributes_for_oid(oid)
        return vals[0].value if vals else None
    except Exception:
        return None


def host_matches(host, names):
    """RFC 6125-style match: exact, or a single left-most wildcard label."""
    host = host.lower().rstrip(".")
    for raw in names:
        n = raw.lower().rstrip(".")
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count("."):
            if host.split(".", 1)[1] == n[2:]:
                return True
    return False


def parse_certificate(der, host):
    cert = x509.load_der_x509_certificate(der)
    not_before, not_after = _cert_times(cert)
    now = datetime.now(timezone.utc)

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
        ip_sans = [str(i) for i in san_ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans, ip_sans = [], []

    subject_cn = _attr(cert.subject, NameOID.COMMON_NAME)
    names = list(sans) or ([subject_cn] if subject_cn else [])

    try:
        ipaddress.ip_address(host)
        hostname_ok = host in ip_sans
    except ValueError:
        hostname_ok = host_matches(host, names)

    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key_type, key_bits = "RSA", pk.key_size
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key_type, key_bits = "EC", pk.curve.key_size
    else:
        key_type, key_bits = type(pk).__name__.replace("PublicKey", ""), None

    try:
        sig_alg = cert.signature_hash_algorithm.name
    except Exception:
        sig_alg = None

    return {
        "subject_cn": subject_cn,
        "issuer_cn": _attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "sans": list(sans)[:25],
        "not_before": not_before.strftime("%Y-%m-%d"),
        "not_after": not_after.strftime("%Y-%m-%d"),
        "days_left": (not_after - now).days,
        "age_days": (now - not_before).days,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "self_signed": cert.issuer == cert.subject,
        "hostname_match": hostname_ok,
        "key_type": key_type,
        "key_bits": key_bits,
        "sig_alg": sig_alg,
        "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "serial": format(cert.serial_number, "x"),
    }


# --------------------------------------------------------------------------
# TLS handshake
# --------------------------------------------------------------------------

VERIFY_REASONS = {
    9: "not_yet_valid",
    10: "expired",
    18: "self_signed",
    19: "self_signed_chain",
    20: "untrusted_issuer",
    21: "untrusted_issuer",
    62: "hostname_mismatch",
}


def _handshake(ip, host, port, timeout, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:                            # let us read certs of legacy servers too
            ctx.minimum_version = ssl.TLSVersion.TLSv1
        except (ValueError, ssl.SSLError):
            pass
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return (tls.getpeercert(binary_form=True), tls.version(),
                    tls.cipher()[0] if tls.cipher() else None)


def check_certificate(host, port=443, timeout=5, allow_private=False):
    """
    Passive certificate check (TLS handshake only).

    Returns a dict. Key fields:
      reachable   - a TLS connection could be made at all
      blocked     - refused by the SSRF guard (private/internal address)
      trusted     - the certificate chains to a trusted root AND matches host
      reason      - why it is untrusted (expired, self_signed, hostname_mismatch,
                    untrusted_issuer, not_yet_valid, tls_old, ...)
      cert        - parsed certificate details (see parse_certificate)
    """
    out = {"host": host, "port": port, "reachable": False, "blocked": False,
           "dns_ok": True, "ips": [], "trusted": None, "reason": None,
           "tls_version": None, "cipher": None, "cert": None, "error": None}

    ips, problem = guard(host, port, allow_private)
    out["ips"] = ips
    if problem == "no_dns":
        out["dns_ok"] = False
        out["error"] = "The domain name does not resolve."
        return out
    if problem == "private_target":
        out["blocked"] = True
        out["error"] = "Refused: the address is private or internal."
        return out

    ip = ips[0]
    der = None
    try:
        der, out["tls_version"], out["cipher"] = _handshake(ip, host, port, timeout, True)
        out["reachable"] = True
        out["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        out["reachable"] = True
        out["trusted"] = False
        out["reason"] = VERIFY_REASONS.get(exc.verify_code, "untrusted_issuer")
        out["error"] = exc.verify_message or str(exc)
    except ssl.SSLError as exc:
        text = str(exc).upper()
        out["error"] = str(exc)
        if "PROTOCOL" in text or "VERSION" in text or "HANDSHAKE_FAILURE" in text:
            out["reachable"] = True
            out["trusted"] = False
            out["reason"] = "tls_old"
        else:
            out["reachable"] = True
            out["trusted"] = False
            out["reason"] = "tls_error"
    except (socket.timeout, TimeoutError, ConnectionError, OSError) as exc:
        out["error"] = f"Could not connect on port {port}: {exc}"
        return out

    if der is None and out["reachable"]:
        try:                            # read the cert we refused, for the report
            der, out["tls_version"], out["cipher"] = _handshake(ip, host, port, timeout, False)
        except Exception as exc:
            out["error"] = out["error"] or str(exc)

    if der:
        try:
            out["cert"] = parse_certificate(der, host)
        except Exception as exc:        # malformed certificate is itself notable
            out["error"] = f"Certificate could not be parsed: {exc}"

    c = out["cert"]
    if c and out["trusted"] is False and out["reason"] in (None, "untrusted_issuer", "tls_error"):
        # sharpen the reason from the certificate itself
        if c["expired"]:
            out["reason"] = "expired"
        elif c["not_yet_valid"]:
            out["reason"] = "not_yet_valid"
        elif c["self_signed"]:
            out["reason"] = "self_signed"
        elif not c["hostname_match"]:
            out["reason"] = "hostname_mismatch"
    return out


# --------------------------------------------------------------------------
# HTTP behaviour (deep scan only; never downloads a body)
# --------------------------------------------------------------------------

def probe_http(url, allow_private=False, max_hops=5, timeout=6):
    """
    Follow redirects manually (so every hop is SSRF-checked) and report the
    chain and whether the final HTTPS site sends HSTS.
    """
    result = {"hops": [], "final_url": url, "hsts": None, "error": None,
              "blocked": False}
    if requests is None:
        result["error"] = "requests library not installed"
        return result

    current = url
    for _ in range(max_hops + 1):
        p = urlparse(current)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "https" else 80)
        ips, problem = guard(host, port, allow_private)
        if problem == "private_target":
            result["blocked"] = True
            result["error"] = "A redirect points to a private/internal address."
            return result
        if problem == "no_dns":
            result["error"] = "The domain name does not resolve."
            return result
        try:
            resp = requests.get(current, allow_redirects=False, stream=True,
                                timeout=timeout, headers={"User-Agent": USER_AGENT})
        except requests.exceptions.SSLError as exc:
            result["error"] = f"TLS error: {exc}"
            return result
        except requests.exceptions.RequestException as exc:
            result["error"] = str(exc)
            return result
        try:
            status = resp.status_code
            location = resp.headers.get("Location")
            hsts = "strict-transport-security" in {k.lower() for k in resp.headers}
        finally:
            resp.close()                # never read the body
        result["hops"].append({"url": current, "status": status,
                               "location": location})
        result["final_url"] = current
        if p.scheme == "https":
            result["hsts"] = hsts
        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        break
    return result


# --------------------------------------------------------------------------
# Domain age (RDAP). Best effort: unknown is NOT treated as suspicious.
# --------------------------------------------------------------------------

def domain_age_days(registrable, timeout=4):
    if requests is None or not registrable or "." not in registrable:
        return None
    try:
        r = requests.get(f"https://rdap.org/domain/{registrable}", timeout=timeout,
                         headers={"Accept": "application/rdap+json",
                                  "User-Agent": USER_AGENT})
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                when = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return (datetime.now(timezone.utc) - _utc(when)).days
    except Exception:
        return None
    return None
