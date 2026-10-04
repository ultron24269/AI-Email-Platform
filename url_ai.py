"""
URL intelligence.

Used in two places:
  * the "Link & certificate check" page (deep=True: certificate, redirects,
    HSTS, domain age, ML model, optional VirusTotal), and
  * every link found inside an email (passive: structure + TLS handshake only).

Everything returns language-neutral findings (see findings.py).
"""

import ipaddress
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from . import site_probe
from .findings import dedupe, fuse, group_status, make, verdict_for
from .knowledge import (BRANDS, HOMOGLYPHS, SECOND_LEVEL_SUFFIXES,
                        SUSPICIOUS_TLDS, URL_SHORTENERS)

SUSPICIOUS_WORDS = {
    "login", "signin", "log-in", "verify", "verification", "secure", "security",
    "account", "accounts", "update", "confirm", "support", "service", "services",
    "helpdesk", "help", "care", "customer", "online", "bank", "banking", "pay",
    "payment", "wallet", "kyc", "otp", "alert", "portal", "official", "auth",
    "reward", "refund", "claim", "unlock", "recover", "billing", "invoice",
}
URL_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update",
                "confirm", "banking", "password", "wallet", "kyc", "otp",
                "payment", "suspend", "unlock", "recover"]


# --------------------------------------------------------------------------
# Domain helpers
# --------------------------------------------------------------------------

def normalise_url(url):
    url = (url or "").strip()
    if url and not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "http://" + url
    return url


def registrable(host):
    """example.co.in -> example.co.in ; a.b.example.com -> example.com"""
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _label_variants(label):
    """A label with hyphens removed, plus its de-homoglyphed variants
    ('paypa1' -> 'paypal', '1nstagram' -> 'instagram')."""
    base = label.lower().replace("-", "")
    variants = {base}
    for src, dst in HOMOGLYPHS:
        if src in base:
            variants.add(base.replace(src, dst))
    if "1" in base:
        variants.add(base.replace("1", "i"))
    # one more round so 'rnicr0soft' -> 'microsoft'
    extra = set()
    for v in variants:
        for src, dst in HOMOGLYPHS:
            if src in v:
                extra.add(v.replace(src, dst))
    return variants | extra


def _distance(a, b):
    """Levenshtein distance (short strings only)."""
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(host, brand=None):
    """Does this host belong to a known brand (or to the named brand)?"""
    reg = registrable(host)
    infos = [BRANDS[brand]] if brand else BRANDS.values()
    for info in infos:
        for d in info["domains"]:
            if reg == d or host == d or host.endswith("." + d):
                return True
    return False


def check_brand(host):
    """
    Is this host pretending to be a known brand?
    Returns None (fine / unrelated) or {'kind': 'lookalike'|'subdomain', 'brand': str}
    """
    host = (host or "").lower().strip(".")
    if not host or is_official(host):
        return None
    reg = registrable(host)
    sld = reg.split(".")[0]
    sub_labels = host[: -len(reg)].strip(".").split(".") if host != reg else []
    parts = [p for p in re.split(r"[-_]+", sld) if p]
    variants = _label_variants(sld)

    for brand, info in BRANDS.items():
        for token in info["tokens"]:
            # brand name placed in front of an unrelated domain:
            # paypal.com.secure-login.xyz
            for lab in sub_labels:
                if token in _label_variants(lab) and len(sub_labels) >= 1:
                    return {"kind": "subdomain", "brand": brand}

            # 1) the domain IS the brand name but on the wrong domain (paypal.xyz)
            if sld == token:
                return {"kind": "lookalike", "brand": brand}
            # 2) brand + suspicious word, hyphen separated (sbi-kyc-update.com)
            if token in parts and (
                    len(parts) == 1 or any(p in SUSPICIOUS_WORDS for p in parts if p != token)):
                return {"kind": "lookalike", "brand": brand}
            # 3) swapped characters (paypa1, rnicrosoft, g00gle)
            if token in variants and sld.replace("-", "") != token:
                return {"kind": "lookalike", "brand": brand}
            if len(token) >= 5:
                for v in variants:
                    # 4) one typo away (amazom, netfliix)
                    if v != token and _distance(v, token) == 1 and abs(len(v) - len(token)) <= 1:
                        return {"kind": "lookalike", "brand": brand}
                    # 5) brand glued to a scam word (paypalsecure, loginpaypal)
                    if token in v and v != token:
                        rest = v.replace(token, "")
                        if rest and any(rest == w or rest.startswith(w) or rest.endswith(w)
                                        for w in SUSPICIOUS_WORDS):
                            return {"kind": "lookalike", "brand": brand}
    return None


# --------------------------------------------------------------------------
# Structure-only findings (no network)
# --------------------------------------------------------------------------

def _short(url, n=80):
    return url if len(url) <= n else url[: n - 1] + "…"


def static_findings(url, display_text=None):
    url = normalise_url(url)
    findings = []
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return [make("link_keywords", evidence=[url], url=_short(url), words="?")]
    ev = [url]
    base = {"url": _short(url), "host": host}

    if "@" in p.netloc:
        findings.append(make("link_at_symbol", ev, **base))

    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host):   # 0x7f000001 / 3232235777
            is_ip = True
    if is_ip:
        findings.append(make("link_ip_host", ev, **base))

    if "xn--" in host or any(ord(c) > 127 for c in host):
        findings.append(make("link_punycode", ev, **base))

    reg = registrable(host)
    if reg in URL_SHORTENERS:
        findings.append(make("link_shortener", ev, **base))
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(make("link_suspicious_tld", ev, tld=tld, **base))
    if p.scheme == "http":
        findings.append(make("link_no_https", ev, **base))
    if port not in (None, 80, 443):
        findings.append(make("link_odd_port", ev, port=port, **base))
    if len(url) > 100:
        findings.append(make("link_long", ev, length=len(url), **base))
    if not is_ip and host.count(".") - reg.count(".") >= 3:
        findings.append(make("link_many_subdomains", ev, **base))
    if any(l.count("-") >= 3 for l in host.split(".")):
        findings.append(make("link_hyphens", ev, **base))

    hay = (host + p.path).lower()
    hit = [w for w in URL_KEYWORDS if w in hay]
    if len(hit) >= 2 and not is_official(host):
        findings.append(make("link_keywords", ev, words=", ".join(hit[:4]), **base))

    brand = None if is_ip else check_brand(host)
    if brand:
        fid = "link_brand_subdomain" if brand["kind"] == "subdomain" else "link_brand_lookalike"
        findings.append(make(fid, ev, brand=brand["brand"], **base))

    # visible text says one place, the href goes somewhere else
    if display_text:
        m = re.search(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})", display_text.lower())
        if m:
            shown = urlparse(normalise_url(m.group(1))).hostname or ""
            if shown and registrable(shown) != reg:
                findings.append(make("link_mismatch", [f"{display_text}  →  {url}"],
                                     shown=shown, **base))
    return findings


# --------------------------------------------------------------------------
# Certificate / site findings
# --------------------------------------------------------------------------

def cert_findings(host, res):
    """Translate a site_probe.check_certificate() result into findings."""
    out = []
    base = {"host": host}
    if res.get("blocked"):
        return [make("site_blocked", [res.get("error") or ""], **base)]
    if not res.get("dns_ok", True):
        return [make("site_no_dns", [host], **base)]
    if not res.get("reachable"):
        return [make("site_unreachable", [res.get("error") or ""], **base)]

    c = res.get("cert") or {}
    reason = res.get("reason")
    ev = [f"{c.get('issuer_org') or c.get('issuer_cn') or '?'}  ·  "
          f"{c.get('not_before', '?')} → {c.get('not_after', '?')}"] if c else []
    p = {"host": host, "date": c.get("not_after", "?"), "days": abs(c.get("days_left", 0) or 0),
         "issuer": c.get("issuer_org") or c.get("issuer_cn") or "?",
         "names": ", ".join((c.get("sans") or [c.get("subject_cn") or "?"])[:3])}

    if res.get("trusted") is False:
        if reason == "expired":
            out.append(make("site_cert_expired", ev, **p))
        elif reason == "not_yet_valid":
            out.append(make("site_cert_not_yet_valid", ev, **{**p, "date": c.get("not_before", "?")}))
        elif reason in ("self_signed", "self_signed_chain"):
            out.append(make("site_cert_self_signed", ev, **p))
        elif reason == "hostname_mismatch":
            out.append(make("site_cert_hostname_mismatch", ev, **p))
        elif reason == "tls_old":
            out.append(make("site_tls_old", [res.get("error") or ""], version="TLS 1.0/1.1", **base))
        else:
            out.append(make("site_cert_untrusted", ev or [res.get("error") or ""], **p))

    if c:
        weak = (c.get("key_type") == "RSA" and (c.get("key_bits") or 4096) < 2048) \
            or c.get("sig_alg") in ("md5", "sha1")
        if weak:
            out.append(make("site_cert_weak", [f"{c.get('key_type')} {c.get('key_bits')} / {c.get('sig_alg')}"], **p))
        if res.get("trusted") and c.get("age_days") is not None and c["age_days"] <= 7:
            out.append(make("site_cert_fresh", ev, days=c["age_days"], **base))
        if res.get("trusted") and 0 <= (c.get("days_left") or 0) <= 14:
            out.append(make("site_cert_expiring", ev, days=c["days_left"], **base))
    if res.get("tls_version") in ("TLSv1", "TLSv1.1"):
        out.append(make("site_tls_old", [res["tls_version"]], version=res["tls_version"], **base))

    if res.get("trusted") and c and not any(f["weight"] >= 0.3 for f in out):
        out.append(make("pos_cert_valid", ev, **p))
    return out


# --------------------------------------------------------------------------
# ML model (optional signal)
# --------------------------------------------------------------------------

def ml_probability(url, host, cert_res=None, http_res=None, dns_ok=True):
    """Phishing probability (%) from the bundled Random Forest, or None if the
    model cannot be loaded. Unknown network facts default to 'benign' so a
    missing measurement never raises the score."""
    try:
        from models.url_phishing_model import predict_url
    except Exception:
        return None
    p = urlparse(url)
    c = (cert_res or {}).get("cert") or {}
    reg = registrable(host)
    feats = {
        "url_length": len(url), "domain_length": len(host), "path_length": len(p.path),
        "subdomain_count": max(0, host.count(".") - reg.count(".")),
        "has_https": int(p.scheme == "https"),
        "has_ip_address": int(bool(re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host))),
        "has_at_symbol": int("@" in p.netloc),
        "has_dash_in_domain": int("-" in host),
        "has_suspicious_keyword": int(any(w in (host + p.path).lower() for w in URL_KEYWORDS)),
        "has_punycode": int("xn--" in host),
        "has_port": int(p.port not in (None, 80, 443)),
        "certificate_valid": int((cert_res or {}).get("trusted", True) is not False),
        "certificate_expired": int(bool(c.get("expired"))),
        "hostname_match": int(c.get("hostname_match", True)),
        "certificate_days_remaining": c.get("days_left", 180),
        "redirect_count": max(0, len((http_res or {}).get("hops", [])) - 1),
        "dns_available": int(dns_ok),
    }
    try:
        return predict_url(feats)["phishing_probability"]
    except Exception:
        return None


# --------------------------------------------------------------------------
# Full assessment of one URL
# --------------------------------------------------------------------------

def assess_url(url, *, display_text=None, cert=True, deep=False, allow_private=False,
               use_ml=True, use_vt=False, cert_cache=None):
    """
    Assess one URL.

    cert  : perform the passive TLS certificate check (https only)
    deep  : additionally follow redirects (SSRF-checked), read HSTS, look up
            domain age via RDAP. Used only when the user asked to scan the URL.
    """
    url = normalise_url(url)
    p = urlparse(url)
    host = (p.hostname or "").lower()
    findings = static_findings(url, display_text)
    ran = {"links"}
    cert_res = http_res = age = ml = vt = None
    dns_ok = True

    if p.scheme == "https" and host and cert:
        ran.add("site")
        port = p.port or 443
        key = (host, port)
        if cert_cache is not None and key in cert_cache:
            cert_res = cert_cache[key]
        else:
            cert_res = site_probe.check_certificate(host, port, allow_private=allow_private)
            if cert_cache is not None:
                cert_cache[key] = cert_res
        dns_ok = cert_res.get("dns_ok", True)
        findings += cert_findings(host, cert_res)
    elif p.scheme == "http" and host and deep:
        ran.add("site")
        ips, problem = site_probe.guard(host, 80, allow_private)
        dns_ok = problem != "no_dns"
        if problem == "no_dns":
            findings.append(make("site_no_dns", [host], host=host))

    if deep and host and (cert_res is None or not cert_res.get("blocked")):
        ran.add("site")
        http_res = site_probe.probe_http(url, allow_private=allow_private)
        hops = http_res["hops"]
        if len(hops) >= 4:
            findings.append(make("site_redirect_long", [h["url"] for h in hops], hops=len(hops), host=host))
        final_host = (urlparse(http_res["final_url"]).hostname or "").lower()
        if final_host and registrable(final_host) != registrable(host):
            findings.append(make("site_redirect_cross", [http_res["final_url"]],
                                 host=host, final=final_host))
        if http_res.get("hsts"):
            findings.append(make("pos_hsts", [], host=host))

        age = site_probe.domain_age_days(registrable(host))
        if age is not None:
            if age < 30:
                findings.append(make("site_domain_new", [registrable(host)], days=age, host=host))
            elif age < 180:
                findings.append(make("site_domain_young", [registrable(host)], days=age, host=host))
            elif age > 730:
                findings.append(make("pos_domain_established", [registrable(host)],
                                     years=round(age / 365, 1), host=host))

    if use_ml and deep:
        ml = ml_probability(url, host, cert_res, http_res, dns_ok)
        if ml is not None and ml >= 80:
            findings.append(make("site_ml_high", [f"{ml}%"], prob=int(ml)))

    if use_vt and deep:
        try:
            from .threat_intel import analyze_indicator
            vt = analyze_indicator(url)
            if vt.get("risk") == "HIGH":
                findings.append(make("site_vt_malicious", [vt.get("reason", "")],
                                     count=vt.get("malicious", "?"), host=host))
            elif vt.get("risk") == "MEDIUM":
                findings.append(make("site_vt_suspicious", [vt.get("reason", "")], host=host))
        except Exception:
            vt = None

    if not any(f["weight"] > 0 for f in findings) and p.scheme == "https":
        findings.append(make("pos_https", [url], host=host))

    findings = dedupe(findings)
    risky = [f for f in findings if f["weight"] > 0]
    score = fuse(risky)
    return {
        "url": url, "host": host, "registrable": registrable(host), "scheme": p.scheme,
        "findings": sorted(findings, key=lambda f: -f["weight"]),
        "score": score, "verdict": verdict_for(score),
        "groups": group_status(findings, ran),
        "cert": cert_res, "http": http_res, "domain_age_days": age,
        "ml_probability": ml, "vt": vt, "deep": deep,
    }


def prefetch_certs(urls, allow_private=False, max_hosts=6, workers=4):
    """Run the passive TLS check for the distinct https hosts of many links at
    once. Returns {(host, port): result} to pass as `cert_cache`."""
    targets = []
    for u in urls:
        p = urlparse(normalise_url(u))
        if p.scheme == "https" and p.hostname:
            key = (p.hostname.lower(), p.port or 443)
            if key not in targets:
                targets.append(key)
    targets = targets[:max_hosts]
    cache = {}
    if not targets:
        return cache
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {k: pool.submit(site_probe.check_certificate, k[0], k[1],
                                  4, allow_private) for k in targets}
        for k, fut in futures.items():
            try:
                cache[k] = fut.result(timeout=12)
            except Exception:
                cache[k] = {"host": k[0], "reachable": False, "dns_ok": True,
                            "blocked": False, "error": "timeout"}
    return cache
