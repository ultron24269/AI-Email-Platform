"""
The vocabulary of the AI engine.

Every reason the platform can give for a verdict is a *finding*. A finding is
language-neutral: it carries an id, a weight and parameters. The words users
read come from modules/i18n.py, so one analysis can be shown in English, Tamil
or Hindi (and the language can be switched after the fact).

Scoring uses "noisy-OR" evidence fusion:

    risk = 1 - (1 - w1) * (1 - w2) * ... * (1 - wn)

Each weight is the probability that this signal, on its own, points to a
malicious message. Independent weak signals add up (three 0.2s -> 0.49), a
single strong signal dominates (0.7 stays >= 0.7), and the result can never
exceed 1.0. Because every weight is visible, every point of the score can be
traced to a reason a human can read.
"""

# id -> (group, weight)
CATALOG = {
    # ---- sender authentication -------------------------------------------
    "auth_spf_fail":          ("auth", 0.28),
    "auth_spf_softfail":      ("auth", 0.14),
    "auth_dkim_fail":         ("auth", 0.25),
    "auth_dmarc_fail":        ("auth", 0.30),
    "auth_missing":           ("auth", 0.06),

    # ---- sender identity -------------------------------------------------
    "sender_reply_mismatch":       ("sender", 0.30),
    "sender_returnpath_mismatch":  ("sender", 0.12),
    "sender_display_spoof":        ("sender", 0.50),
    "sender_lookalike":            ("sender", 0.60),
    "sender_display_email":        ("sender", 0.45),
    "sender_missing":              ("sender", 0.20),
    "date_anomaly":                ("sender", 0.08),

    # ---- message content -------------------------------------------------
    "content_urgency":        ("content", 0.12),
    "content_credentials":    ("content", 0.30),
    "content_otp_request":    ("content", 0.50),
    "content_financial":      ("content", 0.14),
    "content_threat":         ("content", 0.25),
    "content_prize":          ("content", 0.35),
    "content_govt_scam":      ("content", 0.40),
    "content_utility_scam":   ("content", 0.35),
    "content_gift_crypto":    ("content", 0.35),
    "content_generic_greeting": ("content", 0.10),
    "content_shouting":       ("content", 0.08),

    # ---- link structure --------------------------------------------------
    "link_mismatch":          ("links", 0.50),
    "link_ip_host":           ("links", 0.45),
    "link_punycode":          ("links", 0.35),
    "link_brand_lookalike":   ("links", 0.55),
    "link_brand_subdomain":   ("links", 0.50),
    "link_shortener":         ("links", 0.20),
    "link_no_https":          ("links", 0.14),
    "link_suspicious_tld":    ("links", 0.18),
    "link_at_symbol":         ("links", 0.40),
    "link_long":              ("links", 0.08),
    "link_many_subdomains":   ("links", 0.12),
    "link_hyphens":           ("links", 0.10),
    "link_keywords":          ("links", 0.12),
    "link_odd_port":          ("links", 0.15),

    # ---- website & certificate -------------------------------------------
    "site_cert_expired":            ("site", 0.55),
    "site_cert_not_yet_valid":      ("site", 0.45),
    "site_cert_self_signed":        ("site", 0.50),
    "site_cert_untrusted":          ("site", 0.45),
    "site_cert_hostname_mismatch":  ("site", 0.55),
    "site_cert_weak":               ("site", 0.30),
    "site_cert_fresh":              ("site", 0.14),
    "site_cert_expiring":           ("site", 0.08),
    "site_tls_old":                 ("site", 0.20),
    "site_no_dns":                  ("site", 0.35),
    "site_unreachable":             ("site", 0.12),
    "site_domain_new":              ("site", 0.45),
    "site_domain_young":            ("site", 0.14),
    "site_redirect_long":           ("site", 0.18),
    "site_redirect_cross":          ("site", 0.22),
    "site_blocked":                 ("site", 0.00),   # informational
    "site_vt_malicious":            ("site", 0.70),
    "site_vt_suspicious":           ("site", 0.30),
    "site_ml_high":                 ("site", 0.20),

    # ---- attachments -----------------------------------------------------
    "attach_executable":      ("attachments", 0.70),
    "attach_double_ext":      ("attachments", 0.75),
    "attach_macro":           ("attachments", 0.45),
    "attach_archive":         ("attachments", 0.22),
    "attach_webpage":         ("attachments", 0.40),

    # ---- page code inside the email --------------------------------------
    "html_form":              ("html", 0.45),
    "html_script":            ("html", 0.40),
    "html_hidden_text":       ("html", 0.25),

    # ---- manipulation of AI assistants -----------------------------------
    "ai_prompt_injection":    ("ai", 0.65),

    # ---- reassuring facts (weight 0, shown when a message is clean) -------
    "pos_auth_pass":          ("auth", 0.0),
    "pos_cert_valid":         ("site", 0.0),
    "pos_https":              ("links", 0.0),
    "pos_hsts":               ("site", 0.0),
    "pos_domain_established": ("site", 0.0),
    "pos_no_risky_attachment": ("attachments", 0.0),
    "pos_links_clean":        ("links", 0.0),
}

# Display order of the groups in the scorecard.
GROUPS = ["auth", "sender", "content", "links", "site", "attachments", "html", "ai"]

VERDICT_DANGEROUS = 65   # score >= this  -> dangerous
VERDICT_SUSPICIOUS = 30  # score >= this  -> suspicious, otherwise safe


def make(fid, evidence=None, **params):
    """Create a finding. `evidence` is a list of short raw strings (URLs,
    header values, phrases) that justify it."""
    group, weight = CATALOG[fid]
    return {
        "id": fid,
        "group": group,
        "weight": weight,
        "params": params,
        "evidence": [str(e) for e in (evidence or [])][:5],
        "positive": fid.startswith("pos_"),
    }


def severity(weight):
    if weight >= 0.45:
        return "high"
    if weight >= 0.20:
        return "medium"
    if weight > 0:
        return "low"
    return "info"


def fuse(findings):
    """Noisy-OR fusion -> integer score 0..100."""
    keep = 1.0
    for f in findings:
        if f["weight"] > 0:
            keep *= (1.0 - min(0.99, f["weight"]))
    return int(round((1.0 - keep) * 100))


def dedupe(findings):
    """Keep one finding per id (the heaviest); merge their evidence and count
    how many times the pattern occurred (e.g. 4 links with no HTTPS)."""
    best = {}
    for f in findings:
        cur = best.get(f["id"])
        if cur is None:
            best[f["id"]] = dict(f, count=1)
        else:
            cur["count"] += 1
            for e in f["evidence"]:
                if e not in cur["evidence"] and len(cur["evidence"]) < 5:
                    cur["evidence"].append(e)
            if f["weight"] > cur["weight"]:
                cur["weight"] = f["weight"]
                cur["params"] = f["params"]
    return list(best.values())


def verdict_for(score):
    if score >= VERDICT_DANGEROUS:
        return "dangerous"
    if score >= VERDICT_SUSPICIOUS:
        return "suspicious"
    return "safe"


def group_status(findings, ran_groups):
    """Per-group status for the scorecard: clear / warn / danger / skipped."""
    out = {}
    for g in GROUPS:
        if g not in ran_groups:
            out[g] = {"status": "skipped", "count": 0}
            continue
        gf = [f for f in findings if f["group"] == g and f["weight"] > 0]
        worst = max([f["weight"] for f in gf], default=0.0)
        status = "danger" if worst >= 0.45 else "warn" if worst >= 0.08 else "clear"
        out[g] = {"status": status, "count": len(gf)}
    return out
