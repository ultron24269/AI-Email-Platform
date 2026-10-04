"""
Forensic report as a single self-contained HTML file, in English, Tamil or
Hindi. HTML (not a PDF library) is used on purpose: browsers shape Tamil and
Hindi correctly (conjuncts, vowel signs), while common Python PDF libraries do
not. "Print -> Save as PDF" in any browser produces a faithful PDF.

Every value that comes from the message is HTML-escaped: a hostile email must
not be able to inject markup into the report.
"""

import json
from html import escape as _e

from . import i18n
from .findings import GROUPS, severity
from .i18n import group_text, render_finding, sev_label, t, verdict_text
from .stamp import COLORS, stamp_img

REPORT_UI = {
    "rep_title": ("Forensic Threat Report", "தடயவியல் அச்சுறுத்தல் அறிக்கை", "फ़ॉरेंसिक खतरा रिपोर्ट"),
    "rep_case": ("Case ID", "வழக்கு எண்", "केस आईडी"),
    "rep_generated": ("Generated", "உருவாக்கப்பட்டது", "बनाई गई"),
    "rep_verdict": ("Verdict", "தீர்ப்பு", "फ़ैसला"),
    "rep_method_title": ("How this verdict was reached", "இந்தத் தீர்ப்பு எவ்வாறு எட்டப்பட்டது", "यह फ़ैसला कैसे हुआ"),
    "rep_method": ("Every check produces a finding with a weight, the probability that the signal alone indicates a malicious message. Findings are combined with noisy-OR fusion: risk = 1 - product of (1 - weight). The score is that risk on a 0 to 100 scale. Scores of 65 and above are Dangerous, 30 to 64 Suspicious, below 30 Safe. If the sender's SPF and DKIM/DMARC all pass and no strong red flag exists, the score is reduced by 25 percent.",
                    "ஒவ்வொரு சோதனையும் ஒரு எடையுடன் கூடிய கண்டுபிடிப்பை உருவாக்கும்; அந்த எடை என்பது அந்த அறிகுறி மட்டுமே தீங்கான செய்தியைக் குறிக்கும் நிகழ்தகவு. கண்டுபிடிப்புகள் noisy-OR முறையில் இணைக்கப்படுகின்றன: ஆபத்து = 1 - (1 - எடை) களின் பெருக்கற்பலன். மதிப்பெண் என்பது அந்த ஆபத்து 0 முதல் 100 அளவில். 65 மற்றும் அதற்கு மேல் ஆபத்தானது, 30 முதல் 64 சந்தேகத்திற்குரியது, 30 க்குக் கீழ் பாதுகாப்பானது. அனுப்புநரின் SPF மற்றும் DKIM/DMARC அனைத்தும் தேர்ச்சி பெற்று வலுவான எச்சரிக்கை அறிகுறி இல்லாவிட்டால் மதிப்பெண் 25 சதவீதம் குறைக்கப்படும்.",
                    "हर जाँच एक वज़न के साथ निष्कर्ष बनाती है; वज़न का मतलब है कि केवल वह संकेत ही संदेश के दुर्भावनापूर्ण होने की कितनी संभावना दर्शाता है। निष्कर्षों को noisy-OR विधि से जोड़ा जाता है: जोखिम = 1 - (1 - वज़न) का गुणनफल। स्कोर उसी जोखिम का 0 से 100 का पैमाना है। 65 और उससे ऊपर खतरनाक, 30 से 64 संदिग्ध, 30 से नीचे सुरक्षित। यदि भेजने वाले के SPF और DKIM/DMARC सभी पास हों और कोई गंभीर संकेत न हो तो स्कोर 25 प्रतिशत घटा दिया जाता है।"),
    "rep_custody_title": ("Chain of custody", "ஆதாரப் பாதுகாப்புச் சங்கிலி", "साक्ष्य की श्रृंखला"),
    "rep_custody": ("The SHA-256 fingerprint below identifies the exact message that was analysed. If even one byte of the message changes, the fingerprint changes.",
                    "கீழே உள்ள SHA-256 கைரேகை ஆராயப்பட்ட செய்தியை துல்லியமாக அடையாளம் காட்டுகிறது. செய்தியில் ஒரு பைட் மாறினாலும் கைரேகை மாறிவிடும்.",
                    "नीचे का SHA-256 फ़िंगरप्रिंट जाँचे गए संदेश की सटीक पहचान करता है। संदेश का एक बाइट भी बदले तो फ़िंगरप्रिंट बदल जाएगा।"),
    "rep_limits_title": ("Limits of this analysis", "இந்த ஆய்வின் வரம்புகள்", "इस विश्लेषण की सीमाएँ"),
    "rep_limits": ("Automated analysis can miss a well-crafted attack and can flag a genuine message. Brand checks rely on a list of official domains that may be incomplete. Use this report as evidence to support a decision, not as the decision.",
                   "தானியங்கி ஆய்வு நன்கு தயாரிக்கப்பட்ட தாக்குதலைத் தவறவிடலாம்; உண்மையான செய்தியையும் குறிக்கலாம். பிராண்ட் சோதனைகள் முழுமையற்ற அதிகாரப்பூர்வ டொமைன் பட்டியலைச் சார்ந்தவை. இந்த அறிக்கையை முடிவுக்கான ஆதாரமாகப் பயன்படுத்துங்கள்; முடிவாக அல்ல.",
                   "स्वचालित विश्लेषण सोच-समझकर बनाए हमले को चूक सकता है और असली संदेश को भी चिह्नित कर सकता है। ब्रांड जाँच आधिकारिक डोमेन की सूची पर निर्भर है जो अधूरी हो सकती है। इस रिपोर्ट को फ़ैसले के सबूत की तरह इस्तेमाल करें, फ़ैसले की तरह नहीं।"),
    "rep_ip_col": ("IP address", "IP முகவரி", "IP पता"),
    "rep_country": ("Country", "நாடு", "देश"),
    "rep_city": ("City", "நகரம்", "शहर"),
    "rep_org": ("Organisation", "நிறுவனம்", "संस्था"),
    "rep_risk": ("Risk", "ஆபத்து", "जोखिम"),
    "rep_event": ("Event", "நிகழ்வு", "घटना"),
    "rep_time": ("Time", "நேரம்", "समय"),
    "rep_print": ("Print or save as PDF", "அச்சிடு அல்லது PDF ஆகச் சேமி", "प्रिंट करें या PDF सहेजें"),
}
i18n.UI.update(REPORT_UI)

SEV_COLOR = {"high": "#C8102E", "medium": "#B26A00", "low": "#5b6b82", "info": "#17845B"}

CSS = """
:root{--ink:#10233F;--muted:#5b6b82;--paper:#F3F6FA;--card:#fff;--line:#d8e0ea;--blue:#1F5FBF;--red:#C8102E}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font:15px/1.6 'Noto Sans','Noto Sans Tamil','Noto Sans Devanagari','Nirmala UI','Latha','Mangal','Segoe UI',Arial,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:0 20px 48px}
.strip{height:10px;background:repeating-linear-gradient(-45deg,#C8102E 0 14px,#fff 14px 24px,#1F5FBF 24px 38px,#fff 38px 48px)}
header{padding:26px 0 8px;display:flex;justify-content:space-between;gap:16px;align-items:flex-end;flex-wrap:wrap}
h1{margin:0;font-size:26px;letter-spacing:-.01em}
.meta{color:var(--muted);font-size:13px;text-align:right}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px 22px;margin:16px 0;break-inside:avoid}
h2{margin:0 0 12px;font-size:17px}
.verdict{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.postmark{width:250px;max-width:100%;mix-blend-mode:multiply}
.headline{font-size:19px;font-weight:700;margin:0 0 8px}
.pill{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:700;color:#fff}
.bar{height:10px;background:#e6ecf3;border-radius:6px;overflow:hidden;margin:8px 0}
.bar i{display:block;height:100%}
.finding{border-left:5px solid var(--line);padding:8px 0 8px 14px;margin:10px 0}
.finding h3{margin:0 0 2px;font-size:15px}
.finding p{margin:2px 0;color:#26384f}
code,pre{font-family:'JetBrains Mono',Consolas,monospace;font-size:12px;background:#eef2f7;border-radius:6px;padding:1px 6px;word-break:break-all}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
th{color:var(--muted);font-weight:600;width:1%}
.kv th{width:26%}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}
.g{border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.g b{display:block;font-size:13px}.g small{color:var(--muted)}
.tag{font-size:12px;font-weight:700}
.good{color:#17845B}.warn{color:#B26A00}.danger{color:#C8102E}.skip{color:#8a97a8}
.note{color:var(--muted);font-size:13px}
button{background:var(--blue);color:#fff;border:0;border-radius:8px;padding:8px 16px;font:inherit;cursor:pointer}
@media print{body{background:#fff}button{display:none}section{border-color:#bbb}.wrap{max-width:none}}
"""


def _row(k, v):
    return f"<tr><th>{_e(str(k))}</th><td>{v}</td></tr>"


def _grp_class(status):
    return {"clear": "good", "warn": "warn", "danger": "danger"}.get(status, "skip")


def render_report(result, parsed, lang="en", ip_results=None, ti_results=None,
                  timeline=None, ai_text=None):
    """Return the full HTML document as a string."""
    v = result["verdict"]
    col = COLORS[v]
    word = verdict_text(v, "stamp", lang)
    meta = result["meta"]
    case_id = meta["sha256"][:12].upper()
    findings = result["findings"]
    risky = [f for f in findings if f["weight"] > 0]
    good = [f for f in findings if f["positive"]]

    # ---- reasons -------------------------------------------------------------
    def finding_html(f):
        title, why = render_finding(f, lang)
        sev = severity(f["weight"])
        ev = "".join(f"<div><code>{_e(x)}</code></div>" for x in f["evidence"] if x)
        cnt = f' <span class="note">({t("occurs_n", lang, n=f["count"])})</span>' if f.get("count", 1) > 1 else ""
        badge = f'<span class="pill" style="background:{SEV_COLOR[sev]}">{_e(sev_label(f["weight"], lang))}</span>' \
            if f["weight"] > 0 else ""
        return (f'<div class="finding" style="border-left-color:{SEV_COLOR[sev]}"><h3>{badge} {_e(title)}{cnt}</h3>'
                f'<p>{_e(why)}</p>{ev}</div>')

    reasons_html = "".join(finding_html(f) for f in risky) or f'<p class="good">{_e(verdict_text(v, "headline", lang))}</p>'
    good_html = "".join(finding_html(f) for f in good)

    # ---- group scorecard -----------------------------------------------------
    cards = []
    for g in GROUPS:
        name, desc = group_text(g, lang)
        st = result["groups"][g]["status"]
        cards.append(f'<div class="g"><b>{_e(name)}</b><span class="tag {_grp_class(st)}">{_e(t("grp_" + st, lang))}</span>'
                     f'<br/><small>{_e(desc)}</small></div>')

    # ---- facts ---------------------------------------------------------------
    auth = meta["auth"]
    auth_txt = " · ".join(f"{k.upper()}={auth.get(k) or '-'}" for k in ("spf", "dkim", "dmarc"))
    langs = ", ".join(i18n.LANG_NAMES[x] for x in meta["languages"] if x in i18n.LANG_NAMES) or "-"
    facts = "".join([
        _row(t("f_source", lang), _e(t("src_" + meta["source"], lang))),
        _row(t("f_from", lang), _e(meta["from"])),
        _row(t("f_to", lang), _e(meta["to"])),
        _row(t("f_subject", lang), _e(meta["subject"])),
        _row(t("f_date", lang), _e(meta["date"])),
        _row(t("f_reply", lang), _e(meta["reply_to"])),
        _row(t("f_return", lang), _e(meta.get("return_path") or "-")),
        _row(t("f_msgid", lang), f"<code>{_e(meta['message_id'])}</code>"),
        _row(t("f_auth", lang), _e(auth_txt)),
        _row(t("f_lang", lang), _e(langs)),
        _row(t("f_sha", lang), f"<code>{_e(meta['sha256'])}</code>"),
    ])

    # ---- links & certificates -----------------------------------------------
    link_rows = ""
    for r in result["links"]:
        c = (r.get("cert") or {}).get("cert")
        if c:
            state = t("cert_ok", lang) if (r["cert"].get("trusted")) else t("cert_bad", lang)
            cert_cell = f'{_e(state)}: {_e(c.get("issuer_org") or c.get("issuer_cn") or "?")} → {_e(c["not_after"])} ({c["days_left"]} {_e(t("days", lang))})'
        elif r["scheme"] != "https":
            cert_cell = _e(t("cert_na", lang))
        else:
            cert_cell = _e(t("cert_none", lang))
        link_rows += (f'<tr><td><code>{_e(r["url"][:110])}</code></td>'
                      f'<td class="tag" style="color:{COLORS[r["verdict"]]}">{_e(verdict_text(r["verdict"], "word", lang))} ({r["score"]})</td>'
                      f'<td>{cert_cell}</td></tr>')
    links_html = (f'<table><tr><th>{_e(t("col_link", lang))}</th><th>{_e(t("col_verdict", lang))}</th>'
                  f'<th>{_e(t("col_cert", lang))}</th></tr>{link_rows}</table>') if link_rows else f'<p class="note">{_e(t("no_links", lang))}</p>'

    # ---- attachments ---------------------------------------------------------
    att_rows = "".join(
        f'<tr><td>{_e(a["filename"])}</td><td>{a["size"]:,} B</td><td><code>{a["sha256"]}</code></td></tr>'
        for a in meta["attachments"])
    att_html = (f'<table><tr><th>{_e(t("col_file", lang))}</th><th>{_e(t("col_size", lang))}</th><th>SHA-256</th></tr>{att_rows}</table>'
                if att_rows else f'<p class="note">{_e(t("no_attach", lang))}</p>')

    # ---- optional blocks -----------------------------------------------------
    geo_html = ""
    if ip_results:
        rows = "".join(
            f'<tr><td><code>{_e(str(i.get("ip", "")))}</code></td><td>{_e(str(i.get("country", "")))}</td>'
            f'<td>{_e(str(i.get("city", "")))}</td><td>{_e(str(i.get("organization", "")))}</td></tr>'
            for i in ip_results)
        geo_html = (f'<section><h2>{_e(t("det_geo", lang))}</h2><table><tr><th>{_e(t("rep_ip_col", lang))}</th>'
                    f'<th>{_e(t("rep_country", lang))}</th><th>{_e(t("rep_city", lang))}</th>'
                    f'<th>{_e(t("rep_org", lang))}</th></tr>{rows}</table></section>')
    ti_html = ""
    if ti_results:
        rows = "".join(
            f'<tr><td><code>{_e(str(i.get("indicator", ""))[:90])}</code></td><td>{_e(str(i.get("risk", "")))}</td>'
            f'<td>{_e(str(i.get("reason", "")))}</td></tr>' for i in ti_results)
        ti_html = (f'<section><h2>{_e(t("det_ti", lang))}</h2><table><tr><th>{_e(t("col_link", lang))}</th>'
                   f'<th>{_e(t("rep_risk", lang))}</th><th></th></tr>{rows}</table></section>')
    tl_html = ""
    if timeline:
        rows = "".join(
            f'<tr><td>{_e(str(e.get("timestamp", "")))}</td><td>{_e(str(e.get("event", "")))}</td>'
            f'<td>{_e(str(e.get("evidence", "")))}</td></tr>' for e in timeline)
        tl_html = (f'<section><h2>{_e(t("det_timeline", lang))}</h2><table><tr><th>{_e(t("rep_time", lang))}</th>'
                   f'<th>{_e(t("rep_event", lang))}</th><th>{_e(t("evidence", lang))}</th></tr>{rows}</table></section>')
    ai_html = ""
    if ai_text:
        ai_html = (f'<section><h2>{_e(t("sec_ai", lang))}</h2><p>{_e(ai_text)}</p>'
                   f'<p class="note">{_e(t("ai_note", lang))}</p></section>')

    limit = f'<p class="note">{_e(t("limit_note", lang))}</p>' if meta["source"] == "text" else ""
    conf = t("conf_" + result["confidence"], lang)
    return f"""<!doctype html>
<html lang="{lang}"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{_e(t("rep_title", lang))} · {case_id}</title><style>{CSS}</style></head>
<body><div class="strip"></div><div class="wrap">
<header><div><h1>{_e(t("rep_title", lang))}</h1><div class="note">{_e(t("app_name", lang))}</div></div>
<div class="meta">{_e(t("rep_case", lang))}: <b>{case_id}</b><br/>{_e(t("rep_generated", lang))}: {_e(meta["analysed_at"])}<br/>
<button onclick="window.print()">{_e(t("rep_print", lang))}</button></div></header>

<section><div class="verdict">{stamp_img(v, word, result["score"])}
<div style="flex:1;min-width:240px"><p class="headline" style="color:{col}">{_e(verdict_text(v, "word", lang))}</p>
<p>{_e(i18n.summary_sentence(result, lang))}</p>
<div class="bar"><i style="width:{result["score"]}%;background:{col}"></i></div>
<div class="note">{_e(t("score_label", lang))}: <b>{result["score"]}/100</b> · {_e(conf)} · {_e(t("checks_run", lang, n=result["rules_run"]))} · {_e(t("flagged_n", lang, n=len(risky)))}</div>{limit}</div></div></section>

<section><h2>{_e(verdict_text(v, "lead", lang))}</h2>{reasons_html}</section>
{f'<section><h2>{_e(t("sec_good", lang))}</h2>{good_html}</section>' if good_html else ''}
<section><h2>{_e(t("sec_advice", lang))}</h2><p>{_e(verdict_text(v, "advice", lang))}</p><p class="note">{_e(t("help_india", lang))}</p></section>
{ai_html}
<section><h2>{_e(t("sec_groups", lang))}</h2><div class="grid">{"".join(cards)}</div></section>
<section><h2>{_e(t("det_message", lang))}</h2><table class="kv">{facts}</table></section>
<section><h2>{_e(t("det_links", lang))}</h2>{links_html}</section>
<section><h2>{_e(t("det_attach", lang))}</h2>{att_html}</section>
{geo_html}{ti_html}{tl_html}
<section><h2>{_e(t("rep_method_title", lang))}</h2><p>{_e(t("rep_method", lang))}</p>
<h2 style="margin-top:14px">{_e(t("rep_custody_title", lang))}</h2><p>{_e(t("rep_custody", lang))}</p>
<h2 style="margin-top:14px">{_e(t("rep_limits_title", lang))}</h2><p>{_e(t("rep_limits", lang))}</p>
<p class="note">{_e(t("disclaimer", lang))}</p></section>
</div></body></html>"""


def evidence_json(result, parsed):
    """Machine-readable evidence bundle (no message body, to keep it shareable)."""
    slim = {k: v for k, v in result.items() if k != "links"}
    slim["links"] = [{"url": r["url"], "verdict": r["verdict"], "score": r["score"],
                      "findings": [f["id"] for f in r["findings"]]} for r in result["links"]]
    return json.dumps(slim, ensure_ascii=False, indent=2, default=str)
