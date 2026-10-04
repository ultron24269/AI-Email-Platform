import os
import time
from datetime import datetime

import streamlit as st

from modules import i18n
from modules.ai_engine import analyze_message
from modules.email_analyzer import parse_email_bytes, parse_pasted_text
from modules.findings import GROUPS, severity
from modules.geolocation import analyze_ips
from modules.i18n import group_text, render_finding, sev_label, t, verdict_text
from modules.inbox_watchdog import WatchError, guess_host, new_state, run_cycle
from modules.llm_advisor import second_opinion
from modules.report_html import evidence_json, render_report
from modules.stamp import COLORS, stamp_img
from modules.threat_intel import analyze_indicators
from modules.url_ai import assess_url, normalise_url

# --------------------------------------------------------------------------
# Page setup
# --------------------------------------------------------------------------

st.set_page_config(page_title="AI Email Threat Platform", page_icon="🛡️",
                   layout="wide", initial_sidebar_state="expanded")

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "modules", "assets", "theme.css"), encoding="utf-8") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

if "lang" not in st.session_state:
    st.session_state.lang = "en"
if "watch_state" not in st.session_state:
    st.session_state.watch_state = new_state()
if "watching" not in st.session_state:
    st.session_state.watching = False

SAMPLES_DIR = os.path.join(_HERE, "samples")
SAMPLE_FILES = ["phish_english_bank.eml", "phish_tamil_electricity.eml", "phish_hindi_kyc.eml",
                "attack_prompt_injection.eml", "attack_double_extension.eml",
                "legit_bank_alert.eml", "legit_personal.eml"]


def L():
    return st.session_state.lang


def _(key, **kw):
    return t(key, L(), **kw)


# --------------------------------------------------------------------------
# Sidebar: language + nav feel
# --------------------------------------------------------------------------

with st.sidebar:
    st.markdown(f"### 🛡️ {_( 'app_name')}")
    st.caption(_("hero_sub"))
    st.divider()
    choice = st.radio(_("lang_label"), options=["en", "ta", "hi"],
                      format_func=lambda x: i18n.LANG_NAMES[x],
                      index=["en", "ta", "hi"].index(L()), key="lang_radio")
    st.session_state.lang = choice
    st.divider()
    st.caption(_("help_india"))
    st.caption(_("footer"))

st.markdown('<div class="postal-strip"></div>', unsafe_allow_html=True)
st.markdown(f'<div class="hero"><h1>🛡️ {_( "hero_title")}</h1><p>{_( "hero_sub")}</p></div>',
           unsafe_allow_html=True)

tab_inspect, tab_watch, tab_link, tab_cases = st.tabs(
    [f"📨 {_('tab_inspect')}", f"📡 {_('tab_watch')}", f"🔗 {_('tab_link')}", f"📚 {_('tab_cases')}"])

# --------------------------------------------------------------------------
# Shared rendering
# --------------------------------------------------------------------------


def render_verdict_banner(result):
    v = result["verdict"]
    col = COLORS[v]
    word = verdict_text(v, "stamp", L())
    c1, c2 = st.columns([1, 3])
    with c1:
        st.markdown(f'<div class="postmark-wrap">{stamp_img(v, word, result["score"])}</div>',
                    unsafe_allow_html=True)
    with c2:
        conf = t("conf_" + result["confidence"], L())
        st.markdown(f"""
        <div class="verdict-banner" style="border-color:{col}33">
          <div style="flex:1;min-width:260px">
            <p class="verdict-word" style="color:{col}">{verdict_text(v, "word", L())}</p>
            <p class="verdict-sub">{i18n.summary_sentence(result, L())}</p>
            <div class="score-track"><div class="score-fill" style="width:{result['score']}%;background:{col}"></div></div>
            <div class="meta-row">{_( 'score_label')}: <b>{result['score']}/100</b> · {conf} ·
              {_( 'checks_run', n=result['rules_run'])} ·
              {_( 'flagged_n', n=sum(1 for f in result['findings'] if f['weight']>0))}</div>
          </div>
        </div>""", unsafe_allow_html=True)
    if result["meta"]["source"] == "text":
        st.caption(_("limit_note"))


def render_findings_list(findings, max_show=None):
    shown = findings[:max_show] if max_show else findings
    for f in shown:
        title, why = render_finding(f, L())
        sev = severity(f["weight"])
        ev = "".join(f"<div><code>{st.session_state.get('_e', lambda s: s)(x)}</code></div>"
                     for x in [])  # placeholder unused
        badge = (f'<span class="pill pill-{sev}">{sev_label(f["weight"], L())}</span> '
                 if f["weight"] > 0 else "")
        cnt = f" ({_( 'occurs_n', n=f['count'])})" if f.get("count", 1) > 1 else ""
        evid = "".join(f'<div><code>{__import__("html").escape(x)}</code></div>'
                       for x in f["evidence"][:3] if x)
        st.markdown(f'<div class="finding" style="border-left-color:{"#C8102E" if sev=="high" else "#B26A00" if sev=="medium" else "#5b6b82" if sev=="low" else "#17845B"}">'
                    f'<h4>{badge}{__import__("html").escape(title)}{cnt}</h4>'
                    f'<p>{__import__("html").escape(why)}</p>{evid}</div>', unsafe_allow_html=True)


def render_group_scorecard(result):
    chips = []
    for g in GROUPS:
        name, desc = group_text(g, L())
        status = result["groups"][g]["status"]
        cls = {"clear": "tag-clear", "warn": "tag-warn", "danger": "tag-danger"}.get(status, "tag-skip")
        chips.append(f'<div class="grp-chip"><b>{__import__("html").escape(name)}</b>'
                     f'<span class="{cls}">{_( "grp_" + status)}</span><br/><small>{__import__("html").escape(desc)}</small></div>')
    st.markdown(f'<div class="grp-grid">{"".join(chips)}</div>', unsafe_allow_html=True)


def render_links_table(result):
    if not result["links"]:
        st.caption(_("no_links"))
        return
    rows = []
    for r in result["links"]:
        c = (r.get("cert") or {}).get("cert")
        if c:
            cert = f"{t('cert_ok', L()) if r['cert'].get('trusted') else t('cert_bad', L())} · {c['not_after']} ({c['days_left']}d)"
        elif r["scheme"] != "https":
            cert = t("cert_na", L())
        else:
            cert = t("cert_none", L())
        rows.append({t("col_link", L()): r["url"][:90], t("col_verdict", L()): f"{verdict_text(r['verdict'],'word',L())} ({r['score']})",
                    t("col_cert", L()): cert})
    st.dataframe(rows, use_container_width=True, hide_index=True)


def result_downloads(result, parsed, ai_text=None, ip_results=None, ti_results=None, timeline=None):
    html_report = render_report(result, parsed, L(), ip_results=ip_results,
                                ti_results=ti_results, timeline=timeline, ai_text=ai_text)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(_("dl_html"), html_report.encode("utf-8"),
                           file_name=f"report_{result['meta']['sha256'][:10]}_{L()}.html",
                           mime="text/html", use_container_width=True)
    with c2:
        pdf_bytes = try_pdf(result, parsed, ip_results, ti_results, timeline)
        if pdf_bytes:
            st.download_button(_("dl_pdf"), pdf_bytes,
                               file_name=f"report_{result['meta']['sha256'][:10]}.pdf",
                               mime="application/pdf", use_container_width=True)
    with c3:
        st.download_button(_("dl_json"), evidence_json(result, parsed).encode("utf-8"),
                           file_name=f"evidence_{result['meta']['sha256'][:10]}.json",
                           mime="application/json", use_container_width=True)
    st.caption(_("report_hint"))
    with st.expander(_("report_preview")):
        st.components.v1.html(html_report, height=520, scrolling=True)


def try_pdf(result, parsed, ip_results=None, ti_results=None, timeline=None):
    """English PDF via the original ReportLab generator (legacy shape)."""
    try:
        from modules.ai_engine import legacy_threat_result, legacy_url_results
        from modules.report import generate_report
        reasons = i18n.plain_reasons(result, "en")
        legacy = legacy_threat_result(result, reasons)
        url_results = legacy_url_results(result)
        buf = generate_report(parsed, legacy, url_results, ip_results or [],
                              ti_results or [], timeline or [])
        return buf.getvalue() if hasattr(buf, "getvalue") else buf
    except Exception:
        return None


def maybe_ai_opinion(parsed, result, enabled):
    if not enabled:
        return None
    api_key = os.environ.get("ANTHROPIC_API_KEY") or st.secrets.get("ANTHROPIC_API_KEY", None) \
        if hasattr(st, "secrets") else os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        st.info(_("ai_disabled"))
        return None
    with st.spinner(_("sec_ai") + "…"):
        out = second_opinion(parsed, result, L(), api_key)
    if not out["ok"]:
        st.warning(_("ai_failed"))
        return None
    return out["text"]


def full_result_view(result, parsed, want_geo=False, want_vt=False, want_ai=False):
    render_verdict_banner(result)
    st.markdown(f"#### {_( 'sec_why')}")
    risky = [f for f in result["findings"] if f["weight"] > 0]
    if not risky:
        st.success(verdict_text("safe", "headline", L()))
    else:
        render_findings_list(risky, max_show=6)
        if len(risky) > 6:
            with st.expander(_("more_reasons", n=len(risky))):
                render_findings_list(risky[6:])
    good = [f for f in result["findings"] if f["positive"]]
    if good:
        with st.expander(_("sec_good")):
            render_findings_list(good)

    st.markdown(f"#### {_( 'sec_advice')}")
    st.info(verdict_text(result["verdict"], "advice", L()))

    ai_text = maybe_ai_opinion(parsed, result, want_ai)
    if ai_text:
        st.markdown(f"#### {_( 'sec_ai')}")
        st.markdown(ai_text)
        st.caption(_("ai_note"))

    st.markdown(f"#### {_( 'sec_groups')}")
    render_group_scorecard(result)

    ip_results = None
    if want_geo:
        with st.spinner(_("det_geo") + "…"):
            found = analyze_ips(parsed.get("headers", {}))
        ip_results = found or None

    ti_results = None
    if want_vt:
        indicators = [r["url"] for r in result["links"][:8]]
        if indicators:
            with st.spinner(_("det_ti") + "…"):
                try:
                    ti_results = analyze_indicators(indicators)
                except Exception:
                    ti_results = None

    timeline = None
    try:
        from modules.ai_engine import legacy_threat_result
        from modules.forensic import build_forensic_timeline
        legacy = legacy_threat_result(result, i18n.plain_reasons(result, "en"))
        timeline = build_forensic_timeline(parsed, ip_results or [], legacy)
    except Exception:
        timeline = None

    with st.expander(_("sec_details")):
        st.markdown(f"**{_( 'det_message')}**")
        m = result["meta"]
        st.write({t("f_from", L()): m["from"], t("f_to", L()): m["to"], t("f_subject", L()): m["subject"],
                 t("f_date", L()): m["date"], t("f_reply", L()): m["reply_to"],
                 t("f_msgid", L()): m["message_id"], t("f_sha", L()): m["sha256"]})
        auth = m["auth"]
        st.caption(f"SPF={auth.get('spf') or '-'} · DKIM={auth.get('dkim') or '-'} · DMARC={auth.get('dmarc') or '-'}")
        st.markdown(f"**{_( 'det_links')}**")
        render_links_table(result)
        st.markdown(f"**{_( 'det_attach')}**")
        if m["attachments"]:
            st.dataframe([{t("col_file", L()): a["filename"], t("col_size", L()): a["size"],
                          "SHA-256": a["sha256"][:24] + "…"} for a in m["attachments"]],
                        use_container_width=True, hide_index=True)
        else:
            st.caption(_("no_attach"))
        if ip_results:
            st.markdown(f"**{_( 'det_geo')}**")
            st.dataframe(ip_results, use_container_width=True, hide_index=True)
        if ti_results:
            st.markdown(f"**{_( 'det_ti')}**")
            st.dataframe(ti_results, use_container_width=True, hide_index=True)
        if timeline:
            st.markdown(f"**{_( 'det_timeline')}**")
            st.dataframe(timeline, use_container_width=True, hide_index=True)

    st.markdown(f"#### {_( 'sec_download')}")
    result_downloads(result, parsed, ai_text=ai_text, ip_results=ip_results,
                     ti_results=ti_results, timeline=timeline)
    st.caption(_("disclaimer"))


# --------------------------------------------------------------------------
# Tab 1 — Inspect a message
# --------------------------------------------------------------------------

with tab_inspect:
    mode = st.radio(" ", [_("mode_upload"), _("mode_paste"), _("mode_sample")],
                    horizontal=True, label_visibility="collapsed", key="inspect_mode")

    parsed = None
    parse_failed = False

    if mode == _("mode_upload"):
        up = st.file_uploader(_("upload_label"), type=["eml"])
        st.caption(_("upload_help"))
        if up is not None:
            try:
                parsed = parse_email_bytes(up.read())
            except Exception:
                parse_failed = True

    elif mode == _("mode_paste"):
        text = st.text_area(_("paste_label"), height=180, placeholder=_("paste_placeholder"))
        if text.strip():
            parsed = parse_pasted_text(text)

    else:
        labels = {f: _("s_" + f.rsplit(".", 1)[0]) for f in SAMPLE_FILES}
        pick = st.selectbox(_("sample_pick"), SAMPLE_FILES, format_func=lambda f: labels[f])
        path = os.path.join(SAMPLES_DIR, pick)
        if os.path.exists(path):
            with open(path, "rb") as f:
                parsed = parse_email_bytes(f.read())

    with st.expander("⚙️ " + _("opt_certs").split(" (")[0] + " / " + _("opt_geo") + " / " + _("opt_vt") + " / " + _("opt_ai"), expanded=False):
        opt_certs = st.checkbox(_("opt_certs"), value=True, key="opt_certs")
        opt_geo = st.checkbox(_("opt_geo"), value=False, key="opt_geo")
        opt_vt = st.checkbox(_("opt_vt"), value=False, key="opt_vt")
        opt_ai = st.checkbox(_("opt_ai"), value=False, key="opt_ai")

    go = st.button("🔍 " + _("btn_analyze"), type="primary", use_container_width=False,
                   disabled=parsed is None and not parse_failed)

    if parse_failed:
        st.error(_("parse_error"))
    elif go and parsed is None:
        st.warning(_("nothing_to_scan"))
    elif go and parsed is not None:
        with st.spinner(_("analyzing")):
            result = analyze_message(parsed, check_certs=opt_certs)
        st.session_state["last_result"] = (result, parsed)
        full_result_view(result, parsed, want_geo=opt_geo, want_vt=opt_vt, want_ai=opt_ai)
    elif "last_result" in st.session_state and mode == _("mode_sample"):
        pass  # let a fresh click re-render; avoid stale duplicate render on tab switch

# --------------------------------------------------------------------------
# Tab 2 — Live inbox watchdog
# --------------------------------------------------------------------------

with tab_watch:
    st.markdown(f'<div class="card">{_( "watch_intro")}</div>', unsafe_allow_html=True)

    if not st.session_state.watching:
        c1, c2 = st.columns(2)
        with c1:
            email_addr = st.text_input(_("watch_email"), key="watch_email_in", placeholder="you@gmail.com")
            host_guess = guess_host(email_addr) if email_addr else ""
            host = st.text_input(_("watch_host"), value=host_guess, key="watch_host_in")
        with c2:
            pw = st.text_input(_("watch_password"), type="password", key="watch_pw_in")
            every = st.slider(_("watch_every"), 15, 120, 30, step=5, key="watch_every_in")
        with st.expander(_("watch_help_title")):
            st.markdown(_("watch_help"))
        st.caption(_("watch_privacy"))
        if st.button("📡 " + _("watch_start"), type="primary"):
            if email_addr and pw and host:
                st.session_state.watching = True
                st.session_state.watch_state = new_state()
                st.session_state.watch_creds = (host, email_addr, pw)
                st.rerun()
            else:
                st.warning(_("nothing_to_scan"))
    else:
        host, user, pw = st.session_state.watch_creds
        state = st.session_state.watch_state
        top = st.columns([3, 1, 1])
        with top[0]:
            st.success(_("watch_on", user=user))
            if state["last_check"]:
                st.caption(_("watch_last", time=state["last_check"]))
        with top[1]:
            if st.button("🔄 " + _("watch_now")):
                run_cycle(state, host, user, pw, check_certs=False)
        with top[2]:
            if st.button("⏹ " + _("watch_stop")):
                st.session_state.watching = False
                st.session_state.watch_creds = None
                st.session_state.watch_state = new_state()
                st.rerun()

        if state["error"] == "auth":
            st.error(_("watch_err_auth"))
        elif state["error"] == "conn":
            st.error(_("watch_err_conn"))

        st.caption(_("watch_scanned") + f": {state['scanned']}")

        if not state["items"]:
            st.info(_("watch_empty"))
        for item in state["items"][:20]:
            r = item["result"]
            v = r["verdict"]
            col = COLORS[v]
            subj = item["parsed"]["subject"]
            st.markdown(f"""
            <div class="feed-item">
              <div class="feed-dot" style="background:{col}"></div>
              <div style="flex:1">
                <b>{__import__("html").escape(subj)[:120]}</b><br/>
                <span style="color:var(--muted);font-size:.82rem">{__import__("html").escape(item["parsed"]["sender"])[:100]}</span><br/>
                <span class="pill" style="background:{col}">{verdict_text(v,'word',L())}</span>
                <span style="color:var(--muted);font-size:.8rem"> · {r['score']}/100</span>
              </div>
            </div>""", unsafe_allow_html=True)
            if v == "dangerous":
                st.toast(_("watch_alert", subject=subj[:60]), icon="🚨")
            with st.expander(f"{_('sec_why')}"):
                full_result_view(r, item["parsed"])

        placeholder = st.empty()
        with placeholder.container():
            st.caption(_("watch_connecting") if not state["last_check"] else "")
        time.sleep(30)
        run_cycle(state, host, user, pw, check_certs=False)
        st.rerun()

# --------------------------------------------------------------------------
# Tab 3 — Link & certificate check
# --------------------------------------------------------------------------

with tab_link:
    st.markdown(f'<div class="card">{_( "link_intro")}</div>', unsafe_allow_html=True)
    urls_text = st.text_area(_("link_label"), placeholder=_("link_placeholder"), height=90)
    c1, c2 = st.columns(2)
    with c1:
        deep = st.checkbox(_("link_deep"), value=True, key="link_deep_cb")
    with c2:
        use_vt = st.checkbox(_("link_vt"), value=False, key="link_vt_cb")
    st.caption(_("link_private_note"))

    if st.button("🔍 " + _("link_btn"), type="primary"):
        urls = [normalise_url(u) for u in urls_text.splitlines() if u.strip()]
        if not urls:
            st.warning(_("link_none"))
        for url in urls:
            with st.spinner(f"{url}…"):
                r = assess_url(url, cert=True, deep=deep, use_vt=use_vt)
            col = COLORS[r["verdict"]]
            st.markdown(f"""
            <div class="verdict-banner" style="border-color:{col}33;margin-top:14px">
              <div style="flex:1">
                <p class="verdict-word" style="color:{col}">{verdict_text(r['verdict'],'word',L())} — {r['host']}</p>
                <div class="score-track"><div class="score-fill" style="width:{r['score']}%;background:{col}"></div></div>
                <div class="meta-row">{_( 'score_label')}: <b>{r['score']}/100</b></div>
              </div>
            </div>""", unsafe_allow_html=True)

            risky = [f for f in r["findings"] if f["weight"] > 0]
            if risky:
                render_findings_list(risky)
            else:
                st.success(verdict_text("safe", "headline", L()))

            c = r.get("cert")
            with st.expander(_("cert_card")):
                if c and c.get("cert"):
                    cc = c["cert"]
                    yn = lambda b: t("yes", L()) if b else t("no", L())
                    left, right = st.columns(2)
                    with left:
                        st.write(f"**{_( 'c_trusted')}:** {yn(c.get('trusted'))}")
                        st.write(f"**{_( 'c_host')}:** {yn(cc.get('hostname_match'))}")
                        st.write(f"**{_( 'c_issuer')}:** {cc.get('issuer_org') or cc.get('issuer_cn')}")
                        st.write(f"**{_( 'c_subject')}:** {cc.get('subject_cn')}")
                        st.write(f"**{_( 'c_names')}:** {', '.join(cc.get('sans', [])[:5])}")
                    with right:
                        st.write(f"**{_( 'c_from')}:** {cc.get('not_before')}")
                        st.write(f"**{_( 'c_to')}:** {cc.get('not_after')}")
                        st.write(f"**{_( 'c_left')}:** {cc.get('days_left')} {t('days', L())}")
                        st.write(f"**{_( 'c_tls')}:** {c.get('tls_version')}")
                        st.write(f"**{_( 'c_key')}:** {cc.get('key_type')} {cc.get('key_bits') or ''}")
                        st.write(f"**{_( 'c_sig')}:** {cc.get('sig_alg')}")
                    st.code(cc.get("sha256", ""), language=None)
                else:
                    st.caption(_("no_cert_data"))
                if r.get("http"):
                    st.write(f"**{_( 'c_hsts')}:** {t('yes', L()) if r['http'].get('hsts') else t('no', L())}")
                    if len(r["http"]["hops"]) > 1:
                        st.write(f"**{_( 'c_hops')}:** " + " → ".join(h["url"][:60] for h in r["http"]["hops"]))
                if r.get("domain_age_days") is not None:
                    st.write(f"**{_( 'c_age')}:** {r['domain_age_days']} {t('days', L())}")
                if r.get("ml_probability") is not None:
                    st.write(f"**{_( 'c_ml')}:** {r['ml_probability']}%")

# --------------------------------------------------------------------------
# Tab 4 — Case studies
# --------------------------------------------------------------------------

CASES = [
    {
        "title_en": "The Jamtara-style KYC OTP scam", "title_ta": "ஜாம்தாரா பாணி KYC OTP மோசடி",
        "title_hi": "जामताड़ा शैली की KYC OTP ठगी",
        "body_en": "Networks of fraudsters in India, first exposed around Jamtara, Jharkhand, impersonate bank or KYC officers by phone, SMS and email, pressuring victims to share an OTP to 'update' or 'save' their account, then draining it within minutes.",
        "body_ta": "ஜார்க்கண்ட் மாநிலம் ஜாம்தாராவைச் சுற்றி முதன்முதலில் அம்பலமான மோசடி வலையமைப்புகள், தொலைபேசி, SMS, மின்னஞ்சல் வழியாக வங்கி/KYC அதிகாரிகள் போல நடித்து, கணக்கை 'புதுப்பிக்க' OTP யைப் பகிரச் சொல்லி, சில நிமிடங்களில் பணத்தை உறிஞ்சுகின்றனர்.",
        "body_hi": "झारखंड के जामताड़ा के आसपास पहली बार उजागर हुए ठग नेटवर्क, फोन, SMS और ईमेल से बैंक या KYC अधिकारी बनकर खाता 'अपडेट' करने के नाम पर OTP माँगते हैं और मिनटों में पैसे निकाल लेते हैं।",
        "catch": ["content_otp_request", "content_credentials", "sender_lookalike"], "match": "phish_hindi_kyc",
    },
    {
        "title_en": "'Digital arrest' video-call extortion", "title_ta": "'டிஜிட்டல் கைது' வீடியோ அழைப்பு மிரட்டல்",
        "title_hi": "'डिजिटल अरेस्ट' वीडियो-कॉल ठगी",
        "body_en": "Since 2023-24, callers posing as CBI, customs or narcotics officers claim a parcel or SIM in the victim's name is linked to a crime and keep them on video call, isolated, until they transfer money to avoid a fake 'arrest'. Indian police and the PIB have repeatedly clarified no law allows such an arrest.",
        "body_ta": "2023-24 முதல், CBI, சுங்கம் அல்லது போதைப்பொருள் அதிகாரிகள் போல நடிப்பவர்கள், பாதிக்கப்பட்டவர் பெயரில் பார்சல்/சிம் குற்றத்துடன் தொடர்புடையது எனக் கூறி, போலி 'கைது' தவிர்க்க பணம் அனுப்பும் வரை வீடியோ அழைப்பில் தனிமைப்படுத்தி வைக்கின்றனர். இத்தகைய கைது சட்டப்படி இல்லை என இந்திய காவல்துறையும் PIB உம் மீண்டும் மீண்டும் தெளிவுபடுத்தியுள்ளன.",
        "body_hi": "2023-24 से, CBI, कस्टम या नारकोटिक्स अधिकारी बनकर कॉल करने वाले, पीड़ित के नाम पार्सल/सिम को अपराध से जोड़कर, नकली 'गिरफ्तारी' से बचने के लिए पैसे भेजने तक वीडियो कॉल पर अलग-थलग रखते हैं। भारतीय पुलिस और PIB बार-बार स्पष्ट कर चुके हैं कि ऐसी कोई गिरफ्तारी कानून में नहीं है।",
        "catch": ["content_govt_scam", "content_threat"], "match": None,
    },
    {
        "title_en": "Fake electricity-disconnection SMS/email", "title_ta": "போலி மின் துண்டிப்பு SMS/மின்னஞ்சல்",
        "title_hi": "नकली बिजली-कटौती SMS/ईमेल",
        "body_en": "Utility boards across India (Tamil Nadu's TANGEDCO among them) have issued public warnings about messages claiming power will be cut that same night unless a 'pending bill' is paid via a link, which actually harvests card details.",
        "body_ta": "இன்று இரவே மின்சாரம் துண்டிக்கப்படும் என்று கூறி, ஒரு இணைப்பு வழியாக 'நிலுவைத் தொகையைச்' செலுத்தச் சொல்லி, உண்மையில் அட்டை விவரங்களைத் திருடும் செய்திகள் குறித்து TANGEDCO உள்ளிட்ட மின் வாரியங்கள் பொது எச்சரிக்கைகள் வெளியிட்டுள்ளன.",
        "body_hi": "उसी रात बिजली काटे जाने का दावा कर, एक लिंक से 'बकाया बिल' भरने को कहने वाले संदेशों के बारे में TANGEDCO सहित भारत भर के बिजली बोर्डों ने सार्वजनिक चेतावनी जारी की है; असल में यह कार्ड की जानकारी चुराता है।",
        "catch": ["content_utility_scam", "content_urgency", "link_no_https"], "match": "phish_tamil_electricity",
    },
    {
        "title_en": "Indirect prompt injection against AI email assistants",
        "title_ta": "AI மின்னஞ்சல் உதவியாளர்கள் மீதான மறைமுக prompt injection",
        "title_hi": "AI ईमेल असिस्टेंट पर अप्रत्यक्ष प्रॉम्प्ट इंजेक्शन",
        "body_en": "Security researchers (including Google's 2024-25 disclosures on Gemini for Workspace) demonstrated that hidden text in an email — invisible to the human reader, e.g. white-on-white — can instruct an AI assistant summarising the inbox to leak data or mark phishing as safe.",
        "body_ta": "மனிதக் கண்ணுக்குத் தெரியாத மறைந்த உரை (எ.கா. வெள்ளையில் வெள்ளை) இன்பாக்ஸைச் சுருக்கும் AI உதவியாளரை தரவைக் கசியவோ ஃபிஷிங்கை பாதுகாப்பாகக் குறிக்கவோ கட்டளையிடக்கூடும் என Google இன் 2024-25 Gemini for Workspace வெளிப்படுத்தல்கள் உள்ளிட்ட பாதுகாப்பு ஆய்வாளர்கள் நிரூபித்துள்ளனர்.",
        "body_hi": "सुरक्षा शोधकर्ताओं (Google के 2024-25 Gemini for Workspace खुलासों सहित) ने दिखाया कि ईमेल में छिपा टेक्स्ट (जैसे सफ़ेद पर सफ़ेद, इंसान को न दिखने वाला) इनबॉक्स सारांशित करने वाले AI असिस्टेंट को डेटा लीक करने या फ़िशिंग को सुरक्षित बताने का निर्देश दे सकता है।",
        "catch": ["ai_prompt_injection", "html_hidden_text"], "match": "attack_prompt_injection",
    },
]

with tab_cases:
    st.markdown(f"### {_( 'cases_title')}")
    st.caption(_("cases_intro"))
    idx = {"en": 0, "ta": 1, "hi": 2}[L()]
    for case in CASES:
        title = case[f"title_{L()}"]
        body = case[f"body_{L()}"]
        st.markdown(f'<div class="case-card"><h4>{title}</h4><p>{body}</p>', unsafe_allow_html=True)
        tags = "".join(f'<span class="case-tag">{__import__("html").escape(render_finding({"id":c,"params":{},"positive":False},L())[0])}</span>'
                       for c in case["catch"])
        st.markdown(f'<div><b>{_( "would_catch")}:</b> {tags}</div></div>', unsafe_allow_html=True)
        if case["match"]:
            path = os.path.join(SAMPLES_DIR, case["match"] + ".eml")
            if os.path.exists(path) and st.button(f"▶ {_( 'tab_inspect')}: {title[:40]}", key="case_" + case["match"]):
                st.session_state["_jump_sample"] = case["match"]
                st.info(_("mode_sample") + f" → {title}")

    st.markdown(f"#### {_( 'novel_title')}")
    NOVEL_POINTS = {
        "en": """
- **Trilingual understanding**: the same rule engine reads English, Tamil and Hindi scam phrasing, needed because India's phishing traffic is not English-only.
- **An explainable, additive score**: each signal contributes a named, visible weight (noisy-OR fusion) instead of an opaque black-box number, so every point of the score traces to a sentence a person can read.
- **Defence for the reader's AI assistant, not just the reader**: a dedicated check looks for hidden instructions aimed at AI mail tools, an emerging 2024-25 attack class most consumer scanners do not yet cover.
- **Live inbox watchdog with a strict read-only guarantee**: continuous protection without ever marking mail as read or touching it.
- **SSRF-safe certificate and URL inspection**: every host is resolved and checked against private/internal ranges before this server connects to it.
""",
        "ta": """
- **முத்தமிழ் புரிதல்**: ஆங்கிலம், தமிழ், இந்தி மூன்றிலும் மோசடி மொழிநடையை ஒரே விதி இயந்திரம் புரிந்துகொள்கிறது — இந்தியாவின் ஃபிஷிங் போக்குவரத்து ஆங்கிலத்தில் மட்டும் இல்லை என்பதால் அவசியம்.
- **விளக்கக்கூடிய, கூட்டு மதிப்பெண்**: ஒவ்வொரு அறிகுறியும் பெயரிடப்பட்ட, தெரியும் எடையுடன் பங்களிக்கிறது (noisy-OR இணைப்பு); மதிப்பெண் ஒரு மனிதர் படிக்கக்கூடிய வாக்கியத்திற்கு எப்போதும் மீளக்கூடியது.
- **வாசகரின் AI உதவியாளருக்கும் பாதுகாப்பு**: AI அஞ்சல் கருவிகளை நோக்கிய மறைந்த கட்டளைகளை ஒரு தனிச் சோதனை கண்டறியும் — பெரும்பாலான நுகர்வோர் ஸ்கேனர்கள் இன்னும் கவனிக்காத 2024-25 புதிய தாக்குதல் வகை.
- **கண்டிப்பான படிக்க-மட்டும் உத்தரவாதத்துடன் நேரடி இன்பாக்ஸ் கண்காணிப்பு**: அஞ்சலைத் தொடாமலேயே தொடர் பாதுகாப்பு.
- **SSRF-பாதுகாப்பான சான்றிதழ் & URL ஆய்வு**: இணைக்கும் முன் ஒவ்வொரு ஹோஸ்ட்டும் தனிப்பட்ட/உள் வரம்புகளுக்கு எதிராகச் சரிபார்க்கப்படுகிறது.
""",
        "hi": """
- **त्रिभाषी समझ**: अंग्रेज़ी, तमिल और हिंदी तीनों में ठगी की भाषा को एक ही नियम-इंजन पहचानता है — भारत का फ़िशिंग ट्रैफ़िक सिर्फ़ अंग्रेज़ी में नहीं है इसलिए ज़रूरी।
- **समझाने योग्य, जोड़ने वाला स्कोर**: हर संकेत नामित, दिखने वाले वज़न के साथ जुड़ता है (noisy-OR फ़्यूज़न); स्कोर का हर अंश हमेशा किसी पढ़ने लायक वाक्य तक वापस जाता है।
- **पाठक के AI असिस्टेंट की भी सुरक्षा**: AI मेल टूल के लिए छिपे निर्देशों की एक अलग जाँच — 2024-25 का नया हमला वर्ग जिसे ज़्यादातर उपभोक्ता स्कैनर अभी नहीं पकड़ते।
- **सख्त पढ़ने-तक-सीमित गारंटी वाली लाइव इनबॉक्स निगरानी**: मेल को छुए बिना लगातार सुरक्षा।
- **SSRF-सुरक्षित प्रमाणपत्र और URL जाँच**: कनेक्ट करने से पहले हर होस्ट को निजी/आंतरिक रेंज के विरुद्ध जाँचा जाता है।
""",
    }
    st.markdown(NOVEL_POINTS[L()])

st.markdown(f'<div class="pf-footer">{_( "footer")}</div>', unsafe_allow_html=True)
