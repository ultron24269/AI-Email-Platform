"""
Everything a person reads, in English, Tamil and Hindi.

UI[key] = (english, tamil, hindi)

Analyses are language-neutral (findings + parameters), so the language can be
switched at any time without re-running a scan.
"""

from .findings import CATALOG, GROUPS, severity
from .i18n_findings import FINDINGS

LANGS = ["en", "ta", "hi"]
LANG_NAMES = {"en": "English", "ta": "தமிழ்", "hi": "हिन्दी"}
_IDX = {"en": 0, "ta": 1, "hi": 2}


class _Safe(dict):
    def __missing__(self, key):
        return "?"


def t(key, lang="en", **kw):
    row = UI.get(key)
    if row is None:
        return key
    text = row[_IDX.get(lang, 0)]
    return text.format_map(_Safe(kw)) if kw else text


# --------------------------------------------------------------------------
# Interface text
# --------------------------------------------------------------------------

UI = {
    # ---- brand & hero ------------------------------------------------------
    "app_name": ("AI Email Threat Platform", "AI மின்னஞ்சல் அச்சுறுத்தல் தளம்", "AI ईमेल खतरा पहचान मंच"),
    "hero_title": ("Is this message safe? Get the answer, and the reason.",
                   "இந்தச் செய்தி பாதுகாப்பானதா? பதிலும் காரணமும் இங்கே.",
                   "क्या यह संदेश सुरक्षित है? जवाब भी, कारण भी।"),
    "hero_sub": ("Upload an email, paste an SMS, or connect your inbox. The platform inspects the sender, the words, the links and the website certificates, then explains its verdict in plain language.",
                 "மின்னஞ்சலைப் பதிவேற்றுங்கள், SMS ஐ ஒட்டுங்கள் அல்லது உங்கள் இன்பாக்ஸை இணையுங்கள். அனுப்புநர், சொற்கள், இணைப்புகள், இணையதளச் சான்றிதழ்கள் ஆகியவற்றை ஆராய்ந்து, தீர்ப்பை எளிய மொழியில் விளக்கும்.",
                 "ईमेल अपलोड करें, SMS पेस्ट करें या अपना इनबॉक्स जोड़ें। यह भेजने वाले, शब्दों, लिंक और वेबसाइट प्रमाणपत्रों की जाँच करता है और अपना फ़ैसला सरल भाषा में समझाता है।"),
    "lang_label": ("Language", "மொழி", "भाषा"),
    "postmark_ring": ("INSPECTED BY AI EMAIL THREAT PLATFORM", "AI மின்னஞ்சல் தளத்தால் ஆய்வு", "AI ईमेल मंच द्वारा जाँचा गया"),

    # ---- tabs --------------------------------------------------------------
    "tab_inspect": ("Inspect a message", "செய்தியைச் சோதிக்க", "संदेश जाँचें"),
    "tab_watch": ("Live inbox watchdog", "நேரடி இன்பாக்ஸ் கண்காணிப்பு", "लाइव इनबॉक्स निगरानी"),
    "tab_link": ("Link & certificate check", "இணைப்பு & சான்றிதழ் சோதனை", "लिंक और प्रमाणपत्र जाँच"),
    "tab_cases": ("Case studies", "வழக்கு ஆய்வுகள்", "केस स्टडी"),

    # ---- inspect -----------------------------------------------------------
    "mode_upload": ("Upload an email (.eml)", "மின்னஞ்சலைப் பதிவேற்று (.eml)", "ईमेल अपलोड करें (.eml)"),
    "mode_paste": ("Paste a message", "செய்தியை ஒட்டு", "संदेश पेस्ट करें"),
    "mode_sample": ("Try a sample", "மாதிரியை முயற்சிக்க", "नमूना आज़माएँ"),
    "upload_label": ("Drop a .eml file here", ".eml கோப்பை இங்கே இடுங்கள்", ".eml फ़ाइल यहाँ डालें"),
    "upload_help": ("Gmail: open the mail, tap the three dots, choose Download message. Outlook: File, Save As, .eml.",
                    "Gmail: மின்னஞ்சலைத் திறந்து, மூன்று புள்ளிகளைத் தட்டி, Download message தேர்ந்தெடுங்கள். Outlook: File, Save As, .eml.",
                    "Gmail: मेल खोलें, तीन बिंदुओं पर टैप करें, Download message चुनें। Outlook: File, Save As, .eml।"),
    "paste_label": ("Paste the message text (email, SMS or WhatsApp)", "செய்தி உரையை ஒட்டுங்கள் (மின்னஞ்சல், SMS அல்லது WhatsApp)", "संदेश का टेक्स्ट पेस्ट करें (ईमेल, SMS या WhatsApp)"),
    "paste_placeholder": ("Dear customer, your account will be blocked today. Update KYC at http://…",
                          "அன்புள்ள வாடிக்கையாளர், உங்கள் கணக்கு இன்று முடக்கப்படும். KYC ஐப் புதுப்பிக்க http://…",
                          "प्रिय ग्राहक, आपका खाता आज बंद हो जाएगा। KYC अपडेट करें http://…"),
    "sample_pick": ("Choose a sample", "மாதிரியைத் தேர்ந்தெடுங்கள்", "नमूना चुनें"),
    "s_phish_english_bank": ("Bank phishing (English)", "வங்கி ஃபிஷிங் (ஆங்கிலம்)", "बैंक फ़िशिंग (अंग्रेज़ी)"),
    "s_phish_tamil_electricity": ("Electricity-cut scam (Tamil)", "மின் துண்டிப்பு மோசடி (தமிழ்)", "बिजली कटने की ठगी (तमिल)"),
    "s_phish_hindi_kyc": ("KYC / OTP scam (Hindi)", "KYC / OTP மோசடி (இந்தி)", "KYC / OTP ठगी (हिंदी)"),
    "s_attack_prompt_injection": ("Attack on AI assistants", "AI உதவியாளர்கள் மீதான தாக்குதல்", "AI असिस्टेंट पर हमला"),
    "s_attack_double_extension": ("Disguised malware attachment", "மறைமுக தீம்பொருள் இணைப்பு", "भेष बदला मैलवेयर अटैचमेंट"),
    "s_legit_bank_alert": ("Genuine bank alert", "உண்மையான வங்கி அறிவிப்பு", "असली बैंक अलर्ट"),
    "s_legit_personal": ("Ordinary personal email", "சாதாரண தனிப்பட்ட மின்னஞ்சல்", "सामान्य निजी ईमेल"),
    "opt_certs": ("Check the certificates of links (needs internet)", "இணைப்புகளின் சான்றிதழ்களைச் சோதி (இணையம் தேவை)", "लिंक के प्रमाणपत्र जाँचें (इंटरनेट चाहिए)"),
    "opt_geo": ("Trace the sender's IP location", "அனுப்புநரின் IP இடத்தைக் கண்டறி", "भेजने वाले के IP की लोकेशन पता करें"),
    "opt_vt": ("Ask VirusTotal about links and IPs", "இணைப்புகள், IP பற்றி VirusTotal ஐக் கேள்", "लिंक और IP के बारे में VirusTotal से पूछें"),
    "opt_ai": ("Add a second opinion from Claude AI (sends the message text to Anthropic)",
               "Claude AI யிடம் இரண்டாவது கருத்தைச் சேர் (செய்தி உரை Anthropic க்கு அனுப்பப்படும்)",
               "Claude AI से दूसरी राय जोड़ें (संदेश का टेक्स्ट Anthropic को भेजा जाएगा)"),
    "btn_analyze": ("Inspect this message", "இந்தச் செய்தியைச் சோதி", "इस संदेश की जाँच करें"),
    "analyzing": ("Inspecting the message…", "செய்தி ஆய்வு செய்யப்படுகிறது…", "संदेश की जाँच हो रही है…"),
    "nothing_to_scan": ("Add a file or some text first.", "முதலில் ஒரு கோப்பு அல்லது உரையைச் சேருங்கள்.", "पहले कोई फ़ाइल या टेक्स्ट जोड़ें।"),
    "parse_error": ("This file could not be read as an email.", "இந்தக் கோப்பை மின்னஞ்சலாகப் படிக்க முடியவில்லை.", "इस फ़ाइल को ईमेल के रूप में पढ़ा नहीं जा सका।"),

    # ---- result ------------------------------------------------------------
    "score_label": ("Risk score", "ஆபத்து மதிப்பெண்", "जोखिम स्कोर"),
    "checks_run": ("{n} checks run", "{n} சோதனைகள் செய்யப்பட்டன", "{n} जाँचें की गईं"),
    "flagged_n": ("{n} flagged", "{n} குறிக்கப்பட்டவை", "{n} चिह्नित"),
    "sec_why": ("Reasons", "காரணங்கள்", "कारण"),
    "sec_all": ("All findings", "அனைத்து கண்டுபிடிப்புகள்", "सभी निष्कर्ष"),
    "sec_good": ("What looked fine", "நன்றாகத் தெரிந்தவை", "जो ठीक दिखा"),
    "sec_groups": ("What we checked", "நாங்கள் சோதித்தவை", "हमने क्या जाँचा"),
    "sec_advice": ("What to do now", "இப்போது என்ன செய்வது", "अब क्या करें"),
    "sec_details": ("Technical evidence", "தொழில்நுட்ப ஆதாரம்", "तकनीकी सबूत"),
    "sec_download": ("Forensic report", "தடயவியல் அறிக்கை", "फ़ॉरेंसिक रिपोर्ट"),
    "sec_ai": ("Second opinion from Claude AI", "Claude AI யின் இரண்டாவது கருத்து", "Claude AI की दूसरी राय"),
    "more_reasons": ("Show all {n} findings", "அனைத்து {n} கண்டுபிடிப்புகளையும் காட்டு", "सभी {n} निष्कर्ष दिखाएँ"),
    "evidence": ("Evidence", "ஆதாரம்", "सबूत"),
    "occurs_n": ("seen {n} times", "{n} முறை காணப்பட்டது", "{n} बार दिखा"),
    "det_message": ("Message facts", "செய்தித் தகவல்கள்", "संदेश की जानकारी"),
    "det_links": ("Links and certificates", "இணைப்புகளும் சான்றிதழ்களும்", "लिंक और प्रमाणपत्र"),
    "det_attach": ("Attachments (with SHA-256)", "இணைப்புக் கோப்புகள் (SHA-256 உடன்)", "अटैचमेंट (SHA-256 के साथ)"),
    "det_geo": ("Where the message travelled from", "செய்தி எங்கிருந்து வந்தது", "संदेश कहाँ से आया"),
    "det_ti": ("Threat intelligence (VirusTotal)", "அச்சுறுத்தல் தகவல் (VirusTotal)", "खतरा सूचना (VirusTotal)"),
    "det_timeline": ("Forensic timeline", "தடயவியல் காலவரிசை", "फ़ॉरेंसिक टाइमलाइन"),
    "f_from": ("From", "அனுப்புநர்", "भेजने वाला"),
    "f_to": ("To", "பெறுநர்", "पाने वाला"),
    "f_subject": ("Subject", "பொருள்", "विषय"),
    "f_date": ("Date", "தேதி", "तारीख"),
    "f_reply": ("Reply-To", "பதில் முகவரி", "जवाब का पता"),
    "f_return": ("Return-Path", "திரும்பும் பாதை", "वापसी पथ"),
    "f_msgid": ("Message-ID", "செய்தி எண்", "संदेश आईडी"),
    "f_sha": ("SHA-256 of the message", "செய்தியின் SHA-256", "संदेश का SHA-256"),
    "f_lang": ("Written in", "எழுதப்பட்ட மொழி", "किस भाषा में लिखा"),
    "f_auth": ("Sender checks (SPF / DKIM / DMARC)", "அனுப்புநர் சோதனைகள் (SPF / DKIM / DMARC)", "भेजने वाले की जाँच (SPF / DKIM / DMARC)"),
    "f_source": ("Source", "மூலம்", "स्रोत"),
    "src_eml": ("Email file with headers", "தலைப்புகளுடன் மின்னஞ்சல் கோப்பு", "हेडर वाली ईमेल फ़ाइल"),
    "src_text": ("Pasted text (no headers)", "ஒட்டிய உரை (தலைப்புகள் இல்லை)", "पेस्ट किया टेक्स्ट (हेडर नहीं)"),
    "col_link": ("Link", "இணைப்பு", "लिंक"),
    "col_verdict": ("Verdict", "தீர்ப்பு", "फ़ैसला"),
    "col_cert": ("Certificate", "சான்றிதழ்", "प्रमाणपत्र"),
    "col_issuer": ("Issuer", "வழங்கியவர்", "जारीकर्ता"),
    "col_expires": ("Expires", "காலாவதி", "समाप्ति"),
    "col_days": ("Days left", "மீதமுள்ள நாட்கள்", "बचे दिन"),
    "col_file": ("File", "கோப்பு", "फ़ाइल"),
    "col_size": ("Size", "அளவு", "आकार"),
    "col_score": ("Score", "மதிப்பெண்", "स्कोर"),
    "cert_none": ("not checked", "சோதிக்கப்படவில்லை", "जाँचा नहीं गया"),
    "cert_ok": ("valid", "செல்லுபடி", "वैध"),
    "cert_bad": ("problem", "சிக்கல்", "समस्या"),
    "cert_na": ("no HTTPS", "HTTPS இல்லை", "HTTPS नहीं"),
    "no_links": ("No links in this message.", "இந்தச் செய்தியில் இணைப்புகள் இல்லை.", "इस संदेश में कोई लिंक नहीं।"),
    "no_attach": ("No attachments.", "இணைப்புக் கோப்புகள் இல்லை.", "कोई अटैचमेंट नहीं।"),
    "geo_none": ("No public IP addresses found in the headers.", "தலைப்புகளில் பொது IP முகவரிகள் இல்லை.", "हेडर में कोई सार्वजनिक IP पता नहीं मिला।"),
    "unavailable": ("not available", "கிடைக்கவில்லை", "उपलब्ध नहीं"),
    "dl_html": ("Download forensic report (HTML)", "தடயவியல் அறிக்கையைப் பதிவிறக்கு (HTML)", "फ़ॉरेंसिक रिपोर्ट डाउनलोड करें (HTML)"),
    "dl_pdf": ("Download English PDF report", "ஆங்கில PDF அறிக்கையைப் பதிவிறக்கு", "अंग्रेज़ी PDF रिपोर्ट डाउनलोड करें"),
    "dl_json": ("Download evidence (JSON)", "ஆதாரத்தைப் பதிவிறக்கு (JSON)", "सबूत डाउनलोड करें (JSON)"),
    "report_hint": ("The HTML report is in the language you selected. Open it in a browser and choose Print, then Save as PDF, to get a PDF in Tamil or Hindi.",
                    "HTML அறிக்கை நீங்கள் தேர்ந்த மொழியில் உள்ளது. அதை உலாவியில் திறந்து Print, பின் Save as PDF தேர்ந்தால் தமிழ் அல்லது இந்தியில் PDF கிடைக்கும்.",
                    "HTML रिपोर्ट आपकी चुनी भाषा में है। इसे ब्राउज़र में खोलकर Print, फिर Save as PDF चुनें तो तमिल या हिंदी में PDF मिलेगा।"),
    "report_preview": ("Preview the report", "அறிக்கையை முன்னோட்டம் பார்", "रिपोर्ट का पूर्वावलोकन"),
    "ai_disabled": ("Add ANTHROPIC_API_KEY to your environment or Streamlit secrets to enable this.",
                    "இதை இயக்க உங்கள் சூழலில் அல்லது Streamlit secrets இல் ANTHROPIC_API_KEY ஐச் சேருங்கள்.",
                    "इसे चालू करने के लिए अपने एनवायरनमेंट या Streamlit secrets में ANTHROPIC_API_KEY जोड़ें।"),
    "ai_failed": ("The AI second opinion could not be fetched. The verdict above does not depend on it.",
                  "AI இரண்டாவது கருத்தைப் பெற முடியவில்லை. மேலே உள்ள தீர்ப்பு அதைச் சார்ந்ததல்ல.",
                  "AI की दूसरी राय नहीं मिल सकी। ऊपर का फ़ैसला उस पर निर्भर नहीं है।"),
    "ai_note": ("Written by Claude from the evidence above. The score and verdict come from the local engine, not from this text.",
                "மேலே உள்ள ஆதாரங்களிலிருந்து Claude எழுதியது. மதிப்பெண்ணும் தீர்ப்பும் உள்ளூர் இயந்திரத்திலிருந்து வருகின்றன, இந்த உரையிலிருந்து அல்ல.",
                "ऊपर के सबूतों से Claude ने लिखा। स्कोर और फ़ैसला स्थानीय इंजन से आते हैं, इस टेक्स्ट से नहीं।"),
    "limit_note": ("Only the message text was checked (no email headers), so the sender could not be verified.",
                   "செய்தி உரை மட்டுமே சோதிக்கப்பட்டது (மின்னஞ்சல் தலைப்புகள் இல்லை); எனவே அனுப்புநரை உறுதிசெய்ய இயலவில்லை.",
                   "सिर्फ़ संदेश का टेक्स्ट जाँचा गया (ईमेल हेडर नहीं), इसलिए भेजने वाले की पुष्टि नहीं हो सकी।"),
    "conf_high": ("High confidence", "அதிக நம்பகத்தன்மை", "उच्च विश्वास"),
    "conf_medium": ("Medium confidence", "நடுத்தர நம்பகத்தன்மை", "मध्यम विश्वास"),
    "conf_low": ("Limited confidence", "குறைந்த நம்பகத்தன்மை", "सीमित विश्वास"),
    "grp_clear": ("Clear", "தெளிவு", "साफ़"),
    "grp_warn": ("Warning", "எச்சரிக்கை", "चेतावनी"),
    "grp_danger": ("Danger", "ஆபத்து", "खतरा"),
    "grp_skipped": ("Not checked", "சோதிக்கப்படவில்லை", "जाँचा नहीं गया"),
    "sev_high": ("High", "அதிகம்", "उच्च"),
    "sev_medium": ("Medium", "நடுத்தரம்", "मध्यम"),
    "sev_low": ("Low", "குறைவு", "कम"),
    "sev_info": ("Info", "தகவல்", "जानकारी"),
    "disclaimer": ("No tool can guarantee 100% safety. This analysis supports your judgement; it does not replace it. When in doubt, contact the organisation through a number or website you already know.",
                   "எந்தக் கருவியும் 100% பாதுகாப்பை உறுதிப்படுத்த முடியாது. இந்த ஆய்வு உங்கள் தீர்மானத்திற்குத் துணை; அதற்கு மாற்றல்ல. சந்தேகமிருந்தால், உங்களுக்கு ஏற்கனவே தெரிந்த எண் அல்லது இணையதளம் வழியாக அந்த நிறுவனத்தைத் தொடர்பு கொள்ளுங்கள்.",
                   "कोई भी टूल 100% सुरक्षा की गारंटी नहीं दे सकता। यह विश्लेषण आपके विवेक की सहायता करता है, उसकी जगह नहीं लेता। संदेह हो तो उस संस्था से उस नंबर या वेबसाइट पर संपर्क करें जिसे आप पहले से जानते हैं।"),

    # ---- inbox watchdog -----------------------------------------------------
    "watch_intro": ("Connect a mailbox and every new message is inspected automatically. The connection is read-only: nothing is deleted, moved or marked as read, and your password lives only in this browser session.",
                    "ஒரு அஞ்சல்பெட்டியை இணையுங்கள்; ஒவ்வொரு புதிய செய்தியும் தானாகவே ஆராயப்படும். இணைப்பு படிக்க மட்டும்: எதுவும் அழிக்கப்படாது, நகர்த்தப்படாது, படித்ததாகக் குறிக்கப்படாது; உங்கள் கடவுச்சொல் இந்த உலாவி அமர்வில் மட்டுமே இருக்கும்.",
                    "कोई मेलबॉक्स जोड़ें और हर नया संदेश अपने आप जाँचा जाएगा। कनेक्शन सिर्फ़ पढ़ने के लिए है: कुछ भी हटाया, हिलाया या 'पढ़ा हुआ' चिह्नित नहीं होता, और आपका पासवर्ड सिर्फ़ इस ब्राउज़र सत्र में रहता है।"),
    "watch_email": ("Email address", "மின்னஞ்சல் முகவரி", "ईमेल पता"),
    "watch_password": ("App password (not your normal password)", "செயலி கடவுச்சொல் (உங்கள் வழக்கமான கடவுச்சொல் அல்ல)", "ऐप पासवर्ड (आपका सामान्य पासवर्ड नहीं)"),
    "watch_host": ("IMAP server", "IMAP சேவையகம்", "IMAP सर्वर"),
    "watch_every": ("Check every", "இத்தனை நொடிக்கு ஒருமுறை சோதி", "हर इतने सेकंड में जाँचें"),
    "watch_start": ("Start watching", "கண்காணிக்கத் தொடங்கு", "निगरानी शुरू करें"),
    "watch_stop": ("Stop and forget the password", "நிறுத்து, கடவுச்சொல்லை மறந்துவிடு", "रोकें और पासवर्ड भूल जाएँ"),
    "watch_now": ("Check now", "இப்போதே சோதி", "अभी जाँचें"),
    "watch_on": ("Watching {user}", "{user} கண்காணிக்கப்படுகிறது", "{user} की निगरानी जारी है"),
    "watch_last": ("Last check {time}", "கடைசி சோதனை {time}", "आखिरी जाँच {time}"),
    "watch_scanned": ("Scanned", "ஆராயப்பட்டவை", "जाँचे गए"),
    "watch_empty": ("Waiting for the first message…", "முதல் செய்திக்காகக் காத்திருக்கிறது…", "पहले संदेश की प्रतीक्षा…"),
    "watch_connecting": ("Connecting to your mailbox…", "உங்கள் அஞ்சல்பெட்டியுடன் இணைகிறது…", "आपके मेलबॉक्स से जुड़ रहा है…"),
    "watch_alert": ("Dangerous email arrived: {subject}", "ஆபத்தான மின்னஞ்சல் வந்துள்ளது: {subject}", "खतरनाक ईमेल आया: {subject}"),
    "watch_err_auth": ("The mailbox rejected the login. Gmail and most providers need an app password, not your normal password, and IMAP must be switched on.",
                       "அஞ்சல்பெட்டி உள்நுழைவை நிராகரித்தது. Gmail உள்ளிட்டவற்றுக்கு வழக்கமான கடவுச்சொல் அல்ல, செயலி கடவுச்சொல் தேவை; IMAP இயக்கப்பட்டிருக்க வேண்டும்.",
                       "मेलबॉक्स ने लॉगिन अस्वीकार किया। Gmail और अधिकांश सेवाओं को सामान्य पासवर्ड नहीं, ऐप पासवर्ड चाहिए, और IMAP चालू होना चाहिए।"),
    "watch_err_conn": ("Could not reach the mail server. Check the server name and your internet connection.",
                       "அஞ்சல் சேவையகத்தை அணுக முடியவில்லை. சேவையகப் பெயரையும் இணைய இணைப்பையும் சரிபாருங்கள்.",
                       "मेल सर्वर तक नहीं पहुँचा जा सका। सर्वर का नाम और इंटरनेट कनेक्शन जाँचें।"),
    "watch_help_title": ("How to get an app password (Gmail)", "செயலி கடவுச்சொல்லைப் பெறுவது எப்படி (Gmail)", "ऐप पासवर्ड कैसे पाएँ (Gmail)"),
    "watch_help": ("1. Turn on 2-Step Verification in your Google Account.\n2. Open Google Account, Security, App passwords, and create one named for this app.\n3. Paste the 16-character code above. Gmail already has IMAP enabled for new accounts.\n4. Use a spare or test mailbox for demonstrations.",
                   "1. உங்கள் Google கணக்கில் 2-Step Verification ஐ இயக்குங்கள்.\n2. Google Account, Security, App passwords சென்று இந்தச் செயலிக்கு ஒன்றை உருவாக்குங்கள்.\n3. அந்த 16 எழுத்து குறியீட்டை மேலே ஒட்டுங்கள். புதிய கணக்குகளில் Gmail இல் IMAP ஏற்கனவே இயக்கத்தில் இருக்கும்.\n4. செயல்விளக்கங்களுக்கு உதிரி அல்லது சோதனை அஞ்சல்பெட்டியைப் பயன்படுத்துங்கள்.",
                   "1. अपने Google खाते में 2-Step Verification चालू करें।\n2. Google Account, Security, App passwords खोलकर इस ऐप के नाम से एक बनाएँ।\n3. वह 16 अक्षरों का कोड ऊपर पेस्ट करें। नए खातों में Gmail पर IMAP पहले से चालू होता है।\n4. प्रदर्शन के लिए अतिरिक्त या टेस्ट मेलबॉक्स इस्तेमाल करें।"),
    "watch_privacy": ("Only messages are read. Nothing is stored on disk, and the analysis stays in this session.",
                      "செய்திகள் மட்டுமே படிக்கப்படுகின்றன. வட்டில் எதுவும் சேமிக்கப்படாது; ஆய்வு இந்த அமர்விலேயே இருக்கும்.",
                      "सिर्फ़ संदेश पढ़े जाते हैं। डिस्क पर कुछ भी सहेजा नहीं जाता; विश्लेषण इसी सत्र में रहता है।"),

    # ---- link check ---------------------------------------------------------
    "link_intro": ("Paste a web address. The platform reads its security certificate, expiry date, HTTPS setup, redirects and age, then explains whether it is safe to open.",
                   "ஒரு இணைய முகவரியை ஒட்டுங்கள். அதன் பாதுகாப்புச் சான்றிதழ், காலாவதி தேதி, HTTPS அமைப்பு, திசைதிருப்பல்கள், வயது ஆகியவற்றை ஆராய்ந்து, அதைத் திறப்பது பாதுகாப்பானதா என்று விளக்கும்.",
                   "कोई वेब पता पेस्ट करें। यह उसका सुरक्षा प्रमाणपत्र, समाप्ति तिथि, HTTPS सेटअप, रीडायरेक्ट और उम्र पढ़कर बताता है कि उसे खोलना सुरक्षित है या नहीं।"),
    "link_label": ("Web address (one per line)", "இணைய முகவரி (ஒரு வரிக்கு ஒன்று)", "वेब पता (हर पंक्ति में एक)"),
    "link_placeholder": ("https://example.com", "https://example.com", "https://example.com"),
    "link_btn": ("Check this link", "இந்த இணைப்பைச் சோதி", "इस लिंक की जाँच करें"),
    "link_deep": ("Deep scan: follow redirects and look up the domain's age", "ஆழ்ந்த ஸ்கேன்: திசைதிருப்பல்களைப் பின்தொடர்ந்து டொமைனின் வயதைப் பார்", "गहरी जाँच: रीडायरेक्ट फ़ॉलो करें और डोमेन की उम्र देखें"),
    "link_vt": ("Also ask VirusTotal", "VirusTotal யிடமும் கேள்", "VirusTotal से भी पूछें"),
    "link_none": ("Enter at least one web address.", "குறைந்தது ஒரு இணைய முகவரியை உள்ளிடுங்கள்.", "कम से कम एक वेब पता दर्ज करें।"),
    "link_private_note": ("Addresses that point to private or internal networks are never contacted.",
                          "தனிப்பட்ட அல்லது உள் வலையமைப்புகளைக் குறிக்கும் முகவரிகள் ஒருபோதும் தொடர்பு கொள்ளப்படாது.",
                          "निजी या आंतरिक नेटवर्क की ओर जाने वाले पते कभी संपर्क में नहीं लिए जाते।"),
    "cert_card": ("Security certificate", "பாதுகாப்புச் சான்றிதழ்", "सुरक्षा प्रमाणपत्र"),
    "c_trusted": ("Trusted by browsers", "உலாவிகளால் நம்பப்படுகிறது", "ब्राउज़र द्वारा भरोसेमंद"),
    "c_https": ("HTTPS", "HTTPS", "HTTPS"),
    "c_issuer": ("Issued by", "வழங்கியவர்", "जारीकर्ता"),
    "c_subject": ("Issued to", "வழங்கப்பட்டவர்", "जारी किया गया"),
    "c_from": ("Valid from", "செல்லுபடி தொடக்கம்", "वैध आरंभ"),
    "c_to": ("Expires on", "காலாவதியாகும் தேதி", "समाप्ति तिथि"),
    "c_left": ("Days remaining", "மீதமுள்ள நாட்கள்", "बचे हुए दिन"),
    "c_host": ("Matches the site name", "தளப் பெயருடன் பொருந்துகிறது", "साइट के नाम से मेल"),
    "c_tls": ("Connection protocol", "இணைப்பு நெறிமுறை", "कनेक्शन प्रोटोकॉल"),
    "c_key": ("Key", "விசை", "कुंजी"),
    "c_sig": ("Signature algorithm", "கையொப்ப படிமுறை", "हस्ताक्षर एल्गोरिद्म"),
    "c_names": ("Names covered", "உள்ளடக்கிய பெயர்கள்", "शामिल नाम"),
    "c_sha": ("Fingerprint (SHA-256)", "கைரேகை (SHA-256)", "फ़िंगरप्रिंट (SHA-256)"),
    "c_hsts": ("HSTS (forces HTTPS)", "HSTS (HTTPS ஐக் கட்டாயப்படுத்தும்)", "HSTS (HTTPS अनिवार्य)"),
    "c_age": ("Domain age", "டொமைன் வயது", "डोमेन की उम्र"),
    "c_hops": ("Redirects", "திசைதிருப்பல்கள்", "रीडायरेक्ट"),
    "c_ips": ("Server addresses", "சேவையக முகவரிகள்", "सर्वर पते"),
    "c_ml": ("AI model: phishing probability", "AI மாதிரி: ஃபிஷிங் நிகழ்தகவு", "AI मॉडल: फ़िशिंग संभावना"),
    "yes": ("Yes", "ஆம்", "हाँ"),
    "no": ("No", "இல்லை", "नहीं"),
    "days": ("days", "நாட்கள்", "दिन"),
    "unknown": ("unknown", "தெரியவில்லை", "अज्ञात"),
    "no_cert_data": ("No certificate could be read (the address is not HTTPS, not reachable, or blocked).",
                     "சான்றிதழைப் படிக்க முடியவில்லை (முகவரி HTTPS அல்ல, அணுக முடியவில்லை அல்லது தடுக்கப்பட்டது).",
                     "प्रमाणपत्र पढ़ा नहीं जा सका (पता HTTPS नहीं है, पहुँच से बाहर है या रोका गया)।"),

    # ---- case studies -------------------------------------------------------
    "cases_title": ("Real attacks this platform is built to catch", "இந்தத் தளம் பிடிக்க உருவாக்கப்பட்ட உண்மையான தாக்குதல்கள்", "असली हमले जिन्हें पकड़ने के लिए यह मंच बना है"),
    "cases_intro": ("Each case is a documented incident. The last line of each case shows which check in this platform would have raised the alarm.",
                    "ஒவ்வொன்றும் பதிவு செய்யப்பட்ட சம்பவம். ஒவ்வொரு வழக்கின் கடைசி வரியும் இந்தத் தளத்தின் எந்தச் சோதனை எச்சரிக்கை ஒலித்திருக்கும் என்பதைக் காட்டும்.",
                    "हर मामला दर्ज किया गया असली घटनाक्रम है। हर मामले की आखिरी पंक्ति बताती है कि इस मंच की कौन-सी जाँच चेतावनी देती।"),
    "novel_title": ("What is new here", "இங்கே புதியது என்ன", "यहाँ नया क्या है"),
    "would_catch": ("This platform would catch it with", "இந்தத் தளம் இதைப் பிடிக்கும் வழி", "यह मंच इसे पकड़ता"),
    "gap_title": ("Where existing tools fall short", "இருக்கும் கருவிகள் எங்கே குறைகின்றன", "मौजूदा टूल कहाँ कम पड़ते हैं"),

    # ---- footer -------------------------------------------------------------
    "footer": ("Built for people, not just analysts. Every score can be traced to a reason you can read.",
               "பகுப்பாய்வாளர்களுக்கு மட்டுமல்ல, மக்களுக்காக உருவாக்கப்பட்டது. ஒவ்வொரு மதிப்பெண்ணும் நீங்கள் படிக்கக்கூடிய காரணத்தைக் கொண்டுள்ளது.",
               "सिर्फ़ विश्लेषकों के लिए नहीं, आम लोगों के लिए बना। हर स्कोर के पीछे ऐसा कारण है जिसे आप पढ़ सकते हैं।"),
    "help_india": ("India: report cyber fraud at cybercrime.gov.in or call 1930.",
                   "இந்தியா: சைபர் மோசடியை cybercrime.gov.in இல் புகாரளியுங்கள் அல்லது 1930 ஐ அழைக்கவும்.",
                   "भारत: साइबर ठगी की शिकायत cybercrime.gov.in पर करें या 1930 पर कॉल करें।"),
}

# --------------------------------------------------------------------------
# Verdicts, advice, groups
# --------------------------------------------------------------------------

VERDICT = {
    "safe": {
        "word": ("Safe to use", "பயன்படுத்த பாதுகாப்பானது", "उपयोग के लिए सुरक्षित"),
        "stamp": ("SAFE", "பாதுகாப்பு", "सुरक्षित"),
        "headline": ("No threat signals found. This appears safe to use.",
                     "அச்சுறுத்தல் அறிகுறிகள் எதுவும் இல்லை. இது பயன்படுத்த பாதுகாப்பாகத் தெரிகிறது.",
                     "खतरे का कोई संकेत नहीं मिला। यह उपयोग के लिए सुरक्षित लगता है।"),
        "lead": ("Why it looks safe", "ஏன் பாதுகாப்பாகத் தெரிகிறது", "यह सुरक्षित क्यों लगता है"),
        "advice": ("Even so, stay careful with unexpected requests for money or codes. No tool can guarantee 100% safety.",
                   "இருப்பினும், எதிர்பாராத பணம் அல்லது குறியீடு கோரிக்கைகளில் கவனமாக இருங்கள். எந்தக் கருவியும் 100% பாதுகாப்பை உறுதிப்படுத்த முடியாது.",
                   "फिर भी, पैसे या कोड की अप्रत्याशित माँग पर सावधान रहें। कोई भी टूल 100% सुरक्षा की गारंटी नहीं दे सकता।"),
    },
    "suspicious": {
        "word": ("Suspicious", "சந்தேகத்திற்குரியது", "संदिग्ध"),
        "stamp": ("CAUTION", "எச்சரிக்கை", "सावधान"),
        "headline": ("This looks suspicious. Verify it before you act.",
                     "இது சந்தேகத்திற்குரியது. செயல்படும் முன் சரிபாருங்கள்.",
                     "यह संदिग्ध लगता है। कोई कदम उठाने से पहले जाँच लें।"),
        "lead": ("Why it looks suspicious", "ஏன் சந்தேகத்திற்குரியது", "यह संदिग्ध क्यों है"),
        "advice": ("Do not click links or open attachments yet. Contact the sender through an official number or website you already know, not the one in this message. If it claims to be your bank, open the bank's app directly.",
                   "இணைப்புகளைக் கிளிக் செய்யவோ இணைப்புக் கோப்புகளைத் திறக்கவோ வேண்டாம். அனுப்புநரை உங்களுக்கு ஏற்கனவே தெரிந்த அதிகாரப்பூர்வ எண் அல்லது இணையதளம் வழியாகத் தொடர்பு கொள்ளுங்கள்; இந்தச் செய்தியில் உள்ளதன் மூலம் அல்ல. வங்கி என்று கூறினால் வங்கியின் செயலியை நேரடியாகத் திறங்கள்.",
                   "अभी लिंक पर क्लिक न करें और अटैचमेंट न खोलें। भेजने वाले से किसी जाने-पहचाने आधिकारिक नंबर या वेबसाइट पर संपर्क करें, इस संदेश वाले पर नहीं। अगर यह बैंक होने का दावा करे तो बैंक का ऐप सीधे खोलें।"),
    },
    "dangerous": {
        "word": ("Dangerous", "ஆபத்தானது", "खतरनाक"),
        "stamp": ("DANGER", "ஆபத்து", "खतरा"),
        "headline": ("This is dangerous. Do not click, reply or open anything.",
                     "இது ஆபத்தானது. எதையும் கிளிக் செய்யவோ, பதிலளிக்கவோ, திறக்கவோ வேண்டாம்.",
                     "यह खतरनाक है। कुछ भी क्लिक, जवाब या ओपन न करें।"),
        "lead": ("Why it is dangerous", "ஏன் ஆபத்தானது", "यह खतरनाक क्यों है"),
        "advice": ("Do not click any link, open attachments or reply. Never share an OTP, password or card details. Delete the message. If you already responded, change your passwords and call your bank. In India, report at cybercrime.gov.in or call 1930.",
                   "எந்த இணைப்பையும் கிளிக் செய்யவோ, இணைப்புக் கோப்புகளைத் திறக்கவோ, பதிலளிக்கவோ வேண்டாம். OTP, கடவுச்சொல், அட்டை விவரங்களை ஒருபோதும் பகிராதீர்கள். செய்தியை நீக்குங்கள். ஏற்கனவே பதிலளித்திருந்தால் கடவுச்சொற்களை மாற்றி உங்கள் வங்கியை அழையுங்கள். இந்தியாவில் cybercrime.gov.in இல் புகாரளியுங்கள் அல்லது 1930 ஐ அழைக்கவும்.",
                   "किसी भी लिंक पर क्लिक न करें, अटैचमेंट न खोलें और जवाब न दें। OTP, पासवर्ड या कार्ड की जानकारी कभी साझा न करें। संदेश हटा दें। यदि आप पहले ही जवाब दे चुके हैं तो पासवर्ड बदलें और अपने बैंक को कॉल करें। भारत में cybercrime.gov.in पर शिकायत करें या 1930 पर कॉल करें।"),
    },
}

GROUP_TEXT = {
    "auth": (("Sender authentication", "SPF, DKIM and DMARC: did the mail really come from the domain it claims?"),
             ("அனுப்புநர் அங்கீகாரம்", "SPF, DKIM, DMARC: அஞ்சல் உண்மையிலேயே கூறப்படும் டொமைனிலிருந்தே வந்ததா?"),
             ("भेजने वाले का सत्यापन", "SPF, DKIM और DMARC: क्या मेल सच में उसी डोमेन से आया जिसका दावा है?")),
    "sender": (("Sender identity", "Display name, Reply-To, look-alike domains"),
               ("அனுப்புநர் அடையாளம்", "காட்டப்படும் பெயர், Reply-To, ஒத்த தோற்ற டொமைன்கள்"),
               ("भेजने वाले की पहचान", "दिखने वाला नाम, Reply-To, नकली मिलते-जुलते डोमेन")),
    "content": (("Message content", "Pressure, threats, prizes, secret-code requests and India-specific scams, in English, Tamil and Hindi"),
                ("செய்தி உள்ளடக்கம்", "அழுத்தம், மிரட்டல், பரிசு, ரகசிய குறியீடு கோரிக்கைகள், இந்திய மோசடிகள்: ஆங்கிலம், தமிழ், இந்தியில்"),
                ("संदेश की सामग्री", "दबाव, धमकी, इनाम, गुप्त कोड की माँग और भारत की ठगी के तरीके: अंग्रेज़ी, तमिल और हिंदी में")),
    "links": (("Links", "Hidden destinations, look-alike domains, shorteners, IP addresses"),
              ("இணைப்புகள்", "மறைந்த இலக்குகள், ஒத்த தோற்ற டொமைன்கள், சுருக்கிகள், IP முகவரிகள்"),
              ("लिंक", "छिपी मंज़िलें, नकली डोमेन, शॉर्टनर, IP पते")),
    "site": (("Website & certificate", "Certificate validity, expiry, HTTPS, domain age, redirects"),
             ("இணையதளம் & சான்றிதழ்", "சான்றிதழ் செல்லுபடி, காலாவதி, HTTPS, டொமைன் வயது, திசைதிருப்பல்கள்"),
             ("वेबसाइट और प्रमाणपत्र", "प्रमाणपत्र की वैधता, समाप्ति, HTTPS, डोमेन की उम्र, रीडायरेक्ट")),
    "attachments": (("Attachments", "Programs, macros, disguised files, archives"),
                    ("இணைப்புக் கோப்புகள்", "நிரல்கள், மேக்ரோக்கள், மறைமுக கோப்புகள், காப்பகங்கள்"),
                    ("अटैचमेंट", "प्रोग्राम, मैक्रो, भेष बदली फ़ाइलें, आर्काइव")),
    "html": (("Hidden page code", "Forms, scripts and hidden text inside the mail"),
             ("மறைந்த பக்கக் குறிமுறை", "மின்னஞ்சலுக்குள் படிவங்கள், ஸ்கிரிப்ட்கள், மறைந்த உரை"),
             ("छिपा पेज कोड", "मेल के अंदर फ़ॉर्म, स्क्रिप्ट, छिपा टेक्स्ट")),
    "ai": (("AI manipulation", "Instructions aimed at AI assistants"),
           ("AI கையாளுதல்", "AI உதவியாளர்களை நோக்கிய கட்டளைகள்"),
           ("AI से छेड़छाड़", "AI असिस्टेंट को निर्देश देने की कोशिश")),
}

# --------------------------------------------------------------------------
# Rendering helpers
# --------------------------------------------------------------------------


def verdict_text(verdict, field, lang):
    return VERDICT[verdict][field][_IDX.get(lang, 0)]


def group_text(group, lang):
    """-> (name, what-we-check)"""
    return GROUP_TEXT[group][_IDX.get(lang, 0)]


def render_finding(f, lang):
    """-> (title, why) for one finding in the requested language."""
    row = FINDINGS[f["id"]][lang if lang in FINDINGS[f["id"]] else "en"]
    params = _Safe(f.get("params", {}))
    return row[0].format_map(params), row[1].format_map(params)


def top_reasons(result, lang, n=3):
    """Titles of the n heaviest risk findings (for one-line summaries)."""
    risky = [f for f in result["findings"] if f["weight"] > 0][:n]
    return [render_finding(f, lang)[0] for f in risky]


def summary_sentence(result, lang):
    """One paragraph: the verdict headline followed by the top reasons."""
    v = result["verdict"]
    head = verdict_text(v, "headline", lang)
    if v == "safe":
        return head
    reasons = top_reasons(result, lang, 3)
    sep = "; "
    return f"{head} {verdict_text(v, 'lead', lang)}: {sep.join(reasons)}."


def plain_reasons(result, lang="en"):
    """Flat list of 'title: why' strings (used by the English PDF report and
    by the LLM prompt)."""
    out = []
    for f in result["findings"]:
        if f["weight"] > 0:
            title, why = render_finding(f, lang)
            out.append(f"{title}: {why}")
    return out


def sev_label(weight, lang):
    return t("sev_" + severity(weight), lang)
