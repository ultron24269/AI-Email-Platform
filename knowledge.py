"""
Static knowledge used by the AI risk engine.

Everything here is DATA, not logic, so it can be reviewed, extended or
translated without touching the detection code.

Phrase banks are written for three languages (English, Tamil, Hindi) plus the
short transliterated words (KYC, OTP, UPI) that people mix into all three.
"""

# --------------------------------------------------------------------------
# Domains
# --------------------------------------------------------------------------

# Public mailbox providers. A "bank" or "support team" writing from one of
# these is a classic impersonation pattern.
FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.in", "yahoo.co.in",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "rediffmail.com",
    "proton.me", "protonmail.com", "mail.com", "gmx.com", "aol.com",
    "zoho.com", "icloud.com", "yandex.com", "tutanota.com",
}

# Top-level domains that are heavily abused for throw-away phishing sites.
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "link",
    "icu", "cyou", "rest", "cfd", "sbs", "buzz", "work", "support", "country",
    "stream", "loan", "men", "gdn", "bid", "win", "review", "party", "monster",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
    "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "buff.ly", "t.ly",
    "s.id", "v.gd", "bl.ink", "lnkd.in",
}

# Registrable domains need three labels under these public suffixes.
SECOND_LEVEL_SUFFIXES = {
    "co.in", "gov.in", "nic.in", "ac.in", "org.in", "net.in", "res.in",
    "edu.in", "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp",
    "co.nz", "com.br", "co.za", "com.sg", "com.my", "com.pk", "com.bd",
}

# --------------------------------------------------------------------------
# Brands people are impersonated as (India-weighted, plus global names)
# tokens : words that appear inside look-alike domains
# names  : words that appear in a sender's display name
# domains: the ONLY registrable domains that legitimately belong to the brand
# --------------------------------------------------------------------------

BRANDS = {
    "SBI": {
        "tokens": ["sbi", "onlinesbi"], "names": ["sbi", "state bank of india"],
        "domains": ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com",
                    "sbilife.co.in", "sbimf.com", "sbi.bank.in"],
    },
    "HDFC Bank": {
        "tokens": ["hdfc", "hdfcbank"], "names": ["hdfc"],
        "domains": ["hdfcbank.com", "hdfcbank.net", "hdfc.com", "hdfclife.com",
                    "hdfcergo.com", "hdfcsec.com", "hdfcfund.com"],
    },
    "ICICI Bank": {
        "tokens": ["icici", "icicibank"], "names": ["icici"],
        "domains": ["icicibank.com", "icicilombard.com", "iciciprulife.com",
                    "icicidirect.com", "icicisecurities.com"],
    },
    "Axis Bank": {
        "tokens": ["axisbank"], "names": ["axis bank"],
        "domains": ["axisbank.com", "axis.bank.in"],
    },
    "Kotak": {
        "tokens": ["kotak", "kotakbank"], "names": ["kotak"],
        "domains": ["kotak.com", "kotakbank.com"],
    },
    "Paytm": {
        "tokens": ["paytm"], "names": ["paytm"],
        "domains": ["paytm.com", "paytmbank.com", "paytmmall.com"],
    },
    "PhonePe": {
        "tokens": ["phonepe"], "names": ["phonepe"],
        "domains": ["phonepe.com"],
    },
    "Google": {
        "tokens": ["google", "gmail"], "names": ["google", "gmail"],
        "domains": ["google.com", "gmail.com", "googlemail.com", "google.co.in",
                    "google.co.uk", "google.com.au", "google.ca", "google.de",
                    "google.fr", "google.co.jp", "youtube.com", "gstatic.com",
                    "withgoogle.com"],
    },
    "Microsoft": {
        "tokens": ["microsoft", "office365", "onedrive"],
        "names": ["microsoft", "office 365", "outlook", "onedrive"],
        "domains": ["microsoft.com", "microsoftonline.com", "office.com",
                    "office365.com", "outlook.com", "live.com", "onedrive.com",
                    "sharepoint.com", "hotmail.com", "msn.com", "windows.com",
                    "azure.com", "microsoft365.com", "skype.com"],
    },
    "Amazon": {
        "tokens": ["amazon"], "names": ["amazon"],
        "domains": ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de",
                    "amazon.ca", "amazon.co.jp", "amazon.fr", "amazon.it",
                    "amazon.es", "amazon.com.au", "amazon.com.br", "amazon.sg",
                    "amazonaws.com", "amzn.to", "amzn.in", "a.co"],
    },
    "PayPal": {
        "tokens": ["paypal"], "names": ["paypal"],
        "domains": ["paypal.com", "paypal.me"],
    },
    "Apple": {
        "tokens": ["apple", "icloud"], "names": ["apple", "icloud"],
        "domains": ["apple.com", "icloud.com", "me.com"],
    },
    "Netflix": {
        "tokens": ["netflix"], "names": ["netflix"],
        "domains": ["netflix.com"],
    },
    "Meta": {
        "tokens": ["facebook", "instagram", "whatsapp"],
        "names": ["facebook", "instagram", "whatsapp"],
        "domains": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com",
                    "fb.com", "facebookmail.com", "fb.me"],
    },
    "LinkedIn": {
        "tokens": ["linkedin"], "names": ["linkedin"],
        "domains": ["linkedin.com", "licdn.com"],
    },
    "Flipkart": {
        "tokens": ["flipkart"], "names": ["flipkart"],
        "domains": ["flipkart.com"],
    },
    "IRCTC": {
        "tokens": ["irctc"], "names": ["irctc"],
        "domains": ["irctc.co.in", "irctc.com"],
    },
    "Income Tax Dept": {
        "tokens": ["incometax", "incometaxindia"], "names": ["income tax"],
        "domains": ["incometax.gov.in", "incometaxindia.gov.in"],
    },
    "Aadhaar / UIDAI": {
        "tokens": ["uidai", "aadhaar"], "names": ["aadhaar", "uidai"],
        "domains": ["uidai.gov.in"],
    },
    "India Post": {
        "tokens": ["indiapost"], "names": ["india post"],
        "domains": ["indiapost.gov.in"],
    },
    "EPFO": {
        "tokens": ["epfo", "epfindia"], "names": ["epfo"],
        "domains": ["epfindia.gov.in"],
    },
    "DHL": {"tokens": ["dhl"], "names": ["dhl"], "domains": ["dhl.com", "dhl.de"]},
    "FedEx": {"tokens": ["fedex"], "names": ["fedex"], "domains": ["fedex.com"]},
    "UPS": {"tokens": ["ups"], "names": ["ups"], "domains": ["ups.com"]},
    "Swiggy / Zomato": {
        "tokens": ["swiggy", "zomato"], "names": ["swiggy", "zomato"],
        "domains": ["swiggy.com", "swiggy.in", "zomato.com"],
    },
    "Jio / Airtel": {
        "tokens": ["jio", "airtel"], "names": ["jio", "airtel"],
        "domains": ["jio.com", "ril.com", "airtel.in", "airtel.com"],
    },
}

# Characters attackers swap to imitate a brand ("paypa1", "rnicrosoft").
HOMOGLYPHS = [
    ("rn", "m"), ("vv", "w"), ("cl", "d"),
    ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("$", "s"), ("@", "a"),
]

# --------------------------------------------------------------------------
# Attachments
# --------------------------------------------------------------------------

EXECUTABLE_EXT = {
    "exe", "scr", "com", "bat", "cmd", "msi", "pif", "cpl", "jar", "js",
    "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "hta", "lnk", "reg", "dll",
    "apk", "sh", "iso", "img", "vhd",
}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "ace"}
WEBPAGE_EXT = {"html", "htm", "xhtml", "shtml", "svg"}
DOCUMENT_EXT = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt",
                "jpg", "jpeg", "png", "gif", "csv", "rtf"}

# --------------------------------------------------------------------------
# Phrase banks. "strong" phrases trigger the category alone; "weak" phrases
# need to appear at least `min_weak` times. Latin phrases are matched on word
# boundaries; Tamil/Hindi phrases as substrings (those scripts have no
# word-boundary convention that regex \b understands).
# --------------------------------------------------------------------------

PHRASES = {
    "urgency": {
        "min_weak": 2,
        "strong": {
            "en": ["act now", "final notice", "final warning", "last warning",
                   "last chance", "expires today", "expire today",
                   "within 24 hours", "within 48 hours", "immediate action",
                   "respond immediately", "time is running out"],
            "ta": ["கடைசி எச்சரிக்கை", "இறுதி எச்சரிக்கை", "24 மணி நேரத்திற்குள்",
                   "இன்று இரவு", "உடனடி நடவடிக்கை"],
            "hi": ["अंतिम चेतावनी", "24 घंटे में", "24 घंटे के भीतर", "आज रात",
                   "तुरंत कार्रवाई", "अत्यंत आवश्यक"],
        },
        "weak": {
            "en": ["urgent", "urgently", "immediately", "right away", "asap",
                   "today only", "hurry"],
            "ta": ["உடனடியாக", "அவசரம்", "அவசர", "இன்றே", "உடனே"],
            "hi": ["तुरंत", "जरूरी", "ज़रूरी", "आज ही", "फौरन", "फ़ौरन", "जल्द से जल्द"],
        },
    },
    "credentials": {
        "min_weak": 2,
        "strong": {
            "en": ["verify your account", "verify account", "confirm your account",
                   "confirm your identity", "update your account",
                   "update your password", "validate your account",
                   "log in to your account", "login to your account",
                   "sign in to verify", "reactivate your account",
                   "re-activate your account", "unlock your account",
                   "secure your account", "verify your identity"],
            "ta": ["கணக்கை சரிபார்", "கணக்கை புதுப்பி", "உங்கள் கணக்கை உறுதி",
                   "கடவுச்சொல்லை புதுப்பி", "கணக்கை மீண்டும் செயல்படுத்த"],
            "hi": ["खाता सत्यापित", "खाते को सत्यापित", "अपना खाता वेरिफाई",
                   "पासवर्ड अपडेट", "खाता अपडेट", "खाते को अपडेट",
                   "खाता दोबारा चालू"],
        },
        "weak": {
            "en": ["password", "login", "log in", "username", "sign in"],
            "ta": ["கடவுச்சொல்", "உள்நுழை", "பயனர் பெயர்"],
            "hi": ["पासवर्ड", "लॉगिन", "लॉग इन", "यूज़रनेम", "यूजरनेम"],
        },
    },
    "financial": {
        "min_weak": 2,
        "strong": {
            "en": ["bank account", "account number", "net banking", "netbanking",
                   "wire transfer", "payment failed", "payment pending",
                   "tax refund", "pay now", "make payment", "outstanding amount"],
            "ta": ["கணக்கு எண்", "பணம் செலுத்த", "பணம் திரும்ப", "வங்கிக் கணக்கு"],
            "hi": ["खाता संख्या", "खाता नंबर", "भुगतान करें", "रिफंड", "बैंक खाता"],
        },
        "weak": {
            "en": ["kyc", "upi", "ifsc", "credit card", "debit card", "refund",
                   "invoice", "transaction", "overdue", "pan card", "aadhaar",
                   "bank"],
            "ta": ["கேஒய்சி", "யுபிஐ", "கிரெடிட் கார்டு", "டெபிட் கார்டு",
                   "ஆதார்", "பான்", "வங்கி", "கட்டணம்"],
            "hi": ["केवाईसी", "यूपीआई", "क्रेडिट कार्ड", "डेबिट कार्ड", "आधार",
                   "पैन", "बैंक", "शुल्क"],
        },
    },
    "threat": {
        "min_weak": 2,
        "strong": {
            "en": ["account will be blocked", "account will be suspended",
                   "account has been suspended", "account will be closed",
                   "account has been blocked", "account is locked",
                   "permanently blocked", "legal action", "legal notice",
                   "arrest warrant", "will be arrested", "will be disconnected",
                   "service will be terminated", "access will be restricted",
                   "will be deactivated"],
            "ta": ["முடக்கப்படும்", "முடக்கப்பட்டது", "துண்டிக்கப்படும்",
                   "நிறுத்தப்படும்", "சட்ட நடவடிக்கை", "கைது செய்யப்படுவீர்கள்",
                   "ரத்து செய்யப்படும்"],
            "hi": ["खाता बंद", "ब्लॉक कर दिया", "ब्लॉक हो जाएगा",
                   "बंद कर दिया जाएगा", "कनेक्शन कट", "कानूनी कार्रवाई",
                   "गिरफ्तार", "रद्द कर दिया जाएगा", "निलंबित"],
        },
        "weak": {
            "en": ["penalty", "suspended", "deactivated", "police case"],
            "ta": ["அபராதம்", "கைது"],
            "hi": ["जुर्माना"],
        },
    },
    "prize": {
        "min_weak": 2,
        "strong": {
            "en": ["you have won", "you've won", "lucky draw", "claim your prize",
                   "claim your reward", "cash prize", "jackpot", "lottery",
                   "you are the winner", "selected as a winner", "free gift"],
            "ta": ["வெற்றி பெற்றுள்ளீர்கள்", "லாட்டரி", "பரிசுத்தொகை",
                   "அதிர்ஷ்ட குலுக்கல்", "பரிசு வென்று"],
            "hi": ["आपने जीता", "आपने जीत", "लॉटरी", "इनाम जीत", "केबीसी",
                   "भाग्यशाली विजेता", "पुरस्कार जीत"],
        },
        "weak": {
            "en": ["congratulations", "winner", "prize", "reward"],
            "ta": ["வாழ்த்துக்கள்", "பரிசு"],
            "hi": ["बधाई", "इनाम", "पुरस्कार"],
        },
    },
    "govt_scam": {
        "min_weak": 2,
        "strong": {
            "en": ["digital arrest", "money laundering case", "narcotics",
                   "enforcement directorate", "cyber crime department",
                   "parcel is held", "courier is held", "illegal items",
                   "customs department", "police verification"],
            "ta": ["டிஜிட்டல் கைது", "சுங்கத்துறை", "போதைப்பொருள்",
                   "பார்சல் நிறுத்தி", "சைபர் கிரைம் பிரிவு"],
            "hi": ["डिजिटल अरेस्ट", "मनी लॉन्ड्रिंग", "नारकोटिक्स",
                   "पार्सल रोक", "कस्टम विभाग", "साइबर क्राइम विभाग"],
        },
        "weak": {
            "en": ["cbi", "trai", "parcel", "customs", "police"],
            "ta": ["சிபிஐ", "பார்சல்", "காவல்துறை"],
            "hi": ["सीबीआई", "पार्सल", "कस्टम", "पुलिस"],
        },
    },
    "utility_scam": {
        "min_weak": 2,
        "strong": {
            "en": ["electricity will be disconnected", "power will be cut",
                   "power supply will be disconnected", "connection will be disconnected",
                   "electricity connection", "bill not updated", "tonight at 9"],
            "ta": ["மின் இணைப்பு", "மின்சாரம் துண்டிக்கப்படும்",
                   "மின் இணைப்பு துண்டிக்கப்படும்", "இன்று இரவு 9"],
            "hi": ["बिजली का कनेक्शन", "बिजली कनेक्शन", "बिजली कट",
                   "बिजली विभाग", "आज रात 9"],
        },
        "weak": {
            "en": ["electricity bill", "unpaid bill", "gas connection"],
            "ta": ["மின் கட்டணம்", "மின்கட்டணம்", "கேஸ் இணைப்பு"],
            "hi": ["बिजली बिल", "गैस कनेक्शन"],
        },
    },
    "gift_crypto": {
        "min_weak": 1,
        "strong": {
            "en": ["gift card", "itunes card", "google play card", "amazon gift",
                   "western union", "moneygram", "wire the money"],
            "ta": ["பரிசு அட்டை", "கிஃப்ட் கார்டு"],
            "hi": ["गिफ्ट कार्ड"],
        },
        "weak": {
            "en": ["bitcoin", "usdt", "binance", "crypto"],
            "ta": ["பிட்காயின்", "கிரிப்டோ"],
            "hi": ["बिटकॉइन", "क्रिप्टो"],
        },
    },
    "generic_greeting": {
        "min_weak": 1,
        "strong": {
            "en": ["dear customer", "dear user", "dear account holder",
                   "dear valued customer", "dear sir/madam", "dear sir or madam",
                   "dear member", "dear client", "dear beneficiary"],
            "ta": ["அன்புள்ள வாடிக்கையாளர்", "அன்பார்ந்த வாடிக்கையாளர்",
                   "அன்புள்ள பயனர்"],
            "hi": ["प्रिय ग्राहक", "प्रिय उपयोगकर्ता", "आदरणीय ग्राहक"],
        },
        "weak": {"en": [], "ta": [], "hi": []},
    },
}

# Sensitive secrets that legitimate organisations NEVER ask you to send.
SECRET_WORDS = {
    "en": ["otp", "one time password", "one-time password", "pin", "cvv",
           "card number", "atm pin", "upi pin", "security code",
           "verification code", "passcode", "password", "account number",
           "aadhaar number", "pan number", "net banking password"],
    "ta": ["ஓடிபி", "otp", "பின் எண்", "சிவிவி", "அட்டை எண்", "ரகசிய எண்",
           "சரிபார்ப்பு குறியீடு", "கடவுச்சொல்", "கணக்கு எண்", "ஆதார் எண்"],
    "hi": ["ओटीपी", "otp", "पिन", "सीवीवी", "कार्ड नंबर", "सुरक्षा कोड",
           "सत्यापन कोड", "पासवर्ड", "खाता संख्या", "खाता नंबर", "आधार नंबर"],
}
REQUEST_VERBS = {
    "en": ["share", "send", "provide", "enter", "reply", "tell", "give",
           "confirm", "submit", "forward", "disclose", "read out", "type"],
    "ta": ["பகிர", "அனுப்ப", "சொல்ல", "தெரிவி", "வழங்க", "உள்ளிட", "பதிலளி"],
    "hi": ["साझा", "भेजें", "भेजिए", "बताएं", "बताइए", "दर्ज करें",
           "जवाब दें", "शेयर"],
}
# A sentence that WARNS ("never share your OTP") must not count as a request.
NEGATIONS = {
    "en": ["do not", "don't", "dont", "never", "not share", "won't ask",
           "will never ask", "no one will ask", "beware", "be careful"],
    "ta": ["வேண்டாம்", "கூடாது", "ஒருபோதும்", "எச்சரிக்கை"],
    "hi": ["न करें", "नहीं", "कभी नहीं", "मत ", "सावधान"],
}

# Text aimed at AI mail assistants rather than at the human reader.
PROMPT_INJECTION_PATTERNS = [
    r"ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|prompts?|rules)",
    r"disregard (?:all |any |the )?(?:previous|prior|above|earlier)? ?(?:instructions|prompts?|rules)",
    r"forget (?:all |everything )?(?:your |the )?(?:previous |prior )?(?:instructions|rules)",
    r"you are (?:now )?(?:an? )?(?:ai|assistant|language model|chatbot)",
    r"as an? (?:ai|language model|assistant)[, ]+(?:you|please)",
    r"(?:mark|classify|label|treat|report) (?:this|the) (?:e-?mail|message|mail) as (?:safe|legitimate|genuine|not (?:spam|phishing)|trusted)",
    r"do not (?:flag|report|block|quarantine) (?:this|the) (?:e-?mail|message|mail|sender)",
    r"(?:system prompt|developer message|hidden instructions?)",
    r"reveal (?:your|the) (?:instructions|system prompt|prompt)",
    r"forward (?:this|all|every) (?:e-?mails?|messages?|conversations?) to",
    r"\[/?inst\]|<\|?(?:system|im_start)\|?>",
    r"new instructions?:",
]

SCRIPT_RANGES = {
    "ta": (0x0B80, 0x0BFF),   # Tamil
    "hi": (0x0900, 0x097F),   # Devanagari (Hindi)
}
