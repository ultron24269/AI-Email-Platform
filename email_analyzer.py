"""
Email parsing.

`parse_email_bytes(raw)` turns a raw RFC-822 message (.eml) into a plain dict
that the rest of the platform works with. It keeps every key the original
prototype returned (sender, receiver, subject, date, reply_to, message_id,
body, urls, headers) so the geolocation, forensic and PDF modules keep
working, and adds what a modern investigation needs: HTML link/text pairs,
forms, hidden text, attachments with SHA-256 hashes, parsed SPF/DKIM/DMARC
results and a hash of the whole message for chain of custody.
"""

import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

from .knowledge import SCRIPT_RANGES

URL_RE = re.compile(r"""(?:https?://|www\.)[^\s<>"'\)\]\}]+""", re.I)
TRAILING = ".,;:!?)]}>'\""

IMPORTANT_HEADERS = [
    "From", "To", "Subject", "Date", "Reply-To", "Message-ID", "Return-Path",
    "Received", "Authentication-Results", "Received-SPF", "X-Originating-IP",
    "X-Mailer", "List-Unsubscribe", "MIME-Version", "Content-Type",
]

VOID_TAGS = {"br", "img", "hr", "input", "meta", "link", "area", "base", "col",
             "embed", "source", "track", "wbr"}
HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em)?\b|"
    r"opacity\s*:\s*0(?:\.0+)?\b|max-height\s*:\s*0|mso-hide\s*:\s*all", re.I)


# --------------------------------------------------------------------------
# HTML scanning
# --------------------------------------------------------------------------

class _HTMLScan(HTMLParser):
    """Collects visible text, hidden text, links (href + visible label), forms,
    password fields, scripts, iframes and 1x1 tracking pixels."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.visible, self.hidden = [], []
        self.links = []
        self.forms = self.scripts = self.iframes = self.pixels = 0
        self.password_field = False
        self._stack = []          # [(tag, hidden_bool)]
        self._a = None            # current anchor {"href":..,"text":[..]}
        self._skip = 0            # inside <script>/<style>

    def _hidden_now(self):
        return any(h for _, h in self._stack)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
            if tag == "script":
                self.scripts += 1
        if tag == "iframe":
            self.iframes += 1
        if tag == "form":
            self.forms += 1
        if tag == "input" and a.get("type", "").lower() == "password":
            self.password_field = True
        if tag == "img":
            w, h = a.get("width", ""), a.get("height", "")
            if w in ("1", "0") and h in ("1", "0"):
                self.pixels += 1
        if tag == "a" and a.get("href"):
            self._a = {"href": a["href"].strip(), "text": []}
        if tag not in VOID_TAGS:
            hidden = bool(HIDDEN_STYLE.search(a.get("style", ""))) or "hidden" in a
            self._stack.append((tag, hidden))

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._a is not None:
            self.links.append({"href": self._a["href"],
                               "text": " ".join("".join(self._a["text"]).split())})
            self._a = None
        for i in range(len(self._stack) - 1, -1, -1):
            if self._stack[i][0] == tag:
                del self._stack[i:]
                break

    def handle_data(self, data):
        if self._skip or not data.strip():
            return
        (self.hidden if self._hidden_now() else self.visible).append(data)
        if self._a is not None and not self._hidden_now():
            self._a["text"].append(data)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def detect_scripts(text):
    """Which of English / Tamil / Hindi is the message written in?"""
    counts = {"en": 0, "ta": 0, "hi": 0}
    for ch in text:
        cp = ord(ch)
        if ch.isalpha():
            for code, (lo, hi) in SCRIPT_RANGES.items():
                if lo <= cp <= hi:
                    counts[code] += 1
                    break
            else:
                if cp < 0x250:
                    counts["en"] += 1
    total = sum(counts.values())
    if not total:
        return []
    return [c for c, n in sorted(counts.items(), key=lambda kv: -kv[1])
            if n / total >= 0.05]


def _clean_url(u):
    u = u.strip().rstrip(TRAILING)
    if u.lower().startswith("www."):
        u = "http://" + u
    return u


def extract_urls(text):
    return [_clean_url(m) for m in URL_RE.findall(text or "")]


def _addr(value):
    """'Name <a@b.com>' -> ('Name', 'a@b.com', 'b.com')."""
    name, addr = parseaddr(str(value or ""))
    addr = addr.strip().strip("<>").lower()
    domain = addr.rsplit("@", 1)[-1] if "@" in addr else ""
    return name.strip(), addr, domain


def parse_auth(headers):
    """Extract SPF / DKIM / DMARC verdicts from Authentication-Results and
    Received-SPF. Returns {'spf': 'pass'|'fail'|...|None, 'dkim': ..., 'dmarc': ...}"""
    text = " ".join(headers.get("Authentication-Results", [])).lower()
    found = {"spf": [], "dkim": [], "dmarc": []}
    for mech, result in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", text):
        found[mech].append(result)
    for line in headers.get("Received-SPF", []):
        first = line.strip().split(" ", 1)[0].lower()
        if first in ("pass", "fail", "softfail", "neutral", "none",
                     "temperror", "permerror"):
            found["spf"].append(first)
    auth = {}
    for mech, vals in found.items():
        if not vals:
            auth[mech] = None
        elif mech == "dkim" and "pass" in vals:     # any valid signature is fine
            auth[mech] = "pass"
        else:
            auth[mech] = vals[0]
    return auth


def _part_text(part):
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def _sniff(payload):
    """Detect executables whatever the file is called."""
    if payload[:2] == b"MZ":
        return "Windows executable (MZ header)"
    if payload[:4] == b"\x7fELF":
        return "Linux executable (ELF header)"
    return None


# --------------------------------------------------------------------------
# Main entry points
# --------------------------------------------------------------------------

def parse_email_bytes(raw):
    """Parse a raw .eml message. Never raises on malformed mail."""
    msg = BytesParser(policy=policy.default).parsebytes(raw)

    headers = {}
    for h in IMPORTANT_HEADERS:
        vals = msg.get_all(h)
        if vals:
            headers[h] = [str(v) for v in vals]

    from_name, from_addr, from_domain = _addr(msg.get("From", ""))
    _, reply_addr, reply_domain = _addr(msg.get("Reply-To", ""))
    _, return_addr, return_domain = _addr(msg.get("Return-Path", ""))

    plain_parts, html_parts, attachments = [], [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        filename = part.get_filename()
        if filename or disp == "attachment":
            payload = part.get_payload(decode=True) or b""
            name = filename or "(unnamed)"
            attachments.append({
                "filename": name,
                "content_type": ctype,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "ext": name.rsplit(".", 1)[-1].lower() if "." in name else "",
                "signature": _sniff(payload),
            })
        elif ctype == "text/plain":
            plain_parts.append(_part_text(part))
        elif ctype == "text/html":
            html_parts.append(_part_text(part))

    scan = _HTMLScan()
    html_body = "\n".join(html_parts)
    if html_body:
        try:
            scan.feed(html_body)
            scan.close()
        except Exception:
            pass

    body = "\n".join(plain_parts).strip()
    if not body and scan.visible:
        body = " ".join(" ".join(scan.visible).split())

    # every URL: plain-text URLs + every anchor href (mailto:/tel:/# are not links)
    links = [l for l in scan.links
             if l["href"].lower().startswith(("http://", "https://", "www."))]
    for l in links:
        l["href"] = _clean_url(l["href"])
    urls = list(dict.fromkeys(extract_urls(body) + [l["href"] for l in links]))

    date_raw = str(msg.get("Date", "Unknown"))
    date_iso = None
    try:
        date_iso = parsedate_to_datetime(date_raw).isoformat()
    except Exception:
        pass

    return {
        "source": "eml",
        "has_headers": bool(headers.get("Received") or headers.get("Authentication-Results")
                            or headers.get("Message-ID")),
        # ---- keys the original prototype exposed (kept for compatibility) ----
        "sender": str(msg.get("From", "Unknown")),
        "receiver": str(msg.get("To", "Unknown")),
        "subject": str(msg.get("Subject", "No Subject")),
        "date": date_raw,
        "reply_to": str(msg.get("Reply-To", "Not Available")),
        "message_id": str(msg.get("Message-ID", "Not Available")),
        "body": body,
        "urls": urls,
        "headers": headers,
        # ---- new investigation fields ---------------------------------------
        "from_name": from_name, "from_addr": from_addr, "from_domain": from_domain,
        "reply_addr": reply_addr, "reply_domain": reply_domain,
        "return_addr": return_addr, "return_domain": return_domain,
        "date_iso": date_iso,
        "auth": parse_auth(headers),
        "links": links,                       # [{'href','text'}]
        "attachments": attachments,
        "html": {
            "present": bool(html_body),
            "forms": scan.forms, "password_field": scan.password_field,
            "scripts": scan.scripts, "iframes": scan.iframes,
            "tracking_pixels": scan.pixels,
            "hidden_text": " ".join(" ".join(scan.hidden).split())[:2000],
        },
        "languages": detect_scripts(body + " " + str(msg.get("Subject", ""))),
        "raw_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_size": len(raw),
    }


def analyze_email(uploaded_file):
    """Backward-compatible wrapper used by the original prototype: accepts a
    Streamlit upload (or any file-like object)."""
    return parse_email_bytes(uploaded_file.read())


def parse_pasted_text(text, subject=""):
    """Wrap a pasted SMS / WhatsApp / e-mail body in the same structure. There
    are no headers to check, and the engine knows it (lower confidence)."""
    text = text or ""
    raw = text.encode("utf-8", errors="replace")
    urls = list(dict.fromkeys(extract_urls(text)))
    return {
        "source": "text", "has_headers": False,
        "sender": "Unknown", "receiver": "Unknown", "subject": subject or "(pasted message)",
        "date": "Unknown", "reply_to": "Not Available", "message_id": "Not Available",
        "body": text, "urls": urls, "headers": {},
        "from_name": "", "from_addr": "", "from_domain": "",
        "reply_addr": "", "reply_domain": "", "return_addr": "", "return_domain": "",
        "date_iso": None,
        "auth": {"spf": None, "dkim": None, "dmarc": None},
        "links": [{"href": u, "text": ""} for u in urls],
        "attachments": [],
        "html": {"present": False, "forms": 0, "password_field": False,
                 "scripts": 0, "iframes": 0, "tracking_pixels": 0, "hidden_text": ""},
        "languages": detect_scripts(text),
        "raw_sha256": hashlib.sha256(raw).hexdigest(), "raw_size": len(raw),
    }
