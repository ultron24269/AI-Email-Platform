"""
Live inbox watchdog.

Connects to a mailbox over IMAP-SSL, fetches messages that arrived since the
last check, and hands each one to the analysis engine.

Safety properties:
  * READ-ONLY. The folder is opened with readonly=True and messages are
    fetched with BODY.PEEK, so nothing is marked as read, moved or deleted.
  * The password is used for one connection at a time and is never written
    to disk or logged. The caller keeps it only in the user's session.
  * Messages above MAX_BYTES are skipped (reported, not downloaded).
  * A fresh connection per poll: no stale sockets when Streamlit reruns.
"""

import imaplib
import socket
from datetime import datetime

from .ai_engine import analyze_message
from .email_analyzer import parse_email_bytes

MAX_BYTES = 8_000_000
FIRST_BATCH = 8            # how many recent messages to look at on first connect
MAX_ITEMS = 60             # feed length kept in memory

IMAP_HOSTS = {
    "gmail.com": "imap.gmail.com", "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com", "hotmail.com": "outlook.office365.com",
    "live.com": "outlook.office365.com", "office365.com": "outlook.office365.com",
    "yahoo.com": "imap.mail.yahoo.com", "yahoo.in": "imap.mail.yahoo.com",
    "yahoo.co.in": "imap.mail.yahoo.com", "icloud.com": "imap.mail.me.com",
    "zoho.com": "imap.zoho.com", "zoho.in": "imap.zoho.in",
}


class WatchError(Exception):
    """kind is 'auth' (login refused) or 'conn' (cannot reach server)."""

    def __init__(self, kind, detail=""):
        super().__init__(kind)
        self.kind = kind
        self.detail = detail


def guess_host(address):
    domain = address.rsplit("@", 1)[-1].strip().lower() if "@" in address else ""
    return IMAP_HOSTS.get(domain, f"imap.{domain}" if domain else "")


def new_state():
    return {"last_uid": None, "uidvalidity": None, "items": [], "scanned": 0,
            "last_check": None, "error": None}


def fetch_new(host, user, password, last_uid=None, uidvalidity=None, folder="INBOX",
              port=993, timeout=20):
    """
    One poll. Returns
      {'messages': [(uid, raw_bytes)], 'skipped': [uid], 'last_uid': int|None,
       'uidvalidity': str|None}
    Raises WatchError.
    """
    try:
        conn = imaplib.IMAP4_SSL(host, port, timeout=timeout)
    except (OSError, socket.error, imaplib.IMAP4.error) as exc:
        raise WatchError("conn", str(exc))
    try:
        try:
            conn.login(user, password)
        except imaplib.IMAP4.error as exc:
            raise WatchError("auth", str(exc))
        typ, _ = conn.select(folder, readonly=True)
        if typ != "OK":
            raise WatchError("conn", f"cannot open folder {folder}")

        vtyp, vdata = conn.response("UIDVALIDITY")
        current_validity = (vdata[0].decode() if vdata and vdata[0] else None)
        if uidvalidity and current_validity and uidvalidity != current_validity:
            last_uid = None                    # mailbox was rebuilt: start over

        typ, data = conn.uid("SEARCH", None, "ALL")
        if typ != "OK":
            raise WatchError("conn", "search failed")
        uids = [int(x) for x in (data[0] or b"").split()]
        if not uids:
            return {"messages": [], "skipped": [], "last_uid": last_uid,
                    "uidvalidity": current_validity}
        wanted = uids[-FIRST_BATCH:] if last_uid is None else [u for u in uids if u > last_uid]

        messages, skipped = [], []
        for uid in wanted:
            typ, meta = conn.uid("FETCH", str(uid), "(RFC822.SIZE)")
            size = 0
            if typ == "OK" and meta and meta[0]:
                head = meta[0] if isinstance(meta[0], bytes) else meta[0][0]
                if b"RFC822.SIZE" in head:
                    try:
                        size = int(head.split(b"RFC822.SIZE")[1].split(b")")[0].strip())
                    except ValueError:
                        size = 0
            if size > MAX_BYTES:
                skipped.append(uid)
                continue
            typ, msg = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if typ == "OK" and msg and isinstance(msg[0], tuple):
                messages.append((uid, msg[0][1]))
        return {"messages": messages, "skipped": skipped, "last_uid": max(uids),
                "uidvalidity": current_validity}
    except (OSError, socket.error, imaplib.IMAP4.abort) as exc:
        raise WatchError("conn", str(exc))
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def run_cycle(state, host, user, password, check_certs=False, folder="INBOX"):
    """
    Poll once and analyse whatever is new. Updates `state` in place and returns
    the list of NEW feed items (newest first).
    """
    try:
        got = fetch_new(host, user, password, state["last_uid"], state["uidvalidity"], folder)
    except WatchError as exc:
        state["error"] = exc.kind
        state["last_check"] = datetime.now().strftime("%H:%M:%S")
        return []
    state["error"] = None
    state["last_uid"], state["uidvalidity"] = got["last_uid"], got["uidvalidity"]
    state["last_check"] = datetime.now().strftime("%H:%M:%S")

    fresh = []
    for uid, raw in got["messages"]:
        parsed = parse_email_bytes(raw)
        result = analyze_message(parsed, check_certs=check_certs)
        fresh.append({"uid": uid, "parsed": parsed, "result": result})
    fresh.reverse()
    state["items"] = (fresh + state["items"])[:MAX_ITEMS]
    state["scanned"] += len(got["messages"])
    return fresh
