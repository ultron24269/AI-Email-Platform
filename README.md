# AI Email Threat Platform

A Streamlit app that inspects an email or a pasted message (SMS/WhatsApp) and
tells you — in **English, Tamil or Hindi** — whether it is safe, suspicious
or dangerous, and *why*, with evidence you can check yourself.

## What it does

- **Inspect a message** — upload a `.eml` file, paste text, or try a sample.
  Checks sender authentication (SPF/DKIM/DMARC), look-alike domains, urgency
  and threat language, requests for OTP/PIN/passwords, links, attachments,
  hidden HTML, and attempts to manipulate AI mail assistants.
- **Live inbox watchdog** — connect a mailbox (IMAP, e.g. Gmail with an app
  password) and every new message is scanned automatically. Strictly
  read-only: nothing is marked read, moved or deleted.
- **Link & certificate check** — paste a URL; the platform reads its TLS
  certificate, expiry date, HTTPS setup, redirects, HSTS and domain age.
- **Case studies** — real documented scam patterns (Jamtara-style KYC/OTP
  fraud, "digital arrest" calls, fake electricity-disconnection messages,
  prompt injection against AI assistants) mapped to the specific checks that
  catch them.
- **Explainable scoring** — every finding carries a named, visible weight.
  Findings combine by noisy-OR fusion (`risk = 1 - Π(1 - weight)`), so every
  point of the score traces back to a sentence a human can read. Nothing is a
  black box.
- **Downloadable evidence** — a localized HTML forensic report (print to PDF
  for Tamil/Hindi), an English PDF report, and a raw JSON evidence bundle.
- Optional **second opinion from Claude** (only sent if you tick the box —
  requires `ANTHROPIC_API_KEY`), and optional **VirusTotal** lookups.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt
streamlit run app.py
```

### Optional API keys

Copy `.streamlit/secrets.toml.example` to `.streamlit/secrets.toml` and fill
in what you want to use:

```toml
ANTHROPIC_API_KEY = "sk-ant-..."      # for the Claude second opinion
VIRUSTOTAL_API_KEY = "your-key"       # for VirusTotal lookups
```

Both features are off unless you tick the corresponding checkbox in the app,
so the platform works fully without any keys — those two features simply
stay disabled.

**Never commit `.streamlit/secrets.toml` or a `.env` file** — both are in
`.gitignore` already.

## Project layout

```
app.py                      Streamlit UI (4 tabs)
modules/
  knowledge.py               Brands, phrase banks (EN/TA/HI), TLDs, extensions
  findings.py                Finding catalog, weights, noisy-OR fusion
  email_analyzer.py          .eml parsing, HTML scan, attachments, hashing
  ai_engine.py                Core risk engine (all checks -> verdict)
  url_ai.py                   Brand look-alike detection, link structure
  site_probe.py                TLS certificate / redirect / domain-age probe (SSRF-safe)
  i18n_findings.py            Explanations for every finding, EN/TA/HI
  i18n.py                      UI strings, verdict text, group text
  stamp.py                     Postmark-style verdict stamp (SVG)
  report_html.py               Multilingual forensic HTML report
  llm_advisor.py                Optional Claude second opinion
  inbox_watchdog.py            Read-only IMAP polling
  geolocation.py, threat_intel.py, forensic.py, report.py   (original modules, reused)
models/
  url_phishing_model.py, url_phishing_model.joblib   (original ML model, reused)
samples/                      Sample .eml files (English/Tamil/Hindi phishing + legit mail)
tests/                        Unit tests (certificate probe, i18n consistency, watchdog, LLM)
```

## Running the tests

```bash
python3 tests/make_samples.py       # (re)generate the sample .eml files
python3 tests/test_site_probe.py    # TLS certificate checks against local test servers
python3 tests/test_i18n.py          # every finding has EN/TA/HI text with matching placeholders
python3 tests/test_watchdog_llm.py  # IMAP watchdog (mocked) + Claude advisor (mocked)
```

## Design notes

- **SSRF safety**: `site_probe.py` resolves every host and refuses private,
  loopback, link-local or reserved addresses before connecting — a phishing
  link pointing at `192.168.0.1` or `localhost` is never followed.
- **Explainability first**: the engine never outputs a bare number. Every
  finding is `(id, weight, evidence, params)`, and `i18n.py` turns that into
  a sentence in the reader's language. The Claude second opinion is
  explicitly told it cannot change the verdict — it only explains the
  evidence the local engine already found.
- **Trilingual phrase banks**: `knowledge.py` and `i18n_findings.py` carry
  parallel English/Tamil/Hindi scam-phrase banks and explanations, checked
  by `tests/test_i18n.py` for completeness.
