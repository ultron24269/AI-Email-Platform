"""
The postmark.

Every inspected message is franked like a letter at a sorting office: a round
cancellation stamp with the verdict, and wavy cancellation lines. It is drawn
as an SVG and embedded as a data URI so it renders identically in Streamlit,
in the downloadable report and when the report is printed.

The ring text is always Latin. Tamil and Hindi need shaping (conjuncts,
vowel signs) that browsers only apply to horizontal text, so the localised
verdict word sits in the centre of the stamp, never along the curve.
"""

import base64
from html import escape

COLORS = {
    "safe": "#17845B",
    "suspicious": "#B26A00",
    "dangerous": "#C8102E",
}

FONT = ("'Noto Sans Tamil','Noto Sans Devanagari','Nirmala UI','Latha','Mangal',"
        "'Segoe UI',Arial,sans-serif")


def _waves(color):
    out = []
    for i, y in enumerate((78, 104, 130, 156, 182)):
        d = f"M228,{y} " + " ".join(
            f"q10,{-9 if j % 2 == 0 else 9} 20,0" for j in range(8))
        out.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="4" '
                   f'stroke-linecap="round" opacity="{0.92 - i * 0.03:.2f}"/>')
    return "".join(out)


def stamp_svg(verdict, word, score, ring_text="AI EMAIL THREAT PLATFORM  ·  INSPECTED  ·  "):
    """Return the stamp as an SVG string. `word` is the localised stamp text."""
    color = COLORS.get(verdict, COLORS["suspicious"])
    size = 44 if len(word) <= 6 else 34 if len(word) <= 9 else 26
    ring = escape(f"{ring_text}RISK {score}/100  ·  ")
    return f"""<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 400 260" width="400" height="260">
  <defs>
    <path id="ring" d="M130,130 m-84,0 a84,84 0 1,1 168,0 a84,84 0 1,1 -168,0"/>
    <filter id="ink" x="-5%" y="-5%" width="110%" height="110%">
      <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="7" result="n"/>
      <feDisplacementMap in="SourceGraphic" in2="n" scale="1.6"/>
    </filter>
  </defs>
  <g transform="rotate(-7 200 130)" filter="url(#ink)" fill="none" stroke="{color}">
    <circle cx="130" cy="130" r="118" stroke-width="5"/>
    <circle cx="130" cy="130" r="108" stroke-width="1.6"/>
    <circle cx="130" cy="130" r="62" stroke-width="1.6"/>
    <text fill="{color}" stroke="none" font-family="Arial,sans-serif" font-size="12.5" font-weight="700" letter-spacing="2.2">
      <textPath href="#ring" xlink:href="#ring">{ring}</textPath>
    </text>
    <text x="130" y="{132 + size * 0.05:.0f}" fill="{color}" stroke="none" text-anchor="middle"
          font-family="{FONT}" font-size="{size}" font-weight="800">{escape(word)}</text>
    <line x1="96" y1="148" x2="164" y2="148" stroke-width="1.6"/>
    <text x="130" y="171" fill="{color}" stroke="none" text-anchor="middle"
          font-family="Arial,sans-serif" font-size="17" font-weight="700" letter-spacing="1">{score}/100</text>
    {_waves(color)}
  </g>
</svg>"""


def stamp_data_uri(verdict, word, score):
    svg = stamp_svg(verdict, word, score)
    return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")


def stamp_img(verdict, word, score, css_class="postmark"):
    return (f'<img class="{css_class}" alt="{escape(word)} {score}/100" '
            f'src="{stamp_data_uri(verdict, word, score)}"/>')
