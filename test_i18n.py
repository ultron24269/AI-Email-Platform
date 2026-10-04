import os, sys, string
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules.findings import CATALOG
from modules.i18n_findings import FINDINGS
from modules import i18n

ALLOWED = {"domain","reply","path","brand","shown","phrases","snippet","url","host","tld","port","length",
           "words","date","days","issuer","names","version","hops","final","count","prob","years",
           "filename","ext","kind","n"}
fmt = string.Formatter()
def fields(s): return {f for _, f, _, _ in fmt.parse(s) if f}

def run():
    missing = [k for k in CATALOG if k not in FINDINGS]
    assert not missing, f"findings without text: {missing}"
    extra = [k for k in FINDINGS if k not in CATALOG]
    assert not extra, f"texts without catalog entry: {extra}"
    for fid, langs in FINDINGS.items():
        assert set(langs) == {"en", "ta", "hi"}, fid
        sets = []
        for lg, (title, why) in langs.items():
            assert title.strip() and why.strip(), (fid, lg)
            fs = fields(title) | fields(why)
            assert fs <= ALLOWED, (fid, lg, fs - ALLOWED)
            sets.append(fs)
        # a translation must not invent or drop placeholders
        assert sets[0] == sets[1] == sets[2], (fid, sets)
    # UI rows have 3 non-empty entries and matching placeholders
    for key, row in i18n.UI.items():
        assert len(row) == 3 and all(x.strip() for x in row), key
        s = [fields(x) for x in row]
        assert s[0] == s[1] == s[2], (key, s)
    for v, d in i18n.VERDICT.items():
        for k, row in d.items():
            assert len(row) == 3 and all(row), (v, k)
    assert set(i18n.GROUP_TEXT) == set(__import__("modules.findings", fromlist=["GROUPS"]).GROUPS)
    print(f"i18n: {len(FINDINGS)} findings x 3 languages, {len(i18n.UI)} UI strings - consistent")

if __name__ == "__main__":
    run()
