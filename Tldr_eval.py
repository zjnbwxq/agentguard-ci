import sys, os, glob, re, collections, tarfile, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ci import (analyze, PURE_BENIGN, READONLY_SUBCMD, INTERPRETERS, SOURCERS,
                FETCH_EXEC, LOCAL_OPAQUE)

URL = "https://codeload.github.com/tldr-pages/tldr/tar.gz/refs/heads/main"
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "_tldr_data")
PH = re.compile(r"\{\{(.*?)\}\}")
CODE = re.compile(r"^`([^`]+)`$")
TRUSTED = (set(PURE_BENIGN) | set(READONLY_SUBCMD) | set(INTERPRETERS) |
           set(SOURCERS) | set(FETCH_EXEC) | set(LOCAL_OPAQUE))


def ensure_data():
    if glob.glob(os.path.join(DATA, "*", "pages", "common", "*.md")):
        return
    os.makedirs(DATA, exist_ok=True)
    tgz = os.path.join(DATA, "tldr.tgz")
    urllib.request.urlretrieve(URL, tgz)
    with tarfile.open(tgz) as t:
        members = [m for m in t.getmembers()
                   if "/pages/common/" in m.name or "/pages/linux/" in m.name]
        t.extractall(DATA, members)


def sub(cmd):
    def r(m):
        s = m.group(1).split("|")[0].strip().replace("path/to/", "")
        return s or "x"
    return PH.sub(r, cmd).strip()


def main():
    ensure_data()
    base = glob.glob(os.path.join(DATA, "*", "pages"))[0]
    files = glob.glob(base + "/common/*.md") + glob.glob(base + "/linux/*.md")
    cmds = []
    for f in files:
        for line in open(f, encoding="utf-8", errors="ignore"):
            m = CODE.match(line.strip())
            if m:
                c = sub(m.group(1))
                if c and not c.startswith("#"):
                    cmds.append(c)
    v = collections.Counter()
    opaque_unknown = 0
    for c in cmds:
        try:
            gt = analyze(c)
        except Exception:
            v["error"] += 1
            continue
        v[gt.verdict()] += 1
        if gt.verdict() == "opaque":
            head = os.path.basename(c.split()[0]) if c.split() else ""
            if head not in TRUSTED:
                opaque_unknown += 1
    n = v["benign"] + v["opaque"] + v["danger"]
    print(f"tldr independent normal-usage corpus: {n} example commands from {len(files)} tools")
    print(f"  no prompt (benign)        : {v['benign']:6d}  {100*v['benign']/n:5.1f}%")
    print(f"  PROMPTED (danger+opaque)  : {v['danger']+v['opaque']:6d}  {100*(v['danger']+v['opaque'])/n:5.1f}%")
    print(f"    uninspectable (opaque)  : {v['opaque']:6d}  {100*v['opaque']/n:5.1f}%  (fatigue driver)")
    print(f"      due to unknown tool   : {opaque_unknown:6d}  {100*opaque_unknown/n:5.1f}%")
    print(f"    danger fact             : {v['danger']:6d}  {100*v['danger']/n:5.1f}%  (faithful on consequential examples plus some over-flag)")
    print()
    print("Interpretation: tldr documents normal idiomatic tool usage, including some")
    print("genuinely consequential commands. The uninspectable rate is the clean fatigue")
    print("proxy: normal usage flagged purely because the tool is not on the trust list.")


if __name__ == "__main__":
    main()
