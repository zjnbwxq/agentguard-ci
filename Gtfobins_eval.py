import sys, os, glob, collections, re, tarfile, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ci import (analyze, PURE_BENIGN, READONLY_SUBCMD, INTERPRETERS, SOURCERS,
                FETCH_EXEC, LOCAL_OPAQUE)

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

URL = "https://codeload.github.com/GTFOBins/GTFOBins.github.io/tar.gz/refs/heads/master"
HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "_gtfo_data")

SUB = {
    "/path/to/input-file": "/etc/shadow", "/path/to/file-input": "/etc/shadow",
    "/path/to/output-file": "/root/.ssh/authorized_keys",
    "/path/to/ouput-file": "/root/.ssh/authorized_keys",
    "/path/to/temp-file": "/tmp/x", "/path/to/temp-dir": "/tmp/d",
    "/path/to/dir": "/tmp/d", "/path/to/output-dir": "/tmp/d",
    "/path/to/input-dir": "/tmp/d", "/path/to/empty-dir": "/tmp/d",
    "/path/to/lib": "/tmp/evil.so", "/path/to/ld": "/tmp/evil.so",
    "/path/to/script": "/tmp/evil.sh", "/path/to/command": "/tmp/payload",
    "/path/to/temp-socket": "/tmp/s.sock", "/path/to/socket": "/tmp/s.sock",
    "/path/to/wordlist": "/tmp/f", "/path/to/hash": "/tmp/f",
    "/path/to/file": "/tmp/f", "/path/to/core-dump": "/tmp/f",
    "$LFILE": "/etc/shadow", "$TF": "/tmp/x", "$URL": "http://evil.sh/p",
    "$RHOST": "10.0.0.1", "$RPORT": "9001", "$LHOST": "10.0.0.1",
    "$LPORT": "9001", "$COMMAND": "id", "$CMD": "id", "$DATA": "pwned",
}
TRUSTED = (set(PURE_BENIGN) | set(READONLY_SUBCMD) | set(INTERPRETERS) |
           set(SOURCERS) | set(FETCH_EXEC) | set(LOCAL_OPAQUE))


def ensure_data():
    if glob.glob(os.path.join(DATA, "*", "_gtfobins", "*")):
        return
    os.makedirs(DATA, exist_ok=True)
    tgz = os.path.join(DATA, "gtfo.tgz")
    urllib.request.urlretrieve(URL, tgz)
    with tarfile.open(tgz) as t:
        t.extractall(DATA)


def sub(code):
    for k, v in SUB.items():
        code = code.replace(k, v)
    return code.strip()


def load_entries():
    ensure_data()
    out = []
    for f in glob.glob(os.path.join(DATA, "*", "_gtfobins", "*")):
        t = open(f, encoding="utf-8", errors="ignore").read()
        parts = t.split("---")
        if len(parts) < 2:
            continue
        try:
            d = yaml.safe_load(parts[1])
        except Exception:
            continue
        if not d or "functions" not in d:
            continue
        for cat, items in d["functions"].items():
            for it in (items or []):
                for line in (it.get("code", "") or "").splitlines():
                    line = sub(line)
                    if line and not line.startswith("#"):
                        out.append((os.path.basename(f), cat, line))
    return out


def main():
    entries = load_entries()
    total = len(entries)
    v = collections.Counter()
    cat = collections.defaultdict(lambda: collections.Counter())
    residual = collections.Counter()
    silent = 0
    for binname, c, cmd in entries:
        try:
            gt = analyze(cmd)
        except Exception:
            v["error"] += 1
            continue
        verdict = gt.verdict()
        v[verdict] += 1
        cat[c][verdict] += 1
        if verdict == "benign":
            silent += 1
            tgt = ""
            for m in re.finditer(r">>?\s*([^\s|;&<>()]+)", cmd):
                tgt = m.group(1)
            if "/tmp" in cmd:
                residual["write/op under /tmp (scratch threshold)"] += 1
            elif cmd.split()[0] in ("mkdir", "touch", "ls", "true", "stat", "file"):
                residual["benign primitive"] += 1
            elif tgt and not tgt.startswith("/"):
                residual["in-tree relative write (risk only when later consumed)"] += 1
            else:
                residual["genuine long tail"] += 1
    print(f"GTFOBins independent corpus: {total} abuse commands")
    flagged = v["danger"] + v["opaque"]
    print(f"flagged (danger {v['danger']} + opaque {v['opaque']}): {flagged} = {100*flagged/total:.1f}%")
    print(f"SILENT PASSES (benign): {silent} = {100*silent/total:.1f}%")
    print("\nby function category:")
    for c in sorted(cat, key=lambda k: -sum(cat[k].values())):
        s = cat[c]
        print(f"  {c:20s} n={sum(s.values()):4d}  danger={s['danger']:4d} "
              f"opaque={s['opaque']:4d} SILENT={s['benign']:3d}")
    print("\nresidual silent-pass breakdown:")
    for k, n in residual.most_common():
        print(f"  {n:4d}  {k}")


if __name__ == "__main__":
    main()
