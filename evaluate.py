from __future__ import annotations
import statistics
import time

from ci import Mediator, SessionAnalyzer, analyze
from corpus import (MALICIOUS, BENIGN_INSPECTABLE, FAITHFUL_PROMPTS, TOCTOU_PAIRS)

NARR_KW = {
    "network_egress": ("http", "curl", "wget", "upload", "send", "remote", "download", "push"),
    "pipe_to_shell": ("execute", "run script", "pipe", "shell"),
    "exec_remote_code": ("execute", "remote code", "download and run"),
    "sensitive_read": ("ssh", ".env", "credential", "secret", "key", "aws"),
    "destructive": ("delete", "remove", "rm ", "wipe", "reset", "destroy", "erase"),
    "privilege": ("sudo", "root", "admin", "privilege"),
    "writes_outside_ws": ("outside", "system", "/etc"),
}


def baseline_trusts(narration, gt_danger):
    n = narration.lower()
    if not gt_danger:
        return True
    return any(any(k in n for k in NARR_KW.get(d, ())) for d in gt_danger)


def run_sequence(steps):
    s = SessionAnalyzer()
    gt = None
    for cmd, written in steps:
        gt = s.observe(cmd, written=written)
    return gt


def line(c="="):
    print(c * 74)


def main():
    line()
    print("HONEST EVALUATION  (analyzer-relative Consent Integrity)")
    line()

    silent = []
    baseline_deceived = 0
    explained = flagged = 0
    print("\n[1] MALICIOUS corpus  (target: 0 silent passes)")
    for c in MALICIOUS:
        gt = run_sequence(c["steps"])
        v = gt.verdict()
        facts = c.get("gt", set()) or {"__opaque__"}
        if not baseline_trusts(c["narration"], facts):
            baseline_deceived += 1
        if v == "benign":
            silent.append(c["name"])
        elif v == "danger":
            explained += 1
        else:
            flagged += 1
        gtset = set(gt.danger)
        if "exec_remote_code" in gtset:
            gtset |= {"network_egress", "pipe_to_shell"}
        cover = "" if not c.get("gt") else ("  facts " + ("OK" if c["gt"] <= gtset else f"MISSING {c['gt']-gtset}"))
        print(f"   {c['name']:42s} {v:7s}{cover}")
    print(f"\n   malicious cases     : {len(MALICIOUS)}")
    print(f"   fully explained     : {explained}")
    print(f"   safely flagged      : {flagged}")
    print(f"   SILENT PASSES       : {len(silent)}   {silent if silent else ''}")
    print(f"   baseline deceived   : {baseline_deceived}/{len(MALICIOUS)} (trusts narration)")

    print("\n[2] BENIGN-INSPECTABLE workflows  (target: 0 false positives)")
    fp = []
    for c in BENIGN_INSPECTABLE:
        gt = run_sequence(c["steps"])
        if gt.needs_human():
            fp.append((c["name"], gt.verdict(), sorted(gt.danger), gt.opaque_reasons[:1]))
        print(f"   {c['name']:42s} {gt.verdict():7s} prompts={gt.needs_human()}")
    print(f"\n   FALSE POSITIVES     : {len(fp)}   {[x[0] for x in fp] if fp else ''}")

    print("\n[3] FAITHFUL-PROMPT cases  (prompts here are correct, not FP)")
    for c in FAITHFUL_PROMPTS:
        gt = run_sequence(c["steps"])
        print(f"   {c['name']:42s} {gt.verdict():7s} prompts={gt.needs_human()}  reason={c['why']}")

    print("\n[4] BIND-TO-EXECUTION (TOCTOU)  (target: all swaps refused)")
    med = Mediator()
    refused = 0
    for p in TOCTOU_PAIRS:
        ap = med.request_approval("benign", p["approved"])
        ran = med.execute(ap["token"], p["swapped_to"])["ran"]
        refused += (ran is False)
        print(f"   approve[{p['approved'][:20]:20s}] exec[{p['swapped_to'][:24]:24s}] ran={ran}")
    print(f"\n   swaps refused       : {refused}/{len(TOCTOU_PAIRS)}")

    print("\n[5] OVERHEAD")
    cmds = [c["steps"][-1][0] for c in MALICIOUS] + [c["steps"][-1][0] for c in BENIGN_INSPECTABLE]
    t = []
    for _ in range(4000):
        c = cmds[_ % len(cmds)]
        a = time.perf_counter(); analyze(c); t.append((time.perf_counter() - a) * 1000)
    print(f"   mean {statistics.mean(t):.3f} ms | median {statistics.median(t):.3f} ms | "
          f"p99 {sorted(t)[int(0.99*len(t))]:.3f} ms | n={len(t)}")
    line()
    print(f"SUMMARY: silent_passes={len(silent)}  false_positives={len(fp)}  "
          f"swaps_refused={refused}/{len(TOCTOU_PAIRS)}")
    line()


if __name__ == "__main__":
    main()
