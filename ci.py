from __future__ import annotations
import base64
import hashlib
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

DANGER_FACTS = {
    "network_egress",
    "pipe_to_shell",
    "exec_remote_code",
    "sensitive_read",
    "destructive",
    "privilege",
    "writes_outside_ws",
    "opaque_executable",
}

SENSITIVE_PATHS = (".ssh", ".env", ".aws", "id_rsa", "id_ed25519",
                   "credentials", ".netrc", ".pgpass", "/etc/")
DESTRUCTIVE_PAT = (
    r"\brm\s+-[a-z]*r[a-z]*f", r"\brm\s+-[a-z]*f[a-z]*r", r"\bmkfs", r"\bdd\s+if=",
    r"\bgit\s+reset\s+--hard", r"\bgit\s+clean\s+-[a-z]*f", r"\bdrop\s+database",
    r"\btruncate\b", r"\bwipefs", r":\s*>\s*/",
)
SHELL_SINKS = ("sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "node", "eval")
NET_TOOLS = ("curl", "wget", "nc", "ncat", "scp", "ssh", "ftp", "telnet")
SAFE_CMDS = {"ls", "cat", "echo", "printf", "git", "make", "pytest", "pip", "pip3",
             "npm", "npx", "node", "python", "python3", "go", "cargo", "rustc",
             "grep", "sed", "awk", "head", "tail", "cd", "mkdir", "touch", "cp", "mv",
             "pwd", "env", "export", "test", "true", "false"}
URL_RE = re.compile(r"https?://([^\s/'\"|;)>]+)", re.I)
DEVTCP_RE = re.compile(r"/dev/tcp/([0-9a-zA-Z_.:-]+)/(\d+)")
HEX_RUN_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
B64_RE = re.compile(r"[A-Za-z0-9+/=]{16,}")


@dataclass
class GroundTruth:
    raw: str
    canonical: str
    facts: Set[str] = field(default_factory=set)
    hosts: List[str] = field(default_factory=list)
    decoded_layers: int = 0
    notes: List[str] = field(default_factory=list)

    @property
    def danger(self) -> Set[str]:
        return self.facts & DANGER_FACTS

    def needs_human(self) -> bool:
        return bool(self.danger)

    def summary(self) -> str:
        if not self.danger:
            return f"Benign local action: {self.canonical[:120]}"
        lines: List[str] = []
        if "exec_remote_code" in self.facts:
            lines.append(f"!! EXECUTES CODE FETCHED FROM NETWORK: {', '.join(self.hosts) or '<host>'}")
        elif "network_egress" in self.facts:
            lines.append(f"!! SENDS DATA TO NETWORK HOST(S): {', '.join(self.hosts) or '<host>'}")
        if "sensitive_read" in self.facts:
            lines.append("!! READS CREDENTIAL/SECRET FILES")
        if "destructive" in self.facts:
            lines.append("!! IRREVERSIBLE DESTRUCTION OF LOCAL DATA")
        if "privilege" in self.facts:
            lines.append("!! ESCALATES PRIVILEGE (sudo/root)")
        if "writes_outside_ws" in self.facts:
            lines.append("!! WRITES OUTSIDE THE TRUSTED WORKSPACE")
        if "opaque_executable" in self.facts:
            lines.append("!! RUNS AN OPAQUE LOCAL BINARY WHOSE BEHAVIOR CANNOT BE INSPECTED")
        for n in self.notes:
            lines.append(f"({n})")
        if self.decoded_layers:
            lines.append(f"(de-obfuscated {self.decoded_layers} encoding layer(s))")
        lines.append(f"actual command: {self.canonical[:200]}")
        return "\n".join(lines)


def _canonical(cmd: str) -> str:
    cmd = cmd.replace("\\\n", " ")
    cmd = re.sub(r"\s+", " ", cmd).strip()
    cmd = re.sub(r"^(\s*(:|true)\s*;\s*)+", "", cmd)
    return cmd


def _b64_try(blob: str) -> Optional[str]:
    try:
        txt = base64.b64decode(blob + "===").decode("utf-8", "strict")
        if txt.isprintable() and len(txt) >= 4:
            return txt
    except Exception:
        return None
    return None


def _eval_value(val: str) -> str:
    val = val.strip()
    m = re.match(r"\$\((.+)\)$", val) or re.match(r"`(.+)`$", val)
    if m:
        inner = m.group(1)
        if "base64" in inner:
            for blob in B64_RE.findall(inner):
                dec = _b64_try(blob)
                if dec:
                    return dec
        return inner
    return val.strip("'\"")


def _resolve_vars(cmd: str) -> str:
    parts = cmd.split(";")
    env: Dict[str, str] = {}
    rest: List[str] = []
    for p in parts:
        m = re.match(r"^\s*([A-Za-z_]\w*)=(.+)$", p)
        if m and not re.search(r"\s(&&|\|\|)\s", p):
            env[m.group(1)] = _eval_value(m.group(2))
        else:
            rest.append(p)
    out = ";".join(rest).strip() if rest else cmd
    for k, v in env.items():
        out = out.replace("${%s}" % k, v).replace("$%s" % k, v)
    return out.strip() or cmd


def _decode_hex(cmd: str) -> Optional[str]:
    if not HEX_RUN_RE.search(cmd):
        return None
    if "printf" not in cmd and "echo -e" not in cmd and "$'" not in cmd:
        return None
    runs = HEX_RUN_RE.findall(cmd)
    try:
        return "".join(bytes.fromhex(r.replace("\\x", "")).decode("latin-1") for r in runs)
    except Exception:
        return None


def _extract_b64(cmd: str) -> Optional[str]:
    if not re.search(r"base64\s+(-d|--decode|-D)", cmd) and "b64decode" not in cmd:
        return None
    if not any(s in cmd for s in SHELL_SINKS):
        return None
    for blob in B64_RE.findall(cmd):
        dec = _b64_try(blob)
        if dec:
            return dec
    return None


def _derive(gt: GroundTruth) -> None:
    if {"network_egress", "pipe_to_shell"} <= gt.facts:
        gt.facts.add("exec_remote_code")


def analyze(cmd: str, _depth: int = 0) -> GroundTruth:
    canon = _canonical(cmd)
    if _depth == 0:
        canon = _resolve_vars(canon)
    gt = GroundTruth(raw=cmd, canonical=canon)

    if _depth < 5:
        piped = re.search(r"\|\s*(%s)\b" % "|".join(SHELL_SINKS), canon)
        hexed = _decode_hex(canon)
        if hexed is not None and piped:
            sub = analyze(hexed, _depth + 1)
            gt.facts |= sub.facts
            gt.hosts += sub.hosts
            gt.decoded_layers = sub.decoded_layers + 1
            gt.facts.add("pipe_to_shell")
            gt.canonical = f"{canon}  ==>  {sub.canonical}"
            _derive(gt)
            return gt
        inner = _extract_b64(canon)
        if inner is not None:
            sub = analyze(inner, _depth + 1)
            gt.facts |= sub.facts
            gt.hosts += sub.hosts
            gt.decoded_layers = sub.decoded_layers + 1
            gt.facts.add("pipe_to_shell")
            gt.canonical = f"{canon}  ==>  {sub.canonical}"
            _derive(gt)
            return gt

    low = canon.lower()
    try:
        toks = shlex.split(canon, posix=True)
    except ValueError:
        toks = canon.split()

    hosts = list(URL_RE.findall(canon))
    for m in DEVTCP_RE.finditer(canon):
        hosts.append(f"{m.group(1)}:{m.group(2)}")
        gt.facts.add("network_egress")
        gt.facts.add("pipe_to_shell")
    if any(t in NET_TOOLS for t in toks) or hosts:
        gt.facts.add("network_egress")
    for i, t in enumerate(toks):
        if t in ("scp", "ssh", "nc", "ncat") and i + 1 < len(toks):
            tgt = toks[i + 1] if not toks[i + 1].startswith("-") else (toks[i + 2] if i + 2 < len(toks) else "")
            if tgt:
                hosts.append(tgt)
                gt.facts.add("network_egress")
    gt.hosts = sorted(set(h for h in hosts if h))

    if re.search(r"\|\s*(%s)\b" % "|".join(SHELL_SINKS), canon):
        gt.facts.add("pipe_to_shell")
    if re.search(r"\beval\b", low) and ("$(" in canon or "`" in canon):
        gt.facts.add("pipe_to_shell")
        if URL_RE.search(canon):
            gt.facts.add("network_egress")

    if any(p in canon for p in SENSITIVE_PATHS):
        if any(t in NET_TOOLS for t in toks) or hosts or "$(" in canon or "`" in canon:
            gt.facts.add("sensitive_read")
            gt.facts.add("network_egress")
        elif re.search(r"\b(cat|less|head|tail|cp|tar|base64)\b", low):
            gt.facts.add("sensitive_read")

    if any(re.search(p, low) for p in DESTRUCTIVE_PAT):
        gt.facts.add("destructive")

    if re.search(r"\bsudo\b|\bsu\b|\bdoas\b", low):
        gt.facts.add("privilege")
    if re.search(r"chmod\s+-r?\s*777\s+/|chown\s+-r\s+\S+\s+/", low):
        gt.facts.add("privilege")
        gt.facts.add("destructive")

    if toks:
        head = toks[0]
        base = os.path.basename(head)
        looks_path = head.startswith("./") or head.startswith("/") or head.startswith("../")
        if looks_path and base not in SAFE_CMDS and not gt.danger:
            gt.facts.add("opaque_executable")

    _derive(gt)
    return gt


class SessionAnalyzer:
    def __init__(self) -> None:
        self.tainted: Set[str] = set()

    @staticmethod
    def _content_dangerous(text: str) -> bool:
        candidates = [text]
        for blob in B64_RE.findall(text):
            dec = _b64_try(blob)
            if dec:
                candidates.append(dec)
        joined = " ".join(candidates).lower()
        keys = ("http://", "https://", "/dev/tcp", "| sh", "|sh", "| bash", "|bash",
                "curl", "wget", "base64 -d", "base64 --decode")
        return any(k in joined for k in keys)

    def observe(self, cmd: str) -> GroundTruth:
        canon = _canonical(cmd)
        gt = analyze(cmd)

        for m in re.finditer(r"(?:>>?|tee)\s+(\S+)", canon):
            path = m.group(1).strip("'\"")
            source = canon.split(">")[0]
            if self._content_dangerous(source):
                self.tainted.add(path)
        for m in re.finditer(r"(?:curl|wget)\b[^|;&]*\s-[oO]\s+(\S+)", canon):
            self.tainted.add(m.group(1).strip("'\""))

        referenced: Set[str] = set()
        for pat in (r"(?:^|;|&&|\|\|)\s*(?:bash|sh|source|\.)\s+(\S+)",
                    r"(?:^|;|&&|\|\|)\s*(\./\S+|/\S+)",
                    r"base64\s+(?:-d|--decode)\s+(\S+)\s*\|\s*(?:sh|bash)"):
            for m in re.finditer(pat, canon):
                referenced.add(m.group(1).strip("'\""))
        hit = referenced & self.tainted
        if hit:
            gt.facts.add("pipe_to_shell")
            if any(self._tainted_is_remote(h) for h in hit) or True:
                gt.facts.add("exec_remote_code")
                gt.facts.add("network_egress")
            gt.notes.append(f"executes a file previously written/fetched with remote-fetch content: {', '.join(sorted(hit))}")
            _derive(gt)
        return gt

    def _tainted_is_remote(self, path: str) -> bool:
        return True


@dataclass
class Approval:
    token: str
    bound_hash: str
    summary: str


class Mediator:
    def __init__(self, risk_tier: bool = True) -> None:
        self.risk_tier = risk_tier
        self._issued: Dict[str, str] = {}

    @staticmethod
    def _hash(cmd: str) -> str:
        return hashlib.sha256(_canonical(cmd).encode()).hexdigest()

    def request_approval(self, agent_narration: str, real_command: str) -> Dict:
        gt = analyze(real_command)
        needs_human = (not self.risk_tier) or gt.needs_human()
        token = hashlib.sha256(f"{time.time_ns()}{real_command}".encode()).hexdigest()[:16]
        self._issued[token] = self._hash(real_command)
        return {
            "token": token,
            "needs_human": needs_human,
            "ground_truth_summary": gt.summary(),
            "agent_claims": agent_narration,
            "danger": gt.danger,
            "gt": gt,
        }

    def execute(self, token: str, command_to_run: str) -> Dict:
        bound = self._issued.get(token)
        if bound is None:
            return {"ran": False, "reason": "no such approval token"}
        if self._hash(command_to_run) != bound:
            return {"ran": False, "reason": "BIND-TO-EXECUTION VIOLATION: action differs from approved action"}
        return {"ran": True, "reason": "action matches approval"}
