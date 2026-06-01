from __future__ import annotations
import base64
import hashlib
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

DANGER_FACTS = {
    "network_egress",
    "pipe_to_shell",
    "exec_remote_code",
    "sensitive_read",
    "destructive",
    "privilege",
    "writes_outside_ws",
}

SENSITIVE_PATHS = (".ssh", ".env", ".aws", "id_rsa", "id_ed25519",
                   "credentials", ".netrc", ".pgpass", "/etc/shadow", "/etc/passwd")
DESTRUCTIVE_PAT = (
    r"\brm\s+-[a-z]*r[a-z]*f", r"\brm\s+-[a-z]*f[a-z]*r", r"\bmkfs", r"\bdd\s+if=",
    r"\bgit\s+reset\s+--hard", r"\bgit\s+clean\s+-[a-z]*f", r"\bdrop\s+database",
    r"\btruncate\b", r"\bwipefs", r":\s*>\s*/",
)
PY_DESTRUCTIVE = (r"shutil\.rmtree", r"os\.remove", r"os\.unlink", r"\.unlink\(", r"os\.rmdir")
SHELL_SINKS = ("sh", "bash", "zsh", "dash", "python", "python3", "perl", "ruby", "node", "eval")
NET_TOOLS = ("curl", "wget", "nc", "ncat", "scp", "ssh", "ftp", "telnet")
INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "python", "python2", "python3",
                "perl", "ruby", "node", "nodejs", "php", "Rscript"}
SOURCERS = {"source", "."}
PURE_BENIGN = {"ls", "cat", "echo", "printf", "pwd", "cd", "grep", "sed", "awk",
               "head", "tail", "wc", "sort", "uniq", "diff", "find", "tree",
               "mkdir", "touch", "cp", "mv", "env", "true", "false", "test", "date",
               "whoami", "hostname", "which", "type", "file", "stat", "du", "df"}
READONLY_SUBCMD = {
    "git": {"status", "diff", "log", "show", "rev-parse", "stash", "add", "commit"},
    "pytest": None, "pip": {"list", "show", "freeze", "--version"},
    "pip3": {"list", "show", "freeze", "--version"},
    "npm": {"list", "ls", "test", "run-script", "--version"},
    "cargo": {"test", "check", "fmt", "clippy", "--version"},
    "go": {"test", "vet", "fmt", "version"},
    "docker": {"ps", "images", "version"},
}
FETCH_EXEC = {
    "cargo": {"build", "run", "install", "update"},
    "go": {"build", "run", "get", "install"},
    "npm": {"install", "ci", "i"},
    "pip": {"install"}, "pip3": {"install"},
    "yarn": None, "pnpm": None, "gradle": None, "mvn": None, "bazel": None,
}
LOCAL_OPAQUE = {"make": None, "cmake": None, "ninja": None}
URL_RE = re.compile(r"https?://([^\s/'\"|;)>]+)", re.I)
DEVTCP_RE = re.compile(r"/dev/tcp/([0-9a-zA-Z_.:-]+)/(\d+)")
HEX_RUN_RE = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
B64_RE = re.compile(r"[A-Za-z0-9+/=]{16,}")


@dataclass
class Context:
    file_content: Callable[[str], Optional[str]] = lambda p: None
    is_built_local: Callable[[str], bool] = lambda p: False
    is_remote: Callable[[str], bool] = lambda p: False
    write_verdict: Callable[[str], Optional[str]] = lambda p: None


_NULL = Context()


@dataclass
class GroundTruth:
    raw: str
    canonical: str
    facts: Set[str] = field(default_factory=set)
    hosts: List[str] = field(default_factory=list)
    decoded_layers: int = 0
    notes: List[str] = field(default_factory=list)
    opaque_reasons: List[str] = field(default_factory=list)

    @property
    def danger(self) -> Set[str]:
        return self.facts & DANGER_FACTS

    @property
    def is_opaque(self) -> bool:
        return bool(self.opaque_reasons)

    def needs_human(self) -> bool:
        return bool(self.danger) or self.is_opaque

    def verdict(self) -> str:
        if self.danger:
            return "danger"
        if self.is_opaque:
            return "opaque"
        return "benign"

    def summary(self) -> str:
        if self.verdict() == "benign":
            return f"Benign inspected action: {self.canonical[:120]}"
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
        for r in self.opaque_reasons:
            lines.append(f"?? UNINSPECTABLE: {r}")
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
    stages = len(re.findall(r"base64\s+(?:-d|--decode|-D)", cmd)) + cmd.count("b64decode")
    if stages == 0:
        return None
    if not any(s in cmd for s in SHELL_SINKS):
        return None
    for blob in B64_RE.findall(cmd):
        dec = _b64_try(blob)
        if dec:
            k = 1
            while k < stages and re.fullmatch(r"[A-Za-z0-9+/=]{16,}", dec.strip()):
                d2 = _b64_try(dec.strip())
                if not d2:
                    break
                dec = d2
                k += 1
            return dec
    return None


def _derive(gt: GroundTruth) -> None:
    if {"network_egress", "pipe_to_shell"} <= gt.facts:
        gt.facts.add("exec_remote_code")


SYS_WRITE_RE = re.compile(r"^/(etc|usr|bin|sbin|root|boot|lib|lib64|opt|sys|proc|var/spool|var/www)(/|$)")
SENSITIVE_WRITE = ("authorized_keys", "crontab", "cron.d", "sudoers", "/etc/passwd",
                   "/etc/shadow", ".bashrc", ".profile", ".bash_profile", "rc.local", ".ssh/")


def _is_out_of_tree(path: str) -> bool:
    p = path.strip("'\"")
    if any(k in p for k in SENSITIVE_WRITE):
        return True
    if SYS_WRITE_RE.match(p):
        return True
    if p.startswith("/home/") or p.startswith("/Users/"):
        return True
    return False


def _scan_writes(text: str, toks: List[str], gt: GroundTruth) -> None:
    for m in re.finditer(r">>?\s*([^\s|;&<>()]+)", text):
        if _is_out_of_tree(m.group(1)):
            gt.facts.add("writes_outside_ws")
    for m in re.finditer(r"\btee\s+(?:-a\s+)?([^\s|;&]+)", text):
        if _is_out_of_tree(m.group(1)):
            gt.facts.add("writes_outside_ws")
    for m in re.finditer(r"\bdd\b[^|;&]*\bof=([^\s|;&]+)", text):
        if _is_out_of_tree(m.group(1)):
            gt.facts.add("writes_outside_ws")
    head = os.path.basename(toks[0]) if toks else ""
    if head in ("cp", "mv", "install", "ln") and len(toks) >= 2:
        args = [t for t in toks[1:] if not t.startswith("-")]
        if args and _is_out_of_tree(args[-1]):
            gt.facts.add("writes_outside_ws")
    if head in ("sed",) and "-i" in toks:
        for t in toks[1:]:
            if not t.startswith("-") and _is_out_of_tree(t):
                gt.facts.add("writes_outside_ws")
    if head in ("tar",) and re.search(r"-C\s+(/\S+)", text):
        m = re.search(r"-C\s+(\S+)", text)
        if m and _is_out_of_tree(m.group(1)):
            gt.facts.add("writes_outside_ws")


def _scan_facts(text: str, gt: GroundTruth) -> None:
    low = text.lower()
    try:
        toks = shlex.split(text, posix=True)
    except ValueError:
        toks = text.split()
    hosts = list(URL_RE.findall(text))
    for m in DEVTCP_RE.finditer(text):
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
    gt.hosts = sorted(set(list(gt.hosts) + [h for h in hosts if h]))
    if re.search(r"\|\s*(%s)\b" % "|".join(SHELL_SINKS), text):
        gt.facts.add("pipe_to_shell")
    if re.search(r"\beval\b", low) and ("$(" in text or "`" in text):
        gt.facts.add("pipe_to_shell")
        if URL_RE.search(text):
            gt.facts.add("network_egress")
    if any(p in text for p in SENSITIVE_PATHS):
        gt.facts.add("sensitive_read")
        if any(t in NET_TOOLS for t in toks) or hosts or "$(" in text or "`" in text:
            gt.facts.add("network_egress")
    if any(re.search(p, low) for p in DESTRUCTIVE_PAT):
        gt.facts.add("destructive")
    if re.search(r"\bsudo\b|\bsu\b|\bdoas\b", low):
        gt.facts.add("privilege")
    if re.search(r"chmod\s+-r?\s*777\s+/|chown\s+-r\s+\S+\s+/", low):
        gt.facts.add("privilege")
        gt.facts.add("destructive")
    _scan_writes(text, toks, gt)


SCRIPT_SHELLOUT = (
    r"\bos\.system\b", r"\bsubprocess\.", r"\bos\.popen\b", r"\bpty\.spawn\b",
    r"\beval\s*\(", r"\bexec\s*\(", r"\bcompile\s*\(", r"\b__import__\s*\(",
    r"\bgetattr\s*\([^)]*os", r"child_process", r"\brequire\s*\(\s*['\"]child_process",
    r"\bFunction\s*\(", r"\bsocket\.", r"\bnew\s+net\.Socket", r"\bRuntime\.getRuntime",
    r"\bpickle\.loads\b", r"\bmarshal\.loads\b", r"\bbase64\.b64decode\b",
)
SCRIPT_NET = (r"\brequests\.", r"\burllib", r"\bhttpx\.", r"\bsocket\.", r"\bfetch\s*\(",
              r"\bhttp\.client", r"\bnet\.", r"\baxios")
CAP_MODULES = (r"\bimport\s+subprocess\b", r"\bfrom\s+subprocess\b", r"\bimport\s+socket\b",
               r"\bimport\s+ctypes\b", r"\bimport\s+cffi\b", r"\bimport\s+shutil\b",
               r"\bimport\s+ftplib\b", r"\bimport\s+paramiko\b", r"\bimport\s+pty\b",
               r"require\(['\"]child_process", r"require\(['\"](?:net|http|https|dgram)")
OS_DANGEROUS = (r"\bos\.popen\b", r"\bos\.exec", r"\bos\.spawn", r"\bos\.fork\b",
                r"\bos\.rename\b", r"\bos\.replace\b", r"\bos\.chmod\b", r"\bos\.chown\b")
OPEN_ABS_WRITE = re.compile(r"open\(\s*['\"](/|\.\./)[^'\"]*['\"]\s*,\s*['\"][wa]")
OPEN_ABS = re.compile(r"open\(\s*['\"](/|\.\./)")


def _analyze_text(content: str) -> GroundTruth:
    gt = GroundTruth(raw="<script>", canonical="<script body>")
    _scan_facts(content, gt)
    for blob in B64_RE.findall(content):
        dec = _b64_try(blob)
        if dec:
            _scan_facts(dec, gt)
    if any(re.search(p, content) for p in PY_DESTRUCTIVE):
        gt.facts.add("destructive")
    if any(re.search(p, content, re.I) for p in SCRIPT_NET):
        gt.facts.add("network_egress")
    if any(re.search(p, content) for p in SCRIPT_SHELLOUT):
        if not gt.danger:
            gt.opaque_reasons.append("script constructs or executes code dynamically; static analysis cannot bound its effect")
    if OPEN_ABS_WRITE.search(content):
        gt.facts.add("writes_outside_ws")
    elif OPEN_ABS.search(content) and not gt.danger:
        gt.opaque_reasons.append("script reads or writes an absolute or out-of-tree path whose effect cannot be bounded")
    if any(re.search(p, content) for p in OS_DANGEROUS) and not gt.danger:
        gt.opaque_reasons.append("script invokes process/permission OS primitives whose effect cannot be bounded")
    if any(re.search(p, content) for p in CAP_MODULES) and not gt.danger and not gt.opaque_reasons:
        gt.opaque_reasons.append("script imports a process/network/native-FFI capability whose effect cannot be statically bounded")
    _derive(gt)
    return gt


def _classify_head(canon: str, gt: GroundTruth, ctx: Context, _depth: int = 0) -> None:
    try:
        toks = shlex.split(canon, posix=True)
    except ValueError:
        toks = canon.split()
    if not toks:
        return
    head = toks[0]
    base = os.path.basename(head)

    target = None
    if base in INTERPRETERS or base in SOURCERS:
        if base in ("sh", "bash", "zsh", "dash", "ksh", "ksh93"):
            if "-c" in toks:
                i = toks.index("-c")
                if i + 1 < len(toks):
                    sub = analyze(toks[i + 1], ctx, _depth + 1) if _depth < 4 else gt
                    gt.facts |= sub.facts
                    gt.hosts = sorted(set(gt.hosts + sub.hosts))
                    gt.opaque_reasons += sub.opaque_reasons
                    if not sub.needs_human():
                        gt.opaque_reasons.append("shell -c executes an inline command string")
                    return
            if len([t for t in toks[1:] if not t.startswith("-")]) == 0:
                gt.opaque_reasons.append("spawns an unrestricted interactive shell")
                return
        for t in toks[1:]:
            if t.startswith("-"):
                continue
            target = t
            break
        if target is None:
            gt.opaque_reasons.append("invokes an interpreter with no inspectable target")
            return
        if ctx.is_remote(target):
            gt.facts.add("exec_remote_code")
            gt.facts.add("network_egress")
            gt.facts.add("pipe_to_shell")
            gt.notes.append(f"executes a file of remote origin: {target}")
            return
        content = ctx.file_content(target)
        if content is None:
            v = ctx.write_verdict(target)
            if v == "benign":
                return
            gt.opaque_reasons.append(f"executes a local script whose contents are not observed: {target}")
            return
        sub = _analyze_text(content)
        gt.facts |= sub.facts
        gt.hosts = sorted(set(gt.hosts + sub.hosts))
        gt.opaque_reasons += sub.opaque_reasons
        if sub.needs_human():
            gt.notes.append(f"inspected script body of {target}")
        return

    looks_path = head.startswith("./") or head.startswith("/") or head.startswith("../")
    if looks_path:
        if ctx.is_built_local(head):
            return
        content = ctx.file_content(head)
        if content is not None and content.lstrip().startswith("#!"):
            sub = _analyze_text(content)
            gt.facts |= sub.facts
            gt.opaque_reasons += sub.opaque_reasons
            return
        gt.opaque_reasons.append(
            f"runs a local executable whose contents cannot be inspected at the boundary (no build provenance): {head}")
        return

    if base in FETCH_EXEC:
        allowed = FETCH_EXEC[base]
        sub = toks[1] if len(toks) > 1 else ""
        ro = READONLY_SUBCMD.get(base)
        if ro is not None and sub in ro:
            return
        if allowed is None or sub in allowed:
            gt.facts.add("network_egress")
            gt.opaque_reasons.append(
                f"build tool fetches and executes third-party code not visible at the boundary: {base} {sub}".strip())
        return

    if base in LOCAL_OPAQUE:
        gt.opaque_reasons.append(
            f"runs build recipes not statically resolved at the boundary: {canon[:60]}")
        return

    if base in READONLY_SUBCMD:
        ro = READONLY_SUBCMD[base]
        sub = toks[1] if len(toks) > 1 else ""
        if ro is None or sub in ro:
            return
        gt.opaque_reasons.append(f"unrecognized subcommand for {base}: {sub}")
        return

    if base in PURE_BENIGN:
        return

    gt.opaque_reasons.append(f"unrecognized command; cannot establish it is benign: {base}")


def analyze(cmd: str, ctx: Optional[Context] = None, _depth: int = 0) -> GroundTruth:
    ctx = ctx or _NULL
    canon = _canonical(cmd)
    if _depth == 0:
        canon = _resolve_vars(canon)
    gt = GroundTruth(raw=cmd, canonical=canon)

    if _depth < 5:
        piped = re.search(r"\|\s*(%s)\b" % "|".join(SHELL_SINKS), canon)
        hexed = _decode_hex(canon)
        if hexed is not None and piped:
            sub = analyze(hexed, ctx, _depth + 1)
            gt.facts |= sub.facts
            gt.hosts += sub.hosts
            gt.opaque_reasons += sub.opaque_reasons
            gt.decoded_layers = sub.decoded_layers + 1
            gt.facts.add("pipe_to_shell")
            gt.canonical = f"{canon}  ==>  {sub.canonical}"
            _derive(gt)
            return gt
        inner = _extract_b64(canon)
        if inner is not None:
            sub = analyze(inner, ctx, _depth + 1)
            gt.facts |= sub.facts
            gt.hosts += sub.hosts
            gt.opaque_reasons += sub.opaque_reasons
            gt.decoded_layers = sub.decoded_layers + 1
            gt.facts.add("pipe_to_shell")
            gt.canonical = f"{canon}  ==>  {sub.canonical}"
            _derive(gt)
            return gt

    _scan_facts(canon, gt)
    _derive(gt)
    if not gt.danger:
        _classify_head(canon, gt, ctx, _depth)
    return gt


class SessionAnalyzer:
    def __init__(self) -> None:
        self.remote_tainted: Set[str] = set()
        self.built_local: Set[str] = set()
        self.write_verdicts: Dict[str, str] = {}
        self.contents: Dict[str, str] = {}

    def _ctx(self) -> Context:
        return Context(
            file_content=lambda p: self.contents.get(_norm(p)),
            is_built_local=lambda p: _norm(p) in self.built_local,
            is_remote=lambda p: _norm(p) in self.remote_tainted,
            write_verdict=lambda p: self.write_verdicts.get(_norm(p)),
        )

    def observe(self, cmd: str, written: Optional[Dict[str, str]] = None) -> GroundTruth:
        canon = _canonical(cmd)
        gt = analyze(cmd, self._ctx())

        if written:
            for path, content in written.items():
                np = _norm(path)
                self.contents[np] = content
                sub = _analyze_text(content)
                self.write_verdicts[np] = sub.verdict()
                if "network_egress" in _analyze_text(content).facts or self._content_remote(content):
                    self.remote_tainted.add(np)

        for m in re.finditer(r"(?:curl|wget)\b[^|;&]*\s-[oO]\s+(\S+)", canon):
            self.remote_tainted.add(_norm(m.group(1).strip("'\"")))
        for m in re.finditer(r"(?:>>?|tee)\s+(\S+)", canon):
            path = _norm(m.group(1).strip("'\""))
            source = canon.split(">")[0]
            if self._content_remote(source):
                self.remote_tainted.add(path)
        bm = re.match(r"^(cargo|go|gcc|clang|g\+\+|rustc)\b", canon)
        if bm:
            om = re.search(r"-o\s+(\S+)", canon)
            if om:
                self.built_local.add(_norm(om.group(1).strip("'\"")))
            if bm.group(1) in ("cargo", "go"):
                for guess in ("target/release/", "target/debug/", "./"):
                    pass
        return gt

    def register_build(self, output_path: str) -> None:
        self.built_local.add(_norm(output_path))

    @staticmethod
    def _content_remote(text: str) -> bool:
        candidates = [text]
        for blob in B64_RE.findall(text):
            dec = _b64_try(blob)
            if dec:
                candidates.append(dec)
        joined = " ".join(candidates).lower()
        keys = ("http://", "https://", "/dev/tcp", "| sh", "|sh", "| bash", "|bash",
                "curl", "wget", "base64 -d", "base64 --decode")
        return any(k in joined for k in keys)

    def _tainted_is_remote(self, path: str) -> bool:
        return _norm(path) in self.remote_tainted


def _norm(p: str) -> str:
    p = p.strip("'\"")
    if p.startswith("./"):
        p = p[2:]
    return p


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

    def request_approval(self, agent_narration: str, real_command: str,
                         ctx: Optional[Context] = None) -> Dict:
        gt = analyze(real_command, ctx)
        needs_human = (not self.risk_tier) or gt.needs_human()
        token = hashlib.sha256(f"{time.time_ns()}{real_command}".encode()).hexdigest()[:16]
        self._issued[token] = self._hash(real_command)
        return {
            "token": token,
            "needs_human": needs_human,
            "ground_truth_summary": gt.summary(),
            "agent_claims": agent_narration,
            "danger": gt.danger,
            "verdict": gt.verdict(),
            "gt": gt,
        }

    def execute(self, token: str, command_to_run: str) -> Dict:
        bound = self._issued.get(token)
        if bound is None:
            return {"ran": False, "reason": "no such approval token"}
        if self._hash(command_to_run) != bound:
            return {"ran": False, "reason": "BIND-TO-EXECUTION VIOLATION: action differs from approved action"}
        return {"ran": True, "reason": "action matches approval"}
