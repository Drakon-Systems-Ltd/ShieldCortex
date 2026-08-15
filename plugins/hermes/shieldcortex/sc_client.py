"""
ShieldCortex defence client for the Hermes plugin.

Calls ShieldCortex's local REST API. Tool calls go through
`POST /api/v1/action-guard` (the same `evaluateToolCall` the Claude hook and
OpenClaw interceptor run). Content scanning stays on `POST /api/v1/scan`.
Hermes is Python; ShieldCortex is Node — REST is the clean cross-runtime
boundary (no CLI text-scraping, no in-process bridge).

Auth: the API requires a Bearer token (the server writes it to
`~/.shieldcortex/.api-token`, 0600). We read it from `SHIELDCORTEX_API_TOKEN`
or that file and send `Authorization: Bearer …`. Without it the API answers 401
and — being fail-open — the gate silently degrades to a no-op. That exact gap
(no auth header → invisible 401 → never actually scans) was caught in the
ATHENA Hermes dogfood, 2026-06-29; wiring the token closes it.

Failure posture (issue #59 / WS2): if the scanner is unreachable or errors, we
return an `available=False` verdict — and the caller runs the dependency-free
`fallback_catastrophic_match` below. A match fails CLOSED (blocked); anything
else still fails open with a loud `gate_degraded` log, because the fallback
recognising nothing is not evidence the call is safe, only that it isn't one
of the handful of unambiguous shapes. A down scanner still never wedges an
agent doing normal work.
"""
from __future__ import annotations

import json
import os
import re
import urllib.request

# Unambiguous catastrophic shapes for the fail-closed fallback (issue #59/WS2).
# Ported from — and kept in sync with — FALLBACK_CATASTROPHIC_PATTERNS in
# scripts/pre-tool-hook.mjs and plugins/openclaw/interceptor.ts. Narrow by
# design: essentially-never-benign shapes only, so a broken scanner fails
# closed on "rm -rf /"-class commands without turning every tool call into a
# denial. The content scanned here is the tool name + JSON-encoded args (see
# _tool_content in __init__.py) — JSON escaping keeps spaces/pipes/slashes
# literal, so the shapes survive encoding.
_FALLBACK_CATASTROPHIC = [
    re.compile(r"\brm\b[^|;&\n]*?(?:(?<![\w./-])-\w*r\w*f\w*|(?<![\w./-])-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))", re.I),
    re.compile(r"\brm\b[^|;&\n]*\s(?:-\w+\s+)*(?:/|~|\$HOME|/\*|\*|\./\*)(?:\s|$)", re.I),
    re.compile(r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:?\s*&?\s*\}\s*;\s*:"),
    re.compile(r"\bmkfs(\.\w+)?\b", re.I),
    re.compile(r"\bdd\b[^|;&\n]*\bof=/dev/(sd|nvme|hd|disk|mmcblk|vd)", re.I),
    re.compile(r"\b(fdisk|parted|sgdisk|wipefs|blkdiscard)\b", re.I),
    re.compile(
        r"\b(?:curl|wget|fetch)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:env\s+)?(?:\w+=\S*\s+)*"
        r"(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?!(?:\s+-[a-z]+)*\s+-[cem]\b)",
        re.I,
    ),
    re.compile(r"\b(?:curl|wget|fetch)\b[^|\n]*\|[^\n]*\bpython\d?\b[^\n]*\s-m\s*(?:code|pty|pdb)(?![\w.])", re.I),
    re.compile(r"\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s/(?:\s|$)", re.I),
]


def fallback_catastrophic_match(content: str) -> bool:
    """True when `content` matches an unambiguous catastrophic shape (fail-closed tier)."""
    if not content:
        return False
    return any(p.search(content) for p in _FALLBACK_CATASTROPHIC)


# Dangerous tier of the fail-closed fallback (issue #59) — ported from
# tool-action-guard.ts's DANGEROUS list, kept in sync with the OpenClaw
# interceptor + Claude Code hook. Blocked (enforcing) when the scanner is
# unreachable, instead of the pre-#59 fail-open. Mirrors the real (narrowed)
# patterns so read-only forms (crontab -l, npm ls -g, git status) still pass.
_FALLBACK_DANGEROUS = [
    re.compile(r"\brm\b|\bunlink\b|\brmdir\b|(?:(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?|\bxargs\s+(?:-{1,2}\S+\s+)*|-exec\s+)shred\b", re.I),
    re.compile(r"\bsudo\b|\bdoas\b|\bsu\s", re.I),
    re.compile(r"\bgit\b[^|\n]*\bpush\b[^|\n]*(--force\b|-f\b|\+)", re.I),
    re.compile(r"\bgit\b[^|\n]*\b(branch\s+-D|push\b[^|\n]*--delete|push\b[^|\n]*\s:)", re.I),
    re.compile(r"\b(systemctl|service)\b[^|\n]*\b(stop|disable|mask)\b|\b(kill|pkill|killall)\b", re.I),
    re.compile(r"\b(iptables|ufw|nft|netplan|firewall-cmd)\b", re.I),
    re.compile(r"\b(?:apt|apt-get|yum|dnf|brew|pip|pip3|gem|cargo)\b[^|\n]*\b(?:install|add)\b", re.I),
    re.compile(
        r"\b(?:npm|yarn|pnpm|bun)\b(?=[^|;&\n]*(?:\s['\"]?-g\b['\"]?|--global(?![\w-])|\bglobal\s+add\b))"
        r"(?=[^|;&\n]*\s(?:install|add)(?=\s|$|[|;&\n]))|"
        r"\b(?:npm|pnpm|bun)\s+(?:i(?:n(?:s(?:t(?:a(?:ll?)?)?)?)?)?|isnt(?:all)?)\b[^|;&\n]*(?:\s['\"]?-g\b['\"]?|--global(?![\w-]))",
        re.I,
    ),
    re.compile(
        r"(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?"
        r"(?:(?:env|nohup|time|stdbuf|nice)\b(?:\s+(?:-{1,2}\S+|\w+=\S*|\d+))*\s+)*(?:sudo\s+)?"
        r"(?:crontab\b(?!\s+-l\b)|at\b(?!\s+-l\b)(?!\s*$))|/etc/cron|"
        r"\bsystemd-run\b[^|;&\n]*--on-(?:calendar|active|boot|startup|unit-active|unit-inactive)\b",
        re.I,
    ),
    re.compile(r"\bdd\b[^|;&\n]*\bof=", re.I),
    re.compile(r"\bch(?:mod|own)\b[^|;&\n]*(?:-\w*R\w*|--recursive)\b[^|;&\n]*\s/(?:etc|usr|var|home|bin|sbin|boot|lib|lib64|opt|root)(?:/\*?)?(?:\s|$)", re.I),
    re.compile(r"\btruncate\b[^|;&\n]*(?:-s\s*0\b|--size(?:=|\s+)0\b)", re.I),
    re.compile(r"\bhistory\s+-c\b|\.bash_history|truncate\b[^|\n]*\.log", re.I),
    re.compile(r"/etc/(passwd|shadow|sudoers)|~/\.ssh|id_rsa|\.aws/credentials|\.env\b", re.I),
    re.compile(r"(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?uvx\b", re.I),
    re.compile(r"(?:^|[;&|(\n]|\$\()\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:pnpm|yarn)\b[^|;&\n]*\bdlx\b", re.I),
    re.compile(r"\b(?:base64|openssl|xxd|cat|http)\b[^\n|]*\|(?:[^\n|]*\|)*\s*(?:\w+=\S*\s+)*(?:sudo\s+)?(?:bash|sh|zsh|ksh|python\d?|perl|ruby|node)\b(?:\s+-)?\s*(?:[;&|\n]|$)", re.I),
]

# Same command/path/url field set the guard extracts — narrow, not the whole
# args object (a benign `description` must never gate).
_FALLBACK_SURFACE_KEYS = (
    "command", "cmd", "script", "code", "input", "shell", "run",
    "path", "file_path", "filePath", "file", "target", "destination", "dir", "directory",
    "url", "uri", "endpoint", "href", "host", "to",
)


def fallback_surface(args: dict) -> str:
    """Join the raw exec-surface values (command/path/url) from a tool's args.

    The fallback scans this, not the JSON-wrapped tool blob, so command-position
    anchors in the dangerous patterns fire the same way they do on the other
    two runtime surfaces. Capped at 4 KB (kept in sync with the interceptor +
    hook FALLBACK_SCAN_CAP) — an unbounded scan over crafted input is a ReDoS
    vector; dangerous shapes appear early in any real command.
    """
    if not isinstance(args, dict):
        return ""
    parts = [args[k] for k in _FALLBACK_SURFACE_KEYS if isinstance(args.get(k), str) and args[k]]
    return "   ".join(parts)[:4096]


def fallback_dangerous_match(content: str) -> bool:
    """True when `content` matches a recognised-dangerous shape (fail-closed when enforcing)."""
    if not content:
        return False
    return any(p.search(content) for p in _FALLBACK_DANGEROUS)


DEFAULT_BASE_URL = os.environ.get("SHIELDCORTEX_API_URL", "http://127.0.0.1:3001")
TOKEN_FILE = os.path.expanduser("~/.shieldcortex/.api-token")


def _api_token() -> str | None:
    """Bearer token for the ShieldCortex API: env first, then ~/.shieldcortex/.api-token."""
    env = os.environ.get("SHIELDCORTEX_API_TOKEN", "").strip()
    if env:
        return env
    try:
        with open(TOKEN_FILE, encoding="utf-8") as fh:
            tok = fh.read().strip()
            return tok or None
    except OSError:
        return None


class Verdict:
    """Normalised result of a ShieldCortex scan."""

    __slots__ = ("result", "threats", "reason", "available")

    def __init__(self, result: str, threats, reason: str, available: bool = True):
        self.result = (result or "ALLOW").upper()  # ALLOW | BLOCK | QUARANTINE | ERROR
        self.threats = list(threats or [])
        self.reason = reason or ""
        self.available = available  # False => scanner unreachable (fail-open)

    @property
    def blocked(self) -> bool:
        return self.result in ("BLOCK", "QUARANTINE")

    def __repr__(self) -> str:
        return f"Verdict(result={self.result!r}, threats={self.threats!r}, available={self.available})"


def _post(url, body: bytes, timeout: float, opener, headers: dict):
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with opener(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class ActionGuardVerdict:
    """Normalised result of POST /api/v1/action-guard (evaluateToolCall)."""

    __slots__ = ("decision", "signals", "reason", "available")

    def __init__(self, decision: str, signals, reason: str, available: bool = True):
        self.decision = (decision or "allow").lower()  # allow | require_approval | block
        self.signals = list(signals or [])
        self.reason = reason or ""
        self.available = available

    def __repr__(self) -> str:
        return (
            f"ActionGuardVerdict(decision={self.decision!r}, "
            f"signals={self.signals!r}, available={self.available})"
        )


def evaluate_tool_call(
    tool: str,
    args: dict | None = None,
    *,
    base_url: str | None = None,
    timeout: float = 4.0,
    opener=urllib.request.urlopen,
) -> ActionGuardVerdict:
    """Ask ShieldCortex's Action Guard for a verdict. Never raises."""
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    body = json.dumps(
        {
            "tool": tool,
            "args": args if isinstance(args, dict) else {},
            "source": {"type": "tool", "identifier": "hermes"},
        }
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = _api_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        data = _post(f"{base}/api/v1/action-guard", body, timeout, opener, headers)
    except Exception as exc:
        return ActionGuardVerdict("allow", [], f"scanner unreachable: {exc}", available=False)

    # A 200 JSON body is not a verdict. Missing/unknown `decision` used to
    # coerce to allow + available=True, which skipped the #59 fallback and
    # failed open on the advertised bound plane (wrong local service, proxy
    # envelope, future field rename). Treat it as unavailable so the
    # catastrophic/dangerous fallback still runs.
    if not isinstance(data, dict):
        return ActionGuardVerdict("allow", [], "malformed action-guard response", available=False)
    decision_raw = data.get("decision")
    if not isinstance(decision_raw, str) or not decision_raw.strip():
        return ActionGuardVerdict(
            "allow", [], "malformed action-guard response: missing decision", available=False,
        )
    decision = decision_raw.strip().lower()
    if decision not in ("allow", "require_approval", "block"):
        shown = decision[:32]
        return ActionGuardVerdict(
            "allow", [], f"unknown action-guard decision: {shown!r}", available=False,
        )
    signals = data.get("signals") or []
    if not isinstance(signals, list):
        signals = []
    reason = data.get("reason") or ""
    return ActionGuardVerdict(decision, signals, reason, available=True)


def scan(
    content: str,
    *,
    title: str = "hermes",
    source_type: str = "tool",
    source_id: str = "hermes",
    base_url: str | None = None,
    timeout: float = 4.0,
    opener=urllib.request.urlopen,
) -> Verdict:
    """Scan `content` through ShieldCortex. Never raises — returns a Verdict."""
    base = (base_url or DEFAULT_BASE_URL).rstrip("/")
    body = json.dumps(
        {"content": content, "title": title, "source": {"type": source_type, "identifier": source_id}}
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    token = _api_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"  # never logged
    try:
        data = _post(f"{base}/api/v1/scan", body, timeout, opener, headers)
    except Exception as exc:  # network / HTTP / parse error -> fail OPEN
        return Verdict("ERROR", [], f"scanner unreachable: {exc}", available=False)

    fw = (data or {}).get("firewall") or {}
    result = fw.get("result", "ALLOW")
    threats = fw.get("threatIndicators") or fw.get("threats") or []
    reason = fw.get("reason", "")
    return Verdict(result, threats, reason, available=True)
