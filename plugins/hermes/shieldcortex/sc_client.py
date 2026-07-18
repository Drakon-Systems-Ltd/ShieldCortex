"""
ShieldCortex defence client for the Hermes plugin.

Calls ShieldCortex's local REST API (`POST /api/v1/scan`, the documented
"Python via REST" surface) to run content through the defence pipeline and
returns a normalised verdict. Hermes is Python; ShieldCortex is Node — REST is
the clean cross-runtime boundary (no CLI text-scraping, no in-process bridge).

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
    re.compile(r"\brm\b[^|;&\n]*?(?:-\w*r\w*f\w*|-\w*f\w*r\w*|(?=[^|;&\n]*--recursive)(?=[^|;&\n]*--force))", re.I),
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
