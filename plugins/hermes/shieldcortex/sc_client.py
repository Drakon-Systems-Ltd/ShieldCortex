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

Fail-OPEN by design: if the scanner is unreachable or errors, we return an
`available=False` verdict and the policy layer never blocks on it — a down
scanner must not wedge the agent. Every fail-open is logged by the caller.
"""
from __future__ import annotations

import json
import os
import urllib.request

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
