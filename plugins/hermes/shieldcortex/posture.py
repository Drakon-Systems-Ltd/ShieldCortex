"""
Process-side posture self-report for the Hermes plugin (#613).

`shieldcortex doctor` and `shieldcortex policy-evidence` run in a separate
process. They cannot see what `SHIELDCORTEX_ENFORCE` resolved to inside the
Hermes gateway, whether this plugin's `pre_tool_call` hook actually
registered, or whether the scanner was reachable. So the plugin says so
itself, in a small versioned file the CLI reads:

    <config dir>/posture/hermes/<profile>/<instance>.json

where `<config dir>` is `SHIELDCORTEX_CONFIG_DIR` or `~/.shieldcortex`,
`<profile>` is the Hermes profile name when `HERMES_HOME` points at
`.../profiles/<name>` (else `default`), and `<instance>` is this PROCESS's
start identity (pid + Linux start ticks where the host exposes them). Two
gateways on one profile never overwrite each other, and a restarted gateway
never inherits the previous process's denials.

Contract:

* The schema is closed and versioned; the CLI rejects anything else.
* Writes are atomic (temp file + `os.replace`), private (0600 file, 0700
  directories) and bounded (`MAX_BYTES`).
* A denial carries its own timestamp and the identity it was observed
  against. A heartbeat never refreshes it.
* Nothing here may raise into `register()` or `pre_tool_call`, and nothing
  here can change a gate decision: every entry point returns a bool or None
  and swallows its own failures.

Host-integrity limitation: this is a host-local file recording what this
process said about itself. It is not attestation.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from datetime import datetime, timezone

SCHEMA = "shieldcortex.posture.self-report"
VERSION = 1
MAX_BYTES = 8192
MAX_INTERVALS = 8
REASON_MAX = 120
#: Rewrite at least this often while calls keep arriving, so an idle-but-alive
#: gateway does not go stale in the CLI's view unnecessarily.
HEARTBEAT_SECONDS = 600
#: Sibling reports untouched this long are from processes long gone.
PRUNE_AFTER_SECONDS = 7 * 24 * 3600

POSTURES = frozenset({"enforce", "advisory", "intentionally-off", "unavailable", "unknown"})
SCANNER_STATES = frozenset({"available", "degraded", "unknown"})
DENIAL_KINDS = frozenset({"blocked-action", "synthetic-probe"})
PLUGIN_ID = "shieldcortex"

_PROFILE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_IDENT_RE = re.compile(r"^[A-Za-z0-9@/._:+-]{1,64}$")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_plugin_hash_cache = None
_identity = None
_IMPORTED_AT = time.time()


def config_dir() -> str:
    override = (os.environ.get("SHIELDCORTEX_CONFIG_DIR") or "").strip()
    return override or os.path.join(os.path.expanduser("~"), ".shieldcortex")


def profile_id(hermes_home) -> str:
    """The Hermes profile this process serves, as a closed-grammar id."""
    if not isinstance(hermes_home, str) or not hermes_home.strip():
        return "default"
    norm = os.path.normpath(hermes_home.strip())
    parent = os.path.basename(os.path.dirname(norm))
    name = os.path.basename(norm).lower()
    if parent == "profiles" and _PROFILE_RE.match(name):
        return name
    return "default"


def _iso(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (dt.microsecond // 1000)


def _linux_self_start():
    try:
        with open("/proc/self/stat", encoding="utf-8") as fh:
            text = fh.read()
        start = text[text.rindex(")") + 2:].split(" ")[19]
        return start if re.match(r"^[0-9]{1,20}$", start) else None
    except Exception:
        return None


def process_identity():
    """This process's start identity, computed once per process."""
    global _identity
    if _identity is None or _identity["pid"] != os.getpid():
        start = _linux_self_start()
        pid = os.getpid()
        key = "p%d-s%s" % (pid, start) if start else "p%d-r%s" % (pid, secrets.token_hex(4))
        _identity = {"key": key, "pid": pid, "start": start, "started_at": _iso(_IMPORTED_AT)}
    return _identity


def _sanitize_reason(reason) -> str:
    text = reason if isinstance(reason, str) else ""
    text = "".join(ch if 0x20 <= ord(ch) <= 0x7E else "?" for ch in text)[:REASON_MAX]
    return text or "unspecified"


def _ident_or_none(value):
    return value if isinstance(value, str) and _IDENT_RE.match(value) else None


def tested_path(hook, tool_name) -> str:
    tool = re.sub(r"[^A-Za-z0-9._:+-]", "_", str(tool_name or "unknown"))[:40] or "unknown"
    return ("%s:%s" % (hook, tool))[:64]


def _plugin_hash():
    """sha256 over this package's own source files, computed once."""
    global _plugin_hash_cache
    if _plugin_hash_cache is None:
        h = hashlib.sha256()
        try:
            for name in sorted(os.listdir(_PACKAGE_DIR)):
                if not (name.endswith(".py") or name in ("plugin.yaml", "plugin.yml")):
                    continue
                path = os.path.join(_PACKAGE_DIR, name)
                if not os.path.isfile(path):
                    continue
                h.update(name.encode("utf-8") + b"\0")
                with open(path, "rb") as fh:
                    h.update(fh.read())
            _plugin_hash_cache = "sha256:" + h.hexdigest()
        except Exception:
            _plugin_hash_cache = ""
    return _plugin_hash_cache or None


def _plugin_version():
    try:
        with open(os.path.join(_PACKAGE_DIR, "plugin.yaml"), encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^version:\s*['\"]?([A-Za-z0-9._+-]{1,64})['\"]?\s*$", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def policy_hash(policy):
    if policy is None:
        return None
    try:
        blob = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception:
        return None
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _read_previous(path):
    """This process's previous report, only as far as it is safe to carry forward."""
    try:
        st = os.lstat(path)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            return {}
        with open(path, encoding="utf-8") as fh:
            prev = json.loads(fh.read(MAX_BYTES + 1))
        return prev if isinstance(prev, dict) else {}
    except Exception:
        return {}


def _intervals(prev, scanner, reason, now_iso):
    kept = []
    for item in prev.get("degraded_intervals") or []:
        if not isinstance(item, dict):
            continue
        frm, to, why = item.get("from"), item.get("to"), item.get("reason")
        if not (isinstance(frm, str) and _ISO_RE.match(frm)):
            continue
        if to is not None and not (isinstance(to, str) and _ISO_RE.match(to)):
            continue
        kept.append({"from": frm, "to": to, "reason": _sanitize_reason(why)})
    open_last = bool(kept) and kept[-1]["to"] is None
    if scanner == "degraded" and not open_last:
        kept.append({"from": now_iso, "to": None, "reason": _sanitize_reason(reason or "scanner-degraded")})
    elif scanner == "available" and open_last:
        kept[-1]["to"] = now_iso
    return kept[-MAX_INTERVALS:]


def _carried_denial(value, key):
    """A previous denial, kept only if it is well-formed and from THIS process."""
    if not isinstance(value, dict) or value.get("instance") != key:
        return None
    try:
        if set(value) != {"at", "tested_path", "instance", "plugin_hash", "policy_hash", "configured_posture"}:
            return None
        if not (isinstance(value["at"], str) and _ISO_RE.match(value["at"])):
            return None
        if not (isinstance(value["tested_path"], str) and _IDENT_RE.match(value["tested_path"])):
            return None
        for h in ("plugin_hash", "policy_hash"):
            if value[h] is not None and not (isinstance(value[h], str) and _SHA_RE.match(value[h])):
                return None
        if value["configured_posture"] not in POSTURES:
            return None
        return dict(value)
    except Exception:
        return None


def _secure_dir(path):
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise OSError("not a directory")
    if st.st_mode & 0o077:
        os.chmod(path, 0o700)


def _prune(directory, keep, now):
    try:
        for name in os.listdir(directory):
            if name == keep:
                continue
            full = os.path.join(directory, name)
            try:
                st = os.lstat(full)
                if not stat.S_ISREG(st.st_mode):
                    continue
                age = now - st.st_mtime
                if (".tmp-" in name and age > 3600) or (name.endswith(".json") and age > PRUNE_AFTER_SECONDS):
                    os.unlink(full)
            except Exception:
                pass
    except Exception:
        pass


def write_self_report(
    cfg_dir,
    *,
    profile="default",
    configured_posture,
    scanner="unknown",
    policy=None,
    denial=False,
    denial_kind="blocked-action",
    denial_path="pre_tool_call:unknown",
    degraded_reason=None,
    runtime_version=None,
    loaded=True,
    now=None,
) -> bool:
    """Write the report atomically. Returns False on any failure; never raises."""
    tmp = None
    try:
        if configured_posture not in POSTURES or scanner not in SCANNER_STATES:
            return False
        if not isinstance(profile, str) or not _PROFILE_RE.match(profile):
            return False
        if denial and denial_kind not in DENIAL_KINDS:
            return False
        ts = time.time() if now is None else now
        now_iso = _iso(ts)
        ident = process_identity()
        root = os.path.join(cfg_dir, "posture")
        directory = os.path.join(root, "hermes", profile)
        _secure_dir(root)
        _secure_dir(os.path.join(root, "hermes"))
        _secure_dir(directory)
        name = "%s.json" % ident["key"]
        path = os.path.join(directory, name)
        prev = _read_previous(path)
        prev_denials = prev.get("denials") if isinstance(prev.get("denials"), dict) else {}
        blocked = _carried_denial(prev_denials.get("blocked_action"), ident["key"])
        probe = _carried_denial(prev_denials.get("synthetic_probe"), ident["key"])
        count = prev_denials.get("blocked_action_count")
        count = count if isinstance(count, int) and not isinstance(count, bool) and 0 <= count < 10**9 else 0
        p_hash = policy_hash(policy)
        if denial:
            record = {
                "at": now_iso,
                "tested_path": denial_path if isinstance(denial_path, str) and _IDENT_RE.match(denial_path) else "unknown",
                "instance": ident["key"],
                "plugin_hash": _plugin_hash(),
                "policy_hash": p_hash,
                "configured_posture": configured_posture,
            }
            if denial_kind == "synthetic-probe":
                probe = record
            else:
                blocked = record
                count += 1
        body = {
            "schema": SCHEMA,
            "version": VERSION,
            "runtime": "hermes",
            "profile": profile,
            "plane": "tool-gate",
            "instance": {
                "key": ident["key"],
                "pid": ident["pid"],
                "process_start": ident["start"],
                "started_at": ident["started_at"],
                "liveness": "process",
            },
            "runtime_version": _ident_or_none(runtime_version),
            "plugin": {"id": PLUGIN_ID, "version": _plugin_version(), "hash": _plugin_hash()},
            "heartbeat_at": now_iso,
            "loaded": bool(loaded),
            "configured_posture": configured_posture,
            "scanner": scanner,
            "policy_hash": p_hash,
            "degraded_intervals": _intervals(prev, scanner, degraded_reason, now_iso),
            "denials": {"blocked_action": blocked, "synthetic_probe": probe, "blocked_action_count": count},
        }
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        if len(data) > MAX_BYTES:
            body["degraded_intervals"] = body["degraded_intervals"][-1:]
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            if len(data) > MAX_BYTES:
                return False
        tmp = "%s.tmp-%d-%s" % (path, os.getpid(), secrets.token_hex(4))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(tmp, flags, 0o600)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, path)
        tmp = None
        _prune(directory, name, ts)
        return True
    except Exception:
        return False
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except Exception:
                pass


def report_path(cfg_dir, profile="default"):
    """Where THIS process's report for `profile` lives."""
    return os.path.join(cfg_dir, "posture", "hermes", profile, "%s.json" % process_identity()["key"])


class Reporter:
    """Throttled, failure-proof writer used by the plugin's gate."""

    def __init__(self, enforce: bool):
        self.config_dir = config_dir()
        self.profile = profile_id(os.environ.get("HERMES_HOME"))
        self.posture = "enforce" if enforce else "advisory"
        self.policy = {"enforce": bool(enforce)}
        self.scanner = "unknown"
        self._last_write = None

    def write(self, *, scanner=None, denial=False, tool_name=None, reason=None, force=False) -> None:
        try:
            changed = scanner is not None and scanner != self.scanner
            if scanner is not None:
                self.scanner = scanner
            now = time.monotonic()
            due = self._last_write is None or now - self._last_write >= HEARTBEAT_SECONDS
            if not (force or denial or changed or due):
                return
            self._last_write = now
            write_self_report(
                self.config_dir,
                profile=self.profile,
                configured_posture=self.posture,
                scanner=self.scanner,
                policy=self.policy,
                denial=denial,
                denial_kind="blocked-action",
                denial_path=tested_path("pre_tool_call", tool_name),
                degraded_reason=reason,
            )
        except Exception:
            pass
