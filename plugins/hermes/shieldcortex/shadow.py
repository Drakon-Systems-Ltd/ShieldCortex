"""
ShieldCortex — Hermes plugin shadowing detector (#569).

Hermes discovers plugins by walking every child directory of
`$HERMES_HOME/plugins/`, keying each one on the `name:` in its manifest rather
than on the folder name. It walks in sorted order and, on a same-source key
collision, the LATER manifest silently replaces the earlier one
(NousResearch/hermes-agent#121078).

So a backup left beside the live plugin — `plugins/shieldcortex.bak-pre510-<ts>/`,
the natural thing to make before an upgrade — sorts after `plugins/shieldcortex/`
and is what Hermes loads. The upgrade lands on disk and the gateway keeps
running the old code, with nothing in the log to say so.

This module is the plugin's own half of the answer: whichever copy is running
is by definition the one that won discovery, so at `register()` time it can say
out loud where it was loaded from and which other copies were passed over.

## It asks Hermes, and if Hermes cannot answer it says nothing

This code runs INSIDE Hermes, so `hermes_cli` is the only thing it consults:
`_hermes_root_scan` imports `hermes_cli.plugins_discovery` and calls the very
functions the loader used a moment earlier.

Rounds 1 to 3 also carried a reader of our own for the case where that import
fails, narrowing its grammar each round. Four rounds of independent review on
the sibling Ekho change found a confident wrong answer in every version of it,
the last two from lines with no exotic syntax at all — `description: 2026-99-99`
(YAML types the plain scalar as a timestamp, the month is invalid, construction
fails and Hermes drops the whole manifest) and `manifest_version: .inf` (YAML
constructs infinity and Hermes' `int()` conversion raises `OverflowError`).
Chasing YAML's implicit typing and Hermes' own conversions is endless, and a
start-up diagnostic that is sometimes confidently wrong about which copy is
running is worth less than no line at all. So round 4 removed the reader: if
Hermes' discovery is not available, this logs one DEBUG line and returns.

Importing `hermes_cli` is not free of side effects (its `__init__` can
reconfigure the standard streams, and `config` can evict stale modules), but
inside the gateway it is already imported. What this check never does is run
plugin registration or install anything: it calls the read-only scanning
functions and nothing else.

Stdlib only, and every entry point swallows its own errors: a start-up
diagnostic must never be able to stop the gate from registering.
"""
import contextlib
import logging
import os
import threading

#: The manifest key this plugin declares — the thing that can collide.
PLUGIN_NAME = "shieldcortex"

#: Past this many entries in a `plugins/` root, the START-UP check declines
#: (#569 r3). Hermes' discovery reads a manifest per child and recurses into
#: category dirs; that is nothing for the tens of entries a real plugins root
#: holds, and not something to do a second time synchronously inside
#: `register()` for thousands. `shieldcortex doctor` has no such cap: there the
#: scan IS the work.
MAX_STARTUP_ROOT_ENTRIES = 256

log = logging.getLogger("shieldcortex.hermes")


# ── Ask Hermes ────────────────────────────────────────────────────────────

#: The loggers Hermes' discovery emits on. Suppression is scoped to THESE, for
#: the duration of our scan, on OUR thread — never the root logger (#569 r3).
#: A gateway logging from another thread through the same logger is not ours to
#: silence, and an ancestor's filters never see a child's records, so the
#: filter goes on each emitting logger itself.
_DISCOVERY_LOGGERS = (
    "hermes_cli.plugins",
    "hermes_cli.plugins_discovery",
    "hermes_cli.plugins_manifest",
    "hermes_cli.agent_plugins",
)

#: `record.module` for the records this scan causes.
_DISCOVERY_MODULES = frozenset({
    "plugins", "plugins_discovery", "plugins_manifest", "agent_plugins",
})


class _ScanQuietFilter(logging.Filter):
    """Drop the records OUR scan provokes; pass everything else through.

    `scan_directory` warns about every unreadable directory and unparseable
    manifest it meets. That is useful to the gateway and pure noise from a
    diagnostic pass whose whole subject is those directories — the loader has
    already said it once. A filter returning False stops the record before
    `callHandlers`, so it does not propagate either, which is exactly why this
    has to be narrow: same logger, different thread, still gets through.
    """

    def __init__(self):
        logging.Filter.__init__(self)
        self.thread = threading.get_ident()

    def filter(self, record):
        if getattr(record, "module", None) not in _DISCOVERY_MODULES:
            return True
        if getattr(record, "thread", None) not in (None, self.thread):
            return True
        return False


def _discovery_logger_names(modules):
    """Every logger to filter: the documented names, whatever `logger` the
    imported discovery modules actually hold, and any existing children."""
    names = set(_DISCOVERY_LOGGERS)
    for module in modules or ():
        found = getattr(module, "logger", None)
        if isinstance(found, logging.Logger) and found.name:
            names.add(found.name)
    for existing in list(logging.root.manager.loggerDict):
        if any(existing.startswith(name + ".") for name in tuple(names)):
            names.add(existing)
    # Never the root logger: it carries everything this process logs.
    return sorted(name for name in names if name)


@contextlib.contextmanager
def _quiet_discovery_logging(modules=()):
    """Install `_ScanQuietFilter` on the discovery loggers for this block."""
    installed = []
    scan_filter = _ScanQuietFilter()
    try:
        for name in _discovery_logger_names(modules):
            logger = logging.getLogger(name)
            logger.addFilter(scan_filter)
            installed.append(logger)
        yield
    finally:
        for logger in installed:
            try:
                logger.removeFilter(scan_filter)
            except Exception:  # pragma: no cover - defensive
                pass


def _hermes_root_scan(root):
    """`(copies, winner, reason)` from Hermes' own discovery.

    `copies is None` means Hermes could not answer and `reason` says why, in
    the words the operator needs: the import failed, or discovery itself
    raised. Round 2 flattened both to "hermes_cli not importable", which is
    wrong for every failure after a successful import (#569 r3).
    """
    try:
        from pathlib import Path

        from hermes_cli import plugins_discovery as _discovery
        from hermes_cli import plugins_manifest as _manifest
        from hermes_cli.plugins_discovery import resolve_manifest_winners, scan_directory
        from hermes_cli.plugins_manifest import manifest_key
    except Exception as exc:
        return None, None, "hermes_cli is not importable (%s: %s)" % (type(exc).__name__, exc)
    try:
        with _quiet_discovery_logging((_discovery, _manifest)):
            manifests = scan_directory(Path(root), "user")
            copies = [str(m.path) for m in manifests if manifest_key(m) == PLUGIN_NAME]
            winner = resolve_manifest_winners(manifests).get(PLUGIN_NAME)
    except Exception as exc:
        return None, None, "hermes_cli discovery raised %s: %s" % (type(exc).__name__, exc)
    return copies, (str(winner.path) if winner is not None else None), None


def _root_is_too_big(root):
    """True when this root has more entries than the START-UP check will read.

    See `MAX_STARTUP_ROOT_ENTRIES`.
    """
    counted = 0
    try:
        with os.scandir(root) as entries:
            for _entry in entries:
                counted += 1
                if counted > MAX_STARTUP_ROOT_ENTRIES:
                    return True
    except OSError:
        return False  # unreadable: let Hermes' own scan report whatever it can
    return False


def _same_path(left, right):
    """Path identity WITHOUT resolving symlinks — see `_package_dir`."""
    return os.path.normpath(os.path.abspath(left)) == os.path.normpath(os.path.abspath(right))


def detect_shadow(package_dir):
    """Describe this copy's discovery situation, or None when there is nothing
    to say.

    None covers two different things on purpose, because the plugin's start-up
    line treats them the same way — it stays quiet:

      * the root is clean: this copy is named `shieldcortex` (what the
        installer writes) and no sibling takes the same manifest key;
      * Hermes' own discovery could not be reached, or the root is too big to
        rescan inside `register()`. One DEBUG line is logged and no verdict is
        produced. Rounds 1 to 3 answered from a reader of our own here; four
        review rounds found every version of it confidently wrong on some
        ordinary manifest, so there is nothing left to answer WITH (#569 r4).

    `package_dir` must be the path DISCOVERY used, not a resolved one. When
    Hermes loads `plugins/shieldcortex.bak-x -> /srv/sc-old`, the discovery path
    is the link, and it is the link that has to be recognised — a `realpath()`
    hands back `/srv/sc-old`, whose parent is not a `plugins/` root, and the
    whole diagnostic silently gives up on the one case it exists for.

    The returned dict has `loaded` (this copy's path), `expected` (the canonical
    path beside it), `misnamed` and `others` (copies Hermes passed over).
    """
    try:
        loaded = os.path.abspath(package_dir)
        own_name = os.path.basename(loaded)
        parent = os.path.dirname(loaded)

        if _root_is_too_big(parent):
            log.debug(
                "[shieldcortex] plugin copy check skipped at start-up: %s holds more than %d "
                "entries; run `shieldcortex doctor` for the full scan",
                parent, MAX_STARTUP_ROOT_ENTRIES,
            )
            return None

        copies, _winner, reason = _hermes_root_scan(parent)
        if copies is None:
            # Inside the gateway this should be unreachable: Hermes just used
            # the module we are asking for. DEBUG, because a diagnostic that
            # could not run is a fact about this process and not a problem with
            # the host — and because doctor is where "could not determine" is
            # reported properly, with the remedy attached.
            log.debug(
                "[shieldcortex] plugin copy check skipped at start-up: %s; "
                "run `shieldcortex doctor` for the full scan", reason,
            )
            return None

        others = sorted(c for c in copies if not _same_path(c, loaded))
        misnamed = own_name != PLUGIN_NAME
        if not misnamed and not others:
            return None
        return {
            "loaded": loaded,
            "expected": os.path.join(parent, PLUGIN_NAME),
            "misnamed": misnamed,
            "others": others,
        }
    except Exception:  # pragma: no cover - defensive
        return None


def shadow_error_line(report):
    """One log line for a `detect_shadow` report, or None when there is none."""
    if not report:
        return None
    try:
        parts = ["[shieldcortex] plugin copy conflict: Hermes loaded this plugin from %s"
                 % report["loaded"]]
        if report.get("misnamed"):
            parts.append("which is not the installed %s" % report["expected"])
        others = report.get("others") or []
        if others:
            parts.append("other directories declaring `name: %s` were passed over: %s"
                         % (PLUGIN_NAME, ", ".join(others)))
        parts.append(
            "Hermes keys plugins on the manifest name and the last directory in sorted order "
            "wins silently, so an upgrade can leave old code running. Run `shieldcortex doctor "
            "--fix-hermes-plugin-copies`, then restart the Hermes gateway"
        )
        return "; ".join(parts) + "."
    except Exception:  # pragma: no cover - defensive
        return None
