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

## An answer it could not read is not an answer (#569 r8)

Two things make a copy invisible to this check while the gateway loads it
perfectly well, and both are about READING a manifest rather than finding one:

  * the check stopped at `os.stat`, and stat and open are two different
    permissions. A portable `plugin.json` written 0600 by another account
    stats for everybody and opens for nobody else, so the file whose contents
    decide the key was never actually consulted. Every candidate that is there
    is now opened and one byte taken out of it;
  * Hermes wraps what it hit. `agent_plugins._read_json_object` turns a
    PermissionError into an `AgentPluginError` — a ValueError — with
    `raise ... from exc`, and `plugins_discovery` logs that wrapper. On its own
    type it is indistinguishable from a schema rejection, which is an ANSWER,
    so the records this scan provokes are now kept and every one of them is
    followed down its `__cause__`/`__context__` chain.

Neither produces a verdict here: an incomplete answer is one DEBUG line, and
`shieldcortex doctor` is where uncertainty is reported with a remedy.

Stdlib only, and every entry point swallows its own errors: a start-up
diagnostic must never be able to stop the gate from registering.
"""
import contextlib
import logging
import os
import stat
import threading

#: The manifest key this plugin declares — the thing that can collide.
PLUGIN_NAME = "shieldcortex"

#: The manifest names Hermes looks for in a plugin directory, in its order.
MANIFEST_NAMES = ("plugin.yaml", "plugin.yml", "plugin.json")

#: How far down an exception's `__cause__`/`__context__` chain to look for the
#: filesystem error underneath it (#569 r8). Bounded because a chain can be
#: long, and `__context__` can be cyclic.
MAX_EXCEPTION_CHAIN = 12

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
    """Drop the records OUR scan provokes — and KEEP them; pass the rest through.

    `scan_directory` warns about every unreadable directory and unparseable
    manifest it meets. That is useful to the gateway and pure noise from a
    diagnostic pass whose whole subject is those directories — the loader has
    already said it once. A filter returning False stops the record before
    `callHandlers`, so it does not propagate either, which is exactly why this
    has to be narrow: same logger, different thread, still gets through.

    Suppressing a record is fine; DISCARDING what it said is not (#569 r8). A
    manifest Hermes could not read is reported as one of these warnings and
    nowhere else, so the records our own scan caused are kept for
    :func:`_unreadable_from_records` to classify.
    """

    def __init__(self):
        logging.Filter.__init__(self)
        self.thread = threading.get_ident()
        self.records = []

    def filter(self, record):
        if getattr(record, "module", None) not in _DISCOVERY_MODULES:
            return True
        if getattr(record, "thread", None) not in (None, self.thread):
            return True
        self.records.append(record)
        return False


def _fs_reason(path, exc):
    """One filesystem failure in the words an operator can act on."""
    return "%s (%s: %s)" % (path, type(exc).__name__, exc)


def _os_error_in_chain(exc):
    """The filesystem failure underneath *exc* — or None if there is not one.

    Hermes does not always log the error it met. `agent_plugins
    ._read_json_object` turns a PermissionError on `plugin.json` into an
    `AgentPluginError` — a ValueError — with `raise ... from exc`, and
    `plugins_discovery` logs that wrapper (#569 r8). Judged on the logged
    object alone it cannot be told apart from a manifest that failed schema
    validation, which is an ANSWER, so a directory that was not read was taken
    for "not a plugin" and the root came out clean.

    `__cause__` first (the explicit `from`), then `__context__` (what was being
    handled), bounded by :data:`MAX_EXCEPTION_CHAIN` with a seen-set for the
    cycles `__context__` can form. FileNotFoundError is not one of these at any
    depth — a manifest that went away mid-scan was discovered by nobody — and a
    JSON or schema error with no OSError under it comes back None and stays the
    verdict it is.
    """
    seen = set()
    while isinstance(exc, BaseException) and len(seen) < MAX_EXCEPTION_CHAIN:
        if id(exc) in seen:
            return None
        seen.add(id(exc))
        if isinstance(exc, OSError) and not isinstance(exc, FileNotFoundError):
            return exc
        exc = exc.__cause__ if exc.__cause__ is not None else exc.__context__
    return None


def _record_exceptions(record, args):
    """Every exception one record carries: in its args, and in `exc_info`.

    Hermes logs the exception as a formatting argument (`"Failed to parse %s:
    %s", path, exc`) and sometimes attaches it as well — `parse_manifest_file`
    passes `exc_info=` under the plugins debug flag. Both are read, because
    which one is populated is a Hermes-side setting and not something a verdict
    here should depend on.
    """
    found = [arg for arg in args if isinstance(arg, BaseException)]
    info = getattr(record, "exc_info", None)
    if isinstance(info, tuple) and len(info) > 1 and isinstance(info[1], BaseException):
        found.append(info[1])
    return found


def _unreadable_from_records(records):
    """The filesystem failures Hermes met while scanning, as readable reasons.

    The test is on the record's arguments rather than on its wording, so a
    rephrased log line still counts. The path is the first path-like argument —
    Hermes puts it there in every one of these lines — and falls back to the
    errno's own `filename`.
    """
    found = []
    for record in records or ():
        try:
            args = record.args if isinstance(record.args, tuple) else (record.args,)
            under = None
            for candidate in _record_exceptions(record, args):
                under = _os_error_in_chain(candidate)
                if under is not None:
                    break
            if under is None:
                continue
            named = next(
                (a for a in args if isinstance(a, str) or hasattr(a, "__fspath__")), None)
            if named is None:
                named = getattr(under, "filename", None)
            found.append(_fs_reason(named if named is not None else "(path not reported)", under))
        except Exception:  # pragma: no cover - a diagnostic never raises
            continue
    return found


def _manifest_read_problems(root):
    """Why a manifest beside this copy would not be READ — one reason each.

    `scan_directory` picks a child up by asking whether `plugin.yaml` and
    friends exist, and then it OPENS what it found. Those are two different
    permissions (#569 r8): a portable `plugin.json` written 0600 by another
    account stats for everybody and opens for nobody else, so stat-ing it
    proves nothing about the file whose contents decide the key. Every
    candidate that is there is therefore opened and one byte is taken out of
    it.

    Only the root's DIRECT children are walked. A manifest one level down is
    keyed `<category>/<name>` by Hermes and cannot collide with this plugin's
    key, so it is not part of the question this module asks.

    Absent is the ordinary case and no problem at all. A candidate that is not
    a regular file is an answer too and is left alone: nobody reads a directory
    as a manifest, here or in the loader, and opening a FIFO named
    `plugin.json` would hang the gateway's start-up rather than answer it.
    """
    problems = []
    try:
        with os.scandir(root) as entries:
            children = [entry.path for entry in entries if entry.is_dir()]
    except (FileNotFoundError, NotADirectoryError):
        return []  # genuinely absent contributes nothing, which is true
    except OSError as exc:
        return [_fs_reason(root, exc)]
    except Exception:  # pragma: no cover - a diagnostic never raises
        return []
    for child in sorted(children):
        for filename in MANIFEST_NAMES:
            candidate = os.path.join(child, filename)
            try:
                mode = os.stat(candidate).st_mode
            except (FileNotFoundError, NotADirectoryError):
                continue
            except OSError as exc:
                problems.append(_fs_reason(candidate, exc))
                continue
            if not stat.S_ISREG(mode):
                continue
            try:
                with open(candidate, "rb") as handle:
                    handle.read(1)
            except FileNotFoundError:
                continue
            except OSError as exc:
                problems.append(_fs_reason(candidate, exc))
    return problems


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
    """Install `_ScanQuietFilter` on the discovery loggers for this block.

    Yields the filter itself: what it swallowed is the only account anyone has
    of a manifest Hermes could not read (#569 r8).
    """
    installed = []
    scan_filter = _ScanQuietFilter()
    try:
        for name in _discovery_logger_names(modules):
            logger = logging.getLogger(name)
            logger.addFilter(scan_filter)
            installed.append(logger)
        yield scan_filter
    finally:
        for logger in installed:
            try:
                logger.removeFilter(scan_filter)
            except Exception:  # pragma: no cover - defensive
                pass


def _hermes_root_scan(root):
    """`(copies, winner, reason, unreadable)` from Hermes' own discovery.

    `copies is None` means Hermes could not answer and `reason` says why, in
    the words the operator needs: the import failed, or discovery itself
    raised. Round 2 flattened both to "hermes_cli not importable", which is
    wrong for every failure after a successful import (#569 r3).

    `unreadable` is the filesystem failures Hermes met WHILE answering (#569
    r8). Those are not failures of the scan — it completed — but each one is a
    directory whose manifest nobody read, so the copy list is a floor and not
    the whole of it.
    """
    try:
        from pathlib import Path

        from hermes_cli import plugins_discovery as _discovery
        from hermes_cli import plugins_manifest as _manifest
        from hermes_cli.plugins_discovery import resolve_manifest_winners, scan_directory
        from hermes_cli.plugins_manifest import manifest_key
    except Exception as exc:
        return None, None, "hermes_cli is not importable (%s: %s)" % (type(exc).__name__, exc), []
    try:
        with _quiet_discovery_logging((_discovery, _manifest)) as captured:
            manifests = scan_directory(Path(root), "user")
            copies = [str(m.path) for m in manifests if manifest_key(m) == PLUGIN_NAME]
            winner = resolve_manifest_winners(manifests).get(PLUGIN_NAME)
    except Exception as exc:
        return None, None, "hermes_cli discovery raised %s: %s" % (type(exc).__name__, exc), []
    return (copies, (str(winner.path) if winner is not None else None), None,
            _unreadable_from_records(captured.records))


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

        copies, _winner, reason, unreadable = _hermes_root_scan(parent)
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

        # What neither Hermes nor this process could READ (#569 r8). Both
        # halves land here: the manifests we opened ourselves, and the ones
        # Hermes met an error on and logged — including the PermissionError it
        # wraps in an `AgentPluginError` for a portable `plugin.json`, which
        # looks exactly like a schema rejection until the chain is followed.
        #
        # This is a start-up diagnostic, so an incomplete answer is said once
        # at DEBUG and nothing more: the list below is a FLOOR, `doctor` is
        # where "could not determine" is reported properly with the remedy
        # attached, and a gate must never be held up by a check about it.
        unreadable = list(unreadable) + _manifest_read_problems(parent)
        if unreadable:
            log.debug(
                "[shieldcortex] plugin copy check is incomplete: could not read %s; "
                "run `shieldcortex doctor` for the full scan", "; ".join(unreadable),
            )

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
