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

## Where the answer comes from

This code runs INSIDE Hermes, so it asks Hermes. `_hermes_root_scan` imports
`hermes_cli.plugins_discovery` and uses the very functions the loader used a
moment earlier. There is no second implementation of the discovery rules to
drift out of parity with — round 1 had one, and an independent review of the
sibling Ekho fix found six shapes where a hand-rolled line reader and Hermes
disagree.

Importing `hermes_cli` is not free of side effects (its `__init__` can
reconfigure the standard streams, and `config` can evict stale modules), but
inside the gateway it is already imported. What this check never does is run
plugin registration or install anything: it calls the read-only scanning
functions and nothing else.

`_fallback_root_scan` is what runs if that import ever fails — a stripped
environment, a partially installed Hermes. Round 3 made it deliberately narrow:
it only ever answers about a manifest it fully understands, and a manifest it
does not is `unknown`, which costs its whole root a verdict. See
`_understand_manifest`. The real reason the fallback was reached is kept and
printed, rather than flattened to "hermes_cli not importable".

Stdlib only, and every entry point swallows its own errors: a start-up
diagnostic must never be able to stop the gate from registering.
"""
import contextlib
import logging
import os
import re
import threading

#: The manifest key this plugin declares — the thing that can collide.
PLUGIN_NAME = "shieldcortex"

#: Manifests are a few hundred bytes. Hermes reads them whole; the fallback
#: stops here because an unbounded read in a start-up path is a hazard the last
#: scrap of parity is not worth. Over the cap is reported `unknown`, never
#: "not ours" — Hermes would have read it.
MANIFEST_BYTE_CAP = 64 * 1024

#: Past this many entries in a `plugins/` root, the START-UP check declines
#: (#569 r3). Whichever half answers, the cost is a manifest read per child, and
#: Hermes' own discovery also recurses into category dirs and reads each
#: manifest whole. That is nothing for the tens of entries a real plugins root
#: holds, and not something to do synchronously inside `register()` for
#: thousands. `shieldcortex doctor` has no such cap: there the scan IS the work.
MAX_STARTUP_ROOT_ENTRIES = 256

#: `hermes_cli.plugins_discovery._FOREIGN_HARNESS_MANIFEST_DIRS`.
_FOREIGN_HARNESS_MANIFEST_DIRS = frozenset({
    ".claude-plugin", ".codex-plugin", ".cursor-plugin", ".devin-plugin", ".kimi-plugin",
})

_MANIFEST_NAMES = ("plugin.yaml", "plugin.yml")

log = logging.getLogger("shieldcortex.hermes")


# ── Primary: ask Hermes ───────────────────────────────────────────────────

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


# ── Fallback: the conservative reader ─────────────────────────────────────
#
# Round 2 modelled as much of YAML as a line reader can and guessed at the
# rest. Review of the sibling Ekho change showed the guesses are wrong in both
# directions, and both are a start-up diagnostic lying: `name: >-` with an
# indented `shieldcortex` under it made round 2 report a clean install while
# Hermes was loading that backup, and `description: backup: before upgrade`
# under a valid `name:` line made it call a backup LOADED that Hermes rejects.
#
# So the fallback no longer tries to be a YAML parser. A manifest is UNDERSTOOD
# only when every non-blank, non-comment line is either a column-0 `key: value`
# whose value is a plain or quoted single-line scalar with no unquoted `: ` in
# it, or an indented continuation of a key other than `name`. Everything else —
# block scalars, flow collections, anchors, aliases, tags, a null `name:`,
# document markers, tabs — makes the directory `unknown`, and so does any
# directory whose effective manifest is a portable `plugin.json`.

#: A column-0 mapping key. YAML needs the space (or end of line) after the
#: colon: `name:shieldcortex` is the plain scalar `name:shieldcortex`, and a
#: scalar document is not a mapping, so Hermes rejects it outright.
_KEY_LINE = re.compile(r"^([A-Za-z_][A-Za-z0-9_.\-]*):(?:[ \t](.*))?$")

#: A value opening with any of these is not a plain or quoted scalar: a block
#: scalar, a flow collection, an anchor, an alias, a tag, or one of YAML's
#: reserved indicators.
_NOT_A_SCALAR = "|>[]{},&*!%@`?"

#: C0 controls other than tab/LF/CR, plus DEL — outside YAML's printable set,
#: so a manifest carrying one does not load at all.
_NON_PRINTABLE = re.compile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]")

_ABSENT = object()


def _read_bounded(manifest_path):
    """`(text, truncated)` for a manifest, or None when it cannot be read.

    None is a DECIDED answer, not an unknown one: Hermes' `read_text` raises on
    exactly the same inputs — a `plugin.yaml` that is a directory, a permission
    denial, bytes that are not UTF-8 — and takes no manifest from that child.
    """
    try:
        with open(manifest_path, "rb") as fh:
            raw = fh.read(MANIFEST_BYTE_CAP + 1)
    except (OSError, ValueError):
        return None
    if len(raw) > MANIFEST_BYTE_CAP:
        # A cap landing mid-character must not be mistaken for bad bytes.
        return raw[:MANIFEST_BYTE_CAP].decode("utf-8", "replace"), True
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return None


def _closing_quote(value, start):
    """Index of the quote closing the one at `start`, or None if unterminated."""
    quote = value[start]
    index = start + 1
    size = len(value)
    while index < size:
        char = value[index]
        if quote == '"' and char == "\\":
            index += 2
            continue
        if char == quote:
            if quote == "'" and value[index + 1:index + 2] == "'":
                index += 2
                continue
            return index
        index += 1
    return None


def _strip_comment(value):
    """`(payload, readable)` — one line's value with its comment removed.

    YAML starts a comment only at a `#` that begins the value or follows
    whitespace, and never inside quotes: `name: shieldcortex # backup` is
    `shieldcortex` and `name: a#b` is `a#b`. An unterminated quote is not YAML
    this reader can read.
    """
    out = []
    index = 0
    size = len(value)
    while index < size:
        char = value[index]
        if char == "#" and (index == 0 or value[index - 1] in " \t"):
            break
        if char in "\"'":
            closing = _closing_quote(value, index)
            if closing is None:
                return "", False
            out.append(value[index:closing + 1])
            index = closing + 1
            continue
        out.append(char)
        index += 1
    return "".join(out).strip(), True


def _unquote(payload):
    """The string a quoted YAML scalar stands for; a plain one passes through."""
    if len(payload) >= 2 and payload[0] == payload[-1] == '"':
        return payload[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if len(payload) >= 2 and payload[0] == payload[-1] == "'":
        return payload[1:-1].replace("''", "'")
    return payload


def _scalar(value):
    """`(payload, understood)` for one line's value.

    `payload is None` with `understood` means the line carries no value and
    opens a nested block — fine for any key but `name`, whose value would then
    be somewhere this reader cannot see.
    """
    payload, readable = _strip_comment(value)
    if not readable:
        return None, False
    if not payload:
        return None, True
    if payload[0] in "\"'":
        closing = _closing_quote(payload, 0)
        if closing is None or closing != len(payload) - 1:
            return None, False  # unterminated, or something after the quote
        return payload, True
    if payload[0] in _NOT_A_SCALAR:
        return None, False
    if any(char in payload for char in "[]{}\"'"):
        return None, False  # a flow collection, or a quote mid-scalar
    if ": " in payload or payload.endswith(":"):
        return None, False  # `description: backup: x` is not YAML at all
    return payload, True


def _understand_manifest(text):
    """`(declared name or None, understood)` for a manifest body.

    See the block comment above for the rule. `understood is False` is the
    whole point: it means this reader does not know what `yaml.safe_load` would
    make of the document, so the caller must say "unknown" rather than name a
    winner or call a root clean.
    """
    if _NON_PRINTABLE.search(text):
        return None, False
    name = _ABSENT
    key = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        # A tab may never indent YAML, and this reader reads none inside a
        # value either — both ways round, the answer is "ask Hermes".
        if "\t" in raw:
            return None, False
        body = raw.lstrip(" ")
        indent = len(raw) - len(body)

        if indent == 0:
            head = body.rstrip()
            # A document marker means there may be a second document, which
            # makes `safe_load` raise; this reader is not going to decide that.
            if head in ("---", "...") or body.startswith(("--- ", "... ")):
                return None, False
            match = _KEY_LINE.match(body)
            if match is None:
                return None, False  # the top level is not a plain mapping
            key = match.group(1)
            payload, understood = _scalar(match.group(2) or "")
            if not understood:
                return None, False
            if key == "name":
                if payload is None:
                    return None, False  # the value is on lines we cannot read
                # Duplicate keys are legal to PyYAML and the LAST wins, so this
                # deliberately overwrites rather than keeping the first.
                name = _unquote(payload)
            continue

        # An indented line continues the last column-0 key. A continuation of
        # `name` means its value is not the single-line scalar we just read.
        if key is None or key == "name":
            return None, False
        item = body
        while item.startswith("- "):
            item = item[2:].lstrip(" ")
        if not item or item == "-":
            continue
        match = _KEY_LINE.match(item)
        value = (match.group(2) or "") if match else item
        if not _scalar(value)[1]:
            return None, False

    return (None if name is _ABSENT else name), True


def read_manifest_name(manifest_path):
    """The top-level `name:` a manifest declares, or None.

    None covers both "there is no such key" and "this reader does not
    understand the document". Callers that must tell those apart use
    `classify_plugin_dir`.
    """
    read = _read_bounded(manifest_path)
    if read is None or read[1]:
        return None
    name, understood = _understand_manifest(read[0])
    return name if understood else None


def select_manifest(directory):
    """`(kind, path)` for the manifest Hermes would read, or None.

    `plugin.yaml` then `plugin.yml` on EXISTENCE — not "is a file", which is
    what Hermes uses — then a portable `plugin.json` only when neither YAML
    spelling is present.
    """
    for base in _MANIFEST_NAMES:
        candidate = os.path.join(directory, base)
        if os.path.exists(candidate):
            return "yaml", candidate
    portable = os.path.join(directory, "plugin.json")
    if os.path.exists(portable) or os.path.islink(portable):
        return "portable", portable
    return None


def could_be_ours(dir_name, text):
    """Whether a directory could possibly be keyed `shieldcortex`.

    `unknown` costs its whole root a verdict, so it is reserved for manifests
    that could still take OUR key. For Hermes to key a directory `shieldcortex`
    the manifest must produce that exact string, and there are only three ways
    that happens: the directory is named `shieldcortex` (the missing-name
    fallback), the literal bytes are in the file, or a double-quoted scalar
    spells it in escapes — a folded block scalar joins its lines with
    whitespace and cannot spell one word, and an alias resolves to an anchor
    whose text is in the same file. Without this gate, one neighbouring
    third-party manifest with a `description: >` in it would put a permanent
    "cannot determine" on a host where nothing is wrong.
    """
    return dir_name == PLUGIN_NAME or PLUGIN_NAME in text or "\\" in text


def classify_plugin_dir(directory, dir_name):
    """One of `copy`, `other`, `category`, `unknown` for a child directory."""
    selected = select_manifest(directory)
    if selected is None:
        return "category"
    kind, manifest_path = selected
    read = _read_bounded(manifest_path)
    # Unreadable is DECIDED, not unknown: Hermes' own read raises the same way
    # and it takes no manifest from the child.
    if read is None:
        return "other"
    text, truncated = read
    plausible = could_be_ours(dir_name, text)
    if kind == "portable":
        # `agent_plugins._validate_manifest` demands a regular file resolving
        # INSIDE the plugin root, known author fields and object extension
        # namespaces. Round 2 mirrored a fraction of that and called a backup
        # with a symlinked `plugin.json` the winner where Hermes rejects it, so
        # the fallback now declines to judge `plugin.json` at all (#569 r3).
        return "unknown" if plausible else "other"
    if truncated:
        return "unknown" if plausible else "other"
    name, understood = _understand_manifest(text)
    if not understood:
        return "unknown" if plausible else "other"
    # `data.get("name", plugin_dir.name)` — no name means the directory name.
    return "copy" if (name if name is not None else dir_name) == PLUGIN_NAME else "other"


def _fallback_root_scan(root):
    """`(copies, winner, unknown)` from the conservative reader.

    One unknown costs the root its winner (#569 r3): the copy Hermes loads may
    well be a directory this reader would not read, and it may sort after every
    copy it did read.
    """
    copies = []
    unknown = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return [], None, []
    for name in names:
        # Hermes skips dunder children and per-harness manifest dirs outright.
        if name.startswith("__") and name.endswith("__"):
            continue
        if name in _FOREIGN_HARNESS_MANIFEST_DIRS:
            continue
        directory = os.path.join(root, name)
        if not os.path.isdir(directory):
            continue
        verdict = classify_plugin_dir(directory, name)
        if verdict == "unknown":
            unknown.append(directory)
        elif verdict == "copy":
            copies.append(directory)
    winner = copies[-1] if copies and not unknown else None
    return copies, winner, unknown


def scan_plugin_root(root):
    """What is known about one `plugins/` root.

    A dict with `copies`, `winner`, `unknown`, `approximate` and `reason` —
    `reason` being why Hermes could not be asked, kept verbatim so the log line
    can print it.
    """
    copies, winner, reason = _hermes_root_scan(root)
    if copies is not None:
        return {"copies": copies, "winner": winner, "unknown": [],
                "approximate": False, "reason": None}
    copies, winner, unknown = _fallback_root_scan(root)
    return {"copies": copies, "winner": winner, "unknown": unknown,
            "approximate": True, "reason": reason}


def _root_is_too_big(root):
    """True when this root has more entries than the START-UP check will read.

    See `MAX_STARTUP_ROOT_ENTRIES`. Logged at DEBUG, because a skipped
    diagnostic is a fact about this run and not a problem with the host.
    """
    counted = 0
    try:
        with os.scandir(root) as entries:
            for _entry in entries:
                counted += 1
                if counted > MAX_STARTUP_ROOT_ENTRIES:
                    log.debug(
                        "[shieldcortex] plugin copy check skipped at start-up: %s holds more "
                        "than %d entries; run `shieldcortex doctor` for the full scan",
                        root, MAX_STARTUP_ROOT_ENTRIES,
                    )
                    return True
    except OSError:
        return False  # unreadable: let the scan report whatever it can
    return False


def _same_path(left, right):
    """Path identity WITHOUT resolving symlinks — see `_package_dir`."""
    return os.path.normpath(os.path.abspath(left)) == os.path.normpath(os.path.abspath(right))


def detect_shadow(package_dir):
    """Describe this copy's discovery situation, or None when it is clean.

    Clean means: the package directory is named `shieldcortex` (what the
    installer writes), no sibling directory takes the same manifest key, and
    nothing in the root was left undetermined. An undetermined root is NOT
    clean — round 2 appended a note and reported clean anyway (#569 r3).

    `package_dir` must be the path DISCOVERY used, not a resolved one. When
    Hermes loads `plugins/shieldcortex.bak-x -> /srv/sc-old`, the discovery path
    is the link, and it is the link that has to be recognised — a `realpath()`
    hands back `/srv/sc-old`, whose parent is not a `plugins/` root, and the
    whole diagnostic silently gives up on the one case it exists for.

    The returned dict has `loaded` (this copy's path), `expected` (the canonical
    path beside it), `misnamed`, `others` (copies Hermes passed over),
    `approximate` (true when Hermes' own discovery could not be reached),
    `reason` (why, verbatim), `unknown` (directories the fallback would not
    classify) and `undetermined`.
    """
    try:
        loaded = os.path.abspath(package_dir)
        own_name = os.path.basename(loaded)
        parent = os.path.dirname(loaded)
        expected = os.path.join(parent, PLUGIN_NAME)
        misnamed = own_name != PLUGIN_NAME

        report = {
            "loaded": loaded,
            "expected": expected,
            "misnamed": misnamed,
            "others": [],
            "approximate": False,
            "reason": None,
            "unknown": [],
            "undetermined": False,
        }

        if _root_is_too_big(parent):
            # The one thing still knowable for nothing is our own directory
            # name, and it is the strongest signal there is: whichever copy is
            # executing won discovery, so a non-canonical name IS the shadow.
            return report if misnamed else None

        found = scan_plugin_root(parent)
        others = sorted(c for c in found["copies"] if not _same_path(c, loaded))
        unknown = sorted(found["unknown"])
        report["others"] = others
        report["unknown"] = unknown
        report["undetermined"] = bool(unknown)
        report["approximate"] = found["approximate"]
        report["reason"] = found["reason"]

        if not misnamed and not others and not unknown:
            return None
        return report
    except Exception:  # pragma: no cover - defensive
        return None


def shadow_error_line(report):
    """One log line for a `detect_shadow` report, or None when clean."""
    if not report:
        return None
    try:
        definite = bool(report.get("misnamed")) or bool(report.get("others"))
        if definite:
            parts = ["[shieldcortex] plugin copy conflict: Hermes loaded this plugin from %s"
                     % report["loaded"]]
        else:
            # Nothing is wrong that we can point at — we simply could not work
            # out what Hermes loads, and saying "clean" would be the guess this
            # round exists to stop making.
            parts = ["[shieldcortex] could not determine which plugin copy Hermes loads; this "
                     "one was loaded from %s" % report["loaded"]]
        if report.get("misnamed"):
            parts.append("which is not the installed %s" % report["expected"])
        others = report.get("others") or []
        if others:
            parts.append("other directories declaring `name: %s` were passed over: %s"
                         % (PLUGIN_NAME, ", ".join(others)))
        unknown = report.get("unknown") or []
        if unknown:
            parts.append("and these hold a manifest this reader does not model, so whether "
                         "Hermes keys them `%s` is unknown: %s" % (PLUGIN_NAME, ", ".join(unknown)))
        if report.get("approximate"):
            parts.append("(approximate: Hermes' own discovery was not reachable — %s)"
                         % (report.get("reason") or "reason unrecorded"))
        parts.append(
            "Hermes keys plugins on the manifest name and the last directory in sorted order "
            "wins silently, so an upgrade can leave old code running. Run `shieldcortex doctor "
            "--fix-hermes-plugin-copies`, then restart the Hermes gateway"
        )
        return "; ".join(parts) + "."
    except Exception:  # pragma: no cover - defensive
        return None
