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
disagree (`name: x # comment`, a manifest with no `name:`, quoted names, a
portable `plugin.json`, a `plugin.yaml` DIRECTORY beside a valid `plugin.yml`,
and broken YAML under a valid `name:` line).

`_fallback_root_scan` is what runs if that import ever fails — a stripped
environment, a partially installed Hermes. It is conservative: a manifest whose
shape it does not model is reported `unknown` rather than guessed, and anything
it produces is flagged `approximate` so the error line says so.

Stdlib only, and every entry point swallows its own errors: a start-up
diagnostic must never be able to stop the gate from registering.
"""
import json
import logging
import os
import re

#: The manifest key this plugin declares — the thing that can collide.
PLUGIN_NAME = "shieldcortex"

#: Manifests are a few hundred bytes. Hermes reads them whole; the fallback
#: stops here because an unbounded read in a start-up path is a hazard the last
#: scrap of parity is not worth. Over the cap is reported `unknown`, never
#: "not ours" — Hermes would have read it.
MANIFEST_BYTE_CAP = 64 * 1024

#: `hermes_cli.agent_plugins.PLUGIN_SCHEMA_V1`.
PLUGIN_SCHEMA_V1 = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"

#: `hermes_cli.agent_plugins._PLUGIN_NAME_RE`, verbatim.
_PORTABLE_NAME_RE = re.compile(r"^(?!.*(?:--|\.\.))[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$")

#: `hermes_cli.plugins_discovery._FOREIGN_HARNESS_MANIFEST_DIRS`.
_FOREIGN_HARNESS_MANIFEST_DIRS = frozenset({
    ".claude-plugin", ".codex-plugin", ".cursor-plugin", ".devin-plugin", ".kimi-plugin",
})

_MANIFEST_NAMES = ("plugin.yaml", "plugin.yml")


# ── Primary: ask Hermes ───────────────────────────────────────────────────

def _hermes_root_scan(root):
    """`(copies, winner)` from Hermes' own discovery, or None when unavailable.

    `copies` are the directories Hermes keys `shieldcortex`, in discovery order;
    `winner` is the one it loads. The discovery logger is silenced for the call:
    a diagnostic pass must not put warnings in the gateway log about manifests
    the loader has already complained about.
    """
    try:
        from pathlib import Path

        from hermes_cli.plugins_discovery import resolve_manifest_winners, scan_directory
        from hermes_cli.plugins_manifest import manifest_key
    except Exception:
        return None
    logger = logging.getLogger("hermes_cli.plugins")
    was_disabled = logger.disabled
    try:
        logger.disabled = True
        manifests = scan_directory(Path(root), "user")
        copies = [str(m.path) for m in manifests if manifest_key(m) == PLUGIN_NAME]
        winner = resolve_manifest_winners(manifests).get(PLUGIN_NAME)
    except Exception:
        return None
    finally:
        logger.disabled = was_disabled
    return copies, (str(winner.path) if winner is not None else None)


# ── Fallback: the conservative reader ─────────────────────────────────────

def _read_bounded(manifest_path):
    """`(text, truncated)` for a manifest, or None when it cannot be read."""
    try:
        with open(manifest_path, "rb") as fh:
            raw = fh.read(MANIFEST_BYTE_CAP + 1)
    except (OSError, ValueError):
        # A `plugin.yaml` DIRECTORY, a permission denial, an I/O error: Hermes'
        # own `read_text` raises here too and takes no manifest from the child.
        return None
    if len(raw) > MANIFEST_BYTE_CAP:
        return raw[:MANIFEST_BYTE_CAP].decode("utf-8", "replace"), True
    return raw.decode("utf-8", "replace"), False


def _key_colon(line):
    """Index of the `:` that ends a block-mapping key, or -1."""
    quote = ""
    for index, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == ":":
            nxt = line[index + 1:index + 2]
            if nxt in ("", " ", "\t"):
                return index
    return -1


def _comment_start(text):
    """Index of the ` #` that starts a trailing comment, or -1."""
    for index, ch in enumerate(text):
        if ch != "#":
            continue
        if index == 0 or text[index - 1] in (" ", "\t"):
            return index
    return -1


def _flow_delta(line):
    """Net `[`/`{` minus `]`/`}`, ignoring quoted text and comments."""
    depth = 0
    quote = ""
    for index, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
            continue
        if ch in ("'", '"'):
            quote = ch
            continue
        if ch == "#" and (index == 0 or line[index - 1] in (" ", "\t")):
            break
        if ch in ("[", "{"):
            depth += 1
        elif ch in ("]", "}"):
            depth -= 1
    return depth


def _plain_scalar(raw):
    """`(value, modelled)` for a YAML scalar written on one line.

    Quotes are honoured, a ` #` comment is stripped, whitespace trimmed. Shapes
    that put the value somewhere other than this line — an empty value, a block
    scalar, an anchor, an alias, a tag — come back unmodelled, because guessing
    at them is exactly how round 1 disagreed with Hermes.
    """
    text = raw.strip()
    if not text or text.startswith("#"):
        return None, False
    lead = text[0]
    # A collection is not a string, so it can never equal our key. That is a
    # decision, not a gap.
    if lead in ("[", "{"):
        return None, True
    if lead in ("|", ">", "&", "*", "!"):
        return None, False
    if lead in ("'", '"'):
        close = text.find(lead, 1)
        if close == -1:
            return None, False
        inner = text[1:close]
        # Escapes (`''` in single quotes, `\"` in double) are not unescaped here.
        if lead == '"' and "\\" in inner:
            return None, False
        if lead == "'" and text[close + 1:close + 2] == "'":
            return None, False
        after = text[close + 1:].strip()
        if after and not after.startswith("#"):
            return None, False
        return inner, True
    cut = _comment_start(text)
    head = (text if cut == -1 else text[:cut]).strip()
    return (head, True) if head else (None, False)


def read_yaml_manifest_name(text):
    """`(name, modelled)` for a manifest body.

    Models a flat block mapping of `key: value` lines, which is every real
    `plugin.yaml`. A sequence document, a second document, tab indentation, an
    unterminated flow collection, a top-level line that is not a key: all report
    unmodelled, so the caller says "unknown" instead of accepting a manifest
    Hermes rejects.
    """
    name = None
    saw_key = False
    saw_content = False
    doc_started = False
    ended = False
    flow = 0

    for line in text.splitlines():
        if flow > 0:
            flow += _flow_delta(line)
            if flow < 0:
                return None, False
            continue
        if not line.strip():
            continue
        # A tab in the indentation is invalid YAML; libyaml rejects the whole
        # document, so Hermes takes no manifest from it.
        if re.match(r"^ *\t", line):
            return None, False
        if ended:
            return None, False
        if line[:1].isspace():
            flow += _flow_delta(line)
            if flow < 0:
                return None, False
            continue
        if line.startswith("#") or line.startswith("%"):
            continue
        if line == "---" or line.startswith("--- "):
            if doc_started or saw_content:
                return None, False
            doc_started = True
            continue
        if line == "..." or line.startswith("... "):
            ended = True
            continue
        if line == "-" or line.startswith("- "):
            # A sequence item before any key means the document is a list, and
            # `parse_manifest_file` rejects a non-mapping top level outright.
            if not saw_key:
                return None, False
            saw_content = True
            flow += _flow_delta(line)
            if flow < 0:
                return None, False
            continue
        colon = _key_colon(line)
        if colon == -1:
            return None, False
        raw_key = line[:colon].strip()
        if not raw_key:
            return None, False
        if len(raw_key) > 1 and raw_key[0] == raw_key[-1] and raw_key[0] in ("'", '"'):
            key = raw_key[1:-1]
        else:
            key = raw_key
        saw_key = True
        saw_content = True
        rest = line[colon + 1:]
        if key == "name" and name is None:
            value, modelled = _plain_scalar(rest)
            if not modelled:
                return None, False
            name = value
        stripped = rest.strip()
        if stripped.startswith("[") or stripped.startswith("{"):
            flow += _flow_delta(rest)
            if flow < 0:
                return None, False
    if flow != 0:
        return None, False
    return name, True


def read_manifest_name(manifest_path):
    """The top-level `name:` a manifest declares, or None.

    None covers both "there is no such key" and "this reader does not model the
    document". Callers that must tell those apart use `classify_plugin_dir`.
    """
    read = _read_bounded(manifest_path)
    if read is None or read[1]:
        return None
    name, modelled = read_yaml_manifest_name(read[0])
    return name if modelled else None


def read_portable_manifest_name(manifest_path):
    """The `name` a portable `plugin.json` declares, after Hermes' v1 gate."""
    read = _read_bounded(manifest_path)
    if read is None or read[1]:
        return None
    try:
        data = json.loads(read[0])
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("$schema") != PLUGIN_SCHEMA_V1:
        return None
    name = data.get("name")
    if not isinstance(name, str) or not 1 <= len(name) <= 64:
        return None
    if _PORTABLE_NAME_RE.fullmatch(name) is None:
        return None
    return name


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


def classify_plugin_dir(directory, dir_name):
    """One of `copy`, `other`, `category`, `unknown` for a child directory."""
    selected = select_manifest(directory)
    if selected is None:
        return "category"
    kind, manifest_path = selected
    if kind == "portable":
        return "copy" if read_portable_manifest_name(manifest_path) == PLUGIN_NAME else "other"
    read = _read_bounded(manifest_path)
    if read is None:
        return "other"
    text, truncated = read
    # `unknown` is reserved for manifests that could still be ours; a
    # neighbour's broken manifest that never mentions us cannot take our key
    # however it parses.
    plausible = dir_name == PLUGIN_NAME or PLUGIN_NAME in text
    if truncated:
        return "unknown" if plausible else "other"
    name, modelled = read_yaml_manifest_name(text)
    if not modelled:
        return "unknown" if plausible else "other"
    # `data.get("name", plugin_dir.name)` — no name means the directory name.
    return "copy" if (name if name is not None else dir_name) == PLUGIN_NAME else "other"


def _fallback_root_scan(root):
    """`(copies, winner, unknown)` from the conservative reader."""
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
    return copies, (copies[-1] if copies else None), unknown


def scan_plugin_root(root):
    """`(copies, winner, unknown, approximate)` for one `plugins/` root."""
    primary = _hermes_root_scan(root)
    if primary is not None:
        return primary[0], primary[1], [], False
    copies, winner, unknown = _fallback_root_scan(root)
    return copies, winner, unknown, True


def _same_path(left, right):
    """Path identity WITHOUT resolving symlinks — see `_package_dir`."""
    return os.path.normpath(os.path.abspath(left)) == os.path.normpath(os.path.abspath(right))


def detect_shadow(package_dir):
    """Describe this copy's discovery situation, or None when it is clean.

    Clean means: the package directory is named `shieldcortex` (what the
    installer writes) and no sibling directory takes the same manifest key.

    `package_dir` must be the path DISCOVERY used, not a resolved one. When
    Hermes loads `plugins/shieldcortex.bak-x -> /srv/sc-old`, the discovery path
    is the link, and it is the link that has to be recognised — a `realpath()`
    hands back `/srv/sc-old`, whose parent is not a `plugins/` root, and the
    whole diagnostic silently gives up on the one case it exists for.

    The returned dict has `loaded` (this copy's path), `expected` (the canonical
    path beside it), `misnamed`, `others` (copies Hermes passed over),
    `approximate` (true when Hermes' own discovery could not be reached) and
    `unknown` (directories the fallback would not classify).
    """
    try:
        loaded = os.path.abspath(package_dir)
        own_name = os.path.basename(loaded)
        parent = os.path.dirname(loaded)
        expected = os.path.join(parent, PLUGIN_NAME)

        copies, _winner, unknown, approximate = scan_plugin_root(parent)
        others = sorted(c for c in copies if not _same_path(c, loaded))

        misnamed = own_name != PLUGIN_NAME
        if not misnamed and not others:
            return None
        return {
            "loaded": loaded,
            "expected": expected,
            "misnamed": misnamed,
            "others": others,
            "approximate": approximate,
            "unknown": sorted(unknown),
        }
    except Exception:  # pragma: no cover - defensive
        return None


def shadow_error_line(report):
    """One ERROR line for a `detect_shadow` report, or None when clean."""
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
        unknown = report.get("unknown") or []
        if unknown:
            parts.append("and these could not be classified without Hermes' own discovery: %s"
                         % ", ".join(unknown))
        if report.get("approximate"):
            parts.append("(approximate: hermes_cli discovery was not importable, so this is a "
                         "conservative read)")
        parts.append(
            "Hermes keys plugins on the manifest name and the last directory in sorted order "
            "wins silently, so an upgrade can leave old code running. Run `shieldcortex doctor "
            "--fix-hermes-plugin-copies`, then restart the Hermes gateway"
        )
        return "; ".join(parts) + "."
    except Exception:  # pragma: no cover - defensive
        return None
