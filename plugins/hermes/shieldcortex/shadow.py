"""
ShieldCortex — Hermes plugin shadowing detector (#569).

Hermes discovers plugins by walking every child directory of
`$HERMES_HOME/plugins/`, keying each one on the `name:` in its
`plugin.yaml` / `plugin.yml` rather than on the folder name. It walks in
sorted order and, on a same-source key collision, the LATER manifest silently
replaces the earlier one (NousResearch/hermes-agent#121078).

So a backup left beside the live plugin — `plugins/shieldcortex.bak-pre510-<ts>/`,
the natural thing to make before an upgrade — sorts after `plugins/shieldcortex/`
and is what Hermes loads. The upgrade lands on disk and the gateway keeps
running the old code, with nothing in the log to say so.

This module is the plugin's own half of the answer: whichever copy is running
is by definition the one that won discovery, so at `register()` time it can say
out loud where it was loaded from and which other copies were passed over.

Stdlib only, and every entry point swallows its own errors: a start-up
diagnostic must never be able to stop the gate from registering.
"""
import os

#: The manifest key this plugin declares — the thing that can collide.
PLUGIN_NAME = "shieldcortex"

#: Manifests are a few hundred bytes; the cap keeps a corrupt or hostile
#: `plugin.yaml` from being read into memory in full.
MANIFEST_BYTE_CAP = 256 * 1024

_MANIFEST_NAMES = ("plugin.yaml", "plugin.yml")


def _plain_scalar(value):
    """A plain YAML scalar: quotes off, trailing `# comment` off, trimmed.

    Anything that is not a plain scalar (a block scalar, an empty value) comes
    back None — the conservative direction, since a manifest we cannot read is
    one we must not claim to have identified.
    """
    text = value.strip()
    if not text or text.startswith("#"):
        return None
    # Quoted first, and up to the CLOSING quote: a trailing `# comment` after
    # the closing quote must not stop the value being recognised as quoted,
    # and a `#` inside the quotes is part of the value.
    if text[0] in ("'", '"'):
        close = text.find(text[0], 1)
        if close == -1:
            return None
        inner = text[1:close].strip()
        return inner or None
    head = text.split(" #", 1)[0].split("\t#", 1)[0].strip()
    return head or None


def read_manifest_name(manifest_path):
    """The `name:` a plugin manifest declares, read line by line.

    Only a top-level key counts: an indented `name:` belongs to a nested block
    and is not the plugin key. Returns None for an unreadable, oversized or
    malformed file.
    """
    try:
        if os.path.getsize(manifest_path) > MANIFEST_BYTE_CAP:
            return None
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except (OSError, ValueError):
        return None
    for line in lines:
        if line[:1].isspace():
            continue
        if not line.startswith("name"):
            continue
        rest = line[len("name"):].lstrip()
        if not rest.startswith(":"):
            continue
        return _plain_scalar(rest[1:])
    return None


def _manifest_path(directory):
    """The manifest inside `directory`, or None when it holds neither."""
    for base in _MANIFEST_NAMES:
        candidate = os.path.join(directory, base)
        if os.path.isfile(candidate):
            return candidate
    return None


def detect_shadow(package_dir):
    """Describe this copy's discovery situation, or None when it is clean.

    Clean means: the package directory is named `shieldcortex` (what the
    installer writes) and no sibling directory declares the same manifest name.

    The returned dict has `loaded` (this copy's absolute path), `expected`
    (the canonical path beside it), `misnamed` (whether we are running from
    somewhere other than `expected`) and `others` (sibling copies, sorted,
    that Hermes passed over).
    """
    try:
        loaded = os.path.abspath(package_dir)
        own_name = os.path.basename(loaded)
        parent = os.path.dirname(loaded)
        expected = os.path.join(parent, PLUGIN_NAME)

        others = []
        try:
            names = sorted(os.listdir(parent))
        except OSError:
            names = []
        for name in names:
            if name == own_name:
                continue
            # Hermes skips dunder children outright.
            if name.startswith("__") and name.endswith("__"):
                continue
            sibling = os.path.join(parent, name)
            if not os.path.isdir(sibling):
                continue
            manifest = _manifest_path(sibling)
            # No manifest → a category directory, keyed `<cat>/<name>`. It can
            # never collide with a flat plugin name, so it cannot shadow us.
            if manifest is None:
                continue
            if read_manifest_name(manifest) == PLUGIN_NAME:
                others.append(sibling)

        misnamed = own_name != PLUGIN_NAME
        if not misnamed and not others:
            return None
        return {"loaded": loaded, "expected": expected, "misnamed": misnamed, "others": others}
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
        parts.append(
            "Hermes keys plugins on the manifest name and the last directory in sorted order "
            "wins silently, so an upgrade can leave old code running. Run `shieldcortex doctor "
            "--fix-hermes-plugin-copies`, then restart the Hermes gateway"
        )
        return "; ".join(parts) + "."
    except Exception:  # pragma: no cover - defensive
        return None
