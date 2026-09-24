"""
#569 round 2 — the start-up detector must agree with Hermes about which
directory gets the `shieldcortex` key and which one wins it.

Round 1 mirrored the discovery rules in a line reader. An independent review of
the sibling Ekho fix found six shapes where a line reader and Hermes give
DIFFERENT answers — and a start-up diagnostic that is wrong is worse than none,
because it certifies the very state it exists to catch. Those six shapes are the
fixtures below.

Two halves run over the same trees:

  - the FALLBACK reader (`_fallback_root_scan`), always;
  - the PRIMARY path (`_hermes_root_scan`, which imports
    `hermes_cli.plugins_discovery` and calls the loader's own functions),
    whenever `hermes_cli` is importable. In the gateway it always is — that is
    the point of asking in-process — so the skip below only fires when these
    tests are run against a bare interpreter.

`expected` is not the fallback's opinion of itself: each value was recorded by
running Hermes' own `scan_directory` + `resolve_manifest_winners` over these
exact trees.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadow import (  # noqa: E402
    _fallback_root_scan,
    _hermes_root_scan,
    classify_plugin_dir,
    read_manifest_name,
    read_portable_manifest_name,
)

SCHEMA_V1 = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"

try:
    import hermes_cli.plugins_discovery  # noqa: F401

    HERMES_IMPORTABLE = True
except Exception:  # pragma: no cover - depends on the interpreter under test
    HERMES_IMPORTABLE = False


def _write(target, body):
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(body)


def _manifest(root, dir_name, body, filename="plugin.yaml"):
    _write(os.path.join(root, dir_name, filename), body)


def _case_comment(root):
    # Hermes parses YAML, so ` # backup` is a comment and the name is
    # `shieldcortex`. A reader that compares the whole rest of the line misses
    # the shadow and calls the host clean.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.bak-x", "name: shieldcortex # backup\n")


def _case_no_name(root):
    # `data.get("name", plugin_dir.name)`: no `name:` key means the DIRECTORY
    # name is the key.
    _manifest(root, "shieldcortex", "version: 1\n")
    _manifest(root, "zz-nameless", "version: 1\n")


def _case_quoted(root):
    _manifest(root, "shieldcortex", 'name: "shieldcortex"\n')
    _manifest(root, "shieldcortex.q", "name: 'shieldcortex'   # old\n")


def _case_portable(root):
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _write(os.path.join(root, "shieldcortex.portable", "plugin.json"),
           json.dumps({"$schema": SCHEMA_V1, "name": "shieldcortex", "version": "1.0.0"}))
    _write(os.path.join(root, "shieldcortex.badjson", "plugin.json"),
           json.dumps({"name": "shieldcortex"}))
    _write(os.path.join(root, "shieldcortex.notjson", "plugin.json"), "{not json")


def _case_dir_manifest(root):
    # Hermes selects on `Path.exists()`, hits the DIRECTORY, fails to parse, and
    # takes nothing from that child — it never looks at the `plugin.yml`.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    os.makedirs(os.path.join(root, "shieldcortex.dirmanifest", "plugin.yaml"), exist_ok=True)
    _manifest(root, "shieldcortex.dirmanifest", "name: shieldcortex\n", "plugin.yml")


def _case_broken_yaml(root):
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.broken", "name: shieldcortex\nkind: [unclosed\n")
    _manifest(root, "shieldcortex.broken2", "name: shieldcortex\n\tkind: standalone\n")
    _manifest(root, "shieldcortex.broken3", "name: shieldcortex\n:\n  not: [a manifest\n")


def _case_skips(root):
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "__pycache__", "name: shieldcortex\n")
    _manifest(root, ".claude-plugin", "name: shieldcortex\n")
    _manifest(os.path.join(root, "zz-category"), "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "zz-other", "name: ekho\n")
    _manifest(root, "shieldcortex.yml-spelling", "name: shieldcortex\n", "plugin.yml")


def _case_yaml_beats_json(root):
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.both", "name: something-else\n")
    _write(os.path.join(root, "shieldcortex.both", "plugin.json"),
           json.dumps({"$schema": SCHEMA_V1, "name": "shieldcortex"}))


def _case_empty(root):
    _manifest(root, "shieldcortex", "")
    _manifest(root, "zz-empty", "")


def _case_sequence(root):
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.list", "- name: shieldcortex\n")


def _case_none(root):
    _manifest(root, "kanban", "name: kanban\n")


#: (label, builder, copies, winner, unknown-to-the-fallback)
CASES = [
    ("an inline # comment after the name", _case_comment,
     ["shieldcortex", "shieldcortex.bak-x"], "shieldcortex.bak-x", []),
    ("a manifest with no name: at all", _case_no_name,
     ["shieldcortex"], "shieldcortex", []),
    ("quoted names, single and double", _case_quoted,
     ["shieldcortex", "shieldcortex.q"], "shieldcortex.q", []),
    ("a portable plugin.json manifest", _case_portable,
     ["shieldcortex", "shieldcortex.portable"], "shieldcortex.portable", []),
    ("a plugin.yaml directory beside a valid plugin.yml", _case_dir_manifest,
     ["shieldcortex"], "shieldcortex", []),
    ("invalid YAML after a valid name: line", _case_broken_yaml,
     ["shieldcortex"], "shieldcortex",
     ["shieldcortex.broken", "shieldcortex.broken2", "shieldcortex.broken3"]),
    ("dunder, foreign-harness, category, other name, plugin.yml", _case_skips,
     ["shieldcortex", "shieldcortex.yml-spelling"], "shieldcortex.yml-spelling", []),
    ("plugin.yaml takes precedence over plugin.json", _case_yaml_beats_json,
     ["shieldcortex"], "shieldcortex", []),
    ("an empty plugin.yaml", _case_empty, ["shieldcortex"], "shieldcortex", []),
    ("a top-level sequence document", _case_sequence,
     ["shieldcortex"], "shieldcortex", ["shieldcortex.list"]),
    ("no copy at all", _case_none, [], None, []),
]


class ParityFixtures(unittest.TestCase):
    """One `plugins/` root per case — a collision is per-root."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="sc-hermes-parity-")
        cls.roots = {}
        for index, (label, build, _copies, _winner, _unknown) in enumerate(CASES):
            root = os.path.join(cls._tmp, "case-%d" % index, "plugins")
            os.makedirs(root, exist_ok=True)
            build(root)
            cls.roots[label] = root

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)


class FallbackParityTests(ParityFixtures):
    def test_fallback_matches_the_recorded_hermes_answers(self):
        for label, _build, copies, winner, unknown in CASES:
            with self.subTest(label):
                root = self.roots[label]
                got_copies, got_winner, got_unknown = _fallback_root_scan(root)
                self.assertEqual([os.path.basename(c) for c in got_copies], copies)
                self.assertEqual(
                    os.path.basename(got_winner) if got_winner else None, winner)
                self.assertEqual([os.path.basename(u) for u in got_unknown], unknown)

    def test_manifest_readers_directly(self):
        root = self.roots["an inline # comment after the name"]
        self.assertEqual(
            read_manifest_name(os.path.join(root, "shieldcortex.bak-x", "plugin.yaml")),
            "shieldcortex")
        portable = self.roots["a portable plugin.json manifest"]
        self.assertEqual(
            read_portable_manifest_name(
                os.path.join(portable, "shieldcortex.portable", "plugin.json")),
            "shieldcortex")
        # No `$schema` is not an Agent Plugins v1 manifest, and Hermes raises on
        # it rather than keying the directory.
        self.assertIsNone(read_portable_manifest_name(
            os.path.join(portable, "shieldcortex.badjson", "plugin.json")))

    def test_an_unmodelled_manifest_is_unknown_not_guessed(self):
        root = self.roots["invalid YAML after a valid name: line"]
        self.assertEqual(
            classify_plugin_dir(os.path.join(root, "shieldcortex.broken"), "shieldcortex.broken"),
            "unknown")
        # …but only when it could be ours. A neighbour's broken manifest that
        # never mentions our key cannot take it however it parses.
        tmp = tempfile.mkdtemp(prefix="sc-hermes-unknown-")
        try:
            _manifest(tmp, "zz-other", "name: kanban\nkind: [unclosed\n")
            self.assertEqual(classify_plugin_dir(os.path.join(tmp, "zz-other"), "zz-other"),
                             "other")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_an_oversized_manifest_is_unknown_not_skipped(self):
        tmp = tempfile.mkdtemp(prefix="sc-hermes-big-")
        try:
            body = "name: shieldcortex\n" + ("# filler\n" * 12000)
            _manifest(tmp, "shieldcortex.big", body)
            self.assertGreater(
                os.path.getsize(os.path.join(tmp, "shieldcortex.big", "plugin.yaml")),
                64 * 1024)
            # Hermes would read the whole file, so "not ours" would be a claim
            # this reader cannot back.
            self.assertEqual(
                classify_plugin_dir(os.path.join(tmp, "shieldcortex.big"), "shieldcortex.big"),
                "unknown")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipUnless(HERMES_IMPORTABLE,
                     "hermes_cli is not importable by this interpreter; the plugin only runs "
                     "inside Hermes, where it always is")
class HermesPrimaryTests(ParityFixtures):
    def test_hermes_reports_the_recorded_copies_and_winner(self):
        for label, _build, copies, winner, _unknown in CASES:
            with self.subTest(label):
                result = _hermes_root_scan(self.roots[label])
                self.assertIsNotNone(result, "hermes_cli import or scan failed")
                got_copies, got_winner = result
                self.assertEqual([os.path.basename(c) for c in got_copies], copies)
                self.assertEqual(
                    os.path.basename(got_winner) if got_winner else None, winner)

    def test_the_fallback_agrees_with_hermes_on_every_tree(self):
        disagreements = []
        for label, _build, _copies, _winner, _unknown in CASES:
            root = self.roots[label]
            primary = _hermes_root_scan(root)
            self.assertIsNotNone(primary)
            fallback_copies, fallback_winner, _unknown_dirs = _fallback_root_scan(root)
            got = ([os.path.basename(c) for c in primary[0]],
                   os.path.basename(primary[1]) if primary[1] else None)
            mine = ([os.path.basename(c) for c in fallback_copies],
                    os.path.basename(fallback_winner) if fallback_winner else None)
            if got != mine:
                disagreements.append("%s: hermes=%r fallback=%r" % (label, got, mine))
        self.assertEqual(disagreements, [])

    def test_hermes_never_reports_an_unknown_directory(self):
        # The three broken manifests the fallback calls `unknown` are, to
        # Hermes, simply not copies.
        result = _hermes_root_scan(self.roots["invalid YAML after a valid name: line"])
        self.assertIsNotNone(result)
        self.assertEqual(len(result[0]), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
