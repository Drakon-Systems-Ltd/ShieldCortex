"""
#569 — the start-up detector must never disagree with Hermes about which
directory gets the `shieldcortex` key and which one wins it.

Round 1 mirrored the discovery rules in a line reader. Round 2 asked Hermes on
the primary path but kept a guessing reader for the fallback, and independent
review of the sibling Ekho change found the guesses wrong in BOTH directions:
a block-scalar `name:` made it report a clean install while Hermes was loading
the backup, and an invalid `description: backup: x` under a valid `name:` line
made it label a backup LOADED that Hermes rejects.

So round 3 narrowed the fallback to "understood, or unknown", and the contract
these tests pin is a differential one:

    for every fixture tree, the fallback gives the SAME answer as Hermes, or it
    says unknown. Never a confident disagreement.

Two halves run over the same trees:

  - the FALLBACK reader (`_fallback_root_scan`), always;
  - the PRIMARY path (`_hermes_root_scan`, which imports
    `hermes_cli.plugins_discovery` and calls the loader's own functions),
    whenever `hermes_cli` is importable. In the gateway it always is — that is
    the point of asking in-process — so the skip below only fires when these
    tests are run against a bare interpreter.

Every `hermes_*` expectation below was recorded by running Hermes' own
`scan_directory` + `resolve_manifest_winners` over these exact trees, so the
fallback-only half is still pinned to Hermes' behaviour on a box with none.
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
    _understand_manifest,
    classify_plugin_dir,
    could_be_ours,
    read_manifest_name,
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


# ── The four round-3 differential fixtures ────────────────────────────────

def _case_block_scalar(root):
    # THE round-2 blocker. Hermes reads the folded scalar and gets
    # `shieldcortex`, so it LOADS the backup. Round 2 saw a shape it did not
    # model, decided the name was absent, keyed the dir on its own name, and
    # reported a clean canonical install.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.bak-x", "name: >-\n  shieldcortex\n")


def _case_value_colon(root):
    # The same blocker in the other direction. `description: backup: before
    # upgrade` is not YAML — Hermes raises and drops the manifest. Round 2 only
    # ever inspected the `name:` line, so it labelled this backup LOADED.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.bak-y",
              "name: shieldcortex\ndescription: backup: before upgrade\n")


def _case_linked_portable(root):
    # `agent_plugins._validate_manifest` requires plugin.json to resolve INSIDE
    # the plugin root, so Hermes rejects this one. Round 2 followed the link and
    # called the directory the winner.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    outside = os.path.join(os.path.dirname(root), "outside")
    _write(os.path.join(outside, "plugin.json"),
           json.dumps({"$schema": SCHEMA_V1, "name": "shieldcortex", "version": "1.0.0"}))
    linked = os.path.join(root, "shieldcortex.linked")
    os.makedirs(linked, exist_ok=True)
    os.symlink(os.path.join(outside, "plugin.json"), os.path.join(linked, "plugin.json"))


def _case_portable_author(root):
    # `author` may hold only name/email/url. An unknown field raises, so Hermes
    # takes nothing from this directory.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _write(os.path.join(root, "shieldcortex.authored", "plugin.json"),
           json.dumps({"$schema": SCHEMA_V1, "name": "shieldcortex", "version": "1.0.0",
                       "author": {"name": "a", "twitter": "b"}}))


#: (label, builder, hermes copies, hermes winner, fallback copies,
#:  fallback winner, fallback unknown)
CASES = [
    ("an inline # comment after the name", _case_comment,
     ["shieldcortex", "shieldcortex.bak-x"], "shieldcortex.bak-x",
     ["shieldcortex", "shieldcortex.bak-x"], "shieldcortex.bak-x", []),
    ("a manifest with no name: at all", _case_no_name,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], "shieldcortex", []),
    ("quoted names, single and double", _case_quoted,
     ["shieldcortex", "shieldcortex.q"], "shieldcortex.q",
     ["shieldcortex", "shieldcortex.q"], "shieldcortex.q", []),
    # The fallback no longer judges plugin.json at all, so the portable copy
    # Hermes loads comes back unknown and the root loses its winner.
    ("a portable plugin.json manifest", _case_portable,
     ["shieldcortex", "shieldcortex.portable"], "shieldcortex.portable",
     ["shieldcortex"], None, ["shieldcortex.badjson", "shieldcortex.portable"]),
    ("a plugin.yaml directory beside a valid plugin.yml", _case_dir_manifest,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], "shieldcortex", []),
    ("invalid YAML after a valid name: line", _case_broken_yaml,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], None,
     ["shieldcortex.broken", "shieldcortex.broken2", "shieldcortex.broken3"]),
    ("dunder, foreign-harness, category, other name, plugin.yml", _case_skips,
     ["shieldcortex", "shieldcortex.yml-spelling"], "shieldcortex.yml-spelling",
     ["shieldcortex", "shieldcortex.yml-spelling"], "shieldcortex.yml-spelling", []),
    ("plugin.yaml takes precedence over plugin.json", _case_yaml_beats_json,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], "shieldcortex", []),
    ("an empty plugin.yaml", _case_empty,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], "shieldcortex", []),
    ("a top-level sequence document", _case_sequence,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], None, ["shieldcortex.list"]),
    ("no copy at all", _case_none, [], None, [], None, []),
    ("a block-scalar name Hermes reads and loads", _case_block_scalar,
     ["shieldcortex", "shieldcortex.bak-x"], "shieldcortex.bak-x",
     ["shieldcortex"], None, ["shieldcortex.bak-x"]),
    ("invalid YAML from a colon in a later value", _case_value_colon,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], None, ["shieldcortex.bak-y"]),
    ("a plugin.json symlinked outside the plugin root", _case_linked_portable,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], None, ["shieldcortex.linked"]),
    ("a plugin.json with an unknown author field", _case_portable_author,
     ["shieldcortex"], "shieldcortex", ["shieldcortex"], None, ["shieldcortex.authored"]),
]


class ParityFixtures(unittest.TestCase):
    """One `plugins/` root per case — a collision is per-root."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="sc-hermes-parity-")
        cls.roots = {}
        for index, case in enumerate(CASES):
            label, build = case[0], case[1]
            root = os.path.join(cls._tmp, "case-%d" % index, "plugins")
            os.makedirs(root, exist_ok=True)
            build(root)
            cls.roots[label] = root

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._tmp, ignore_errors=True)


class FallbackParityTests(ParityFixtures):
    def test_fallback_matches_the_recorded_answers(self):
        for case in CASES:
            label, copies, winner, unknown = case[0], case[4], case[5], case[6]
            with self.subTest(label):
                got_copies, got_winner, got_unknown = _fallback_root_scan(self.roots[label])
                self.assertEqual([os.path.basename(c) for c in got_copies], copies)
                self.assertEqual(
                    os.path.basename(got_winner) if got_winner else None, winner)
                self.assertEqual([os.path.basename(u) for u in got_unknown], unknown)

    def test_one_unknown_costs_the_root_its_winner(self):
        # The point of the rule: the directory we could not read may well be a
        # copy, and it may sort after every copy we did read. Naming a winner
        # anyway is the guess that made round 2 certify a shadowed host.
        for label in ("a block-scalar name Hermes reads and loads",
                      "invalid YAML from a colon in a later value",
                      "a plugin.json symlinked outside the plugin root",
                      "a plugin.json with an unknown author field"):
            with self.subTest(label):
                copies, winner, unknown = _fallback_root_scan(self.roots[label])
                self.assertNotEqual(unknown, [])
                self.assertIsNone(winner)
                self.assertEqual([os.path.basename(c) for c in copies], ["shieldcortex"])

    def test_manifest_reader_directly(self):
        root = self.roots["an inline # comment after the name"]
        self.assertEqual(
            read_manifest_name(os.path.join(root, "shieldcortex.bak-x", "plugin.yaml")),
            "shieldcortex")
        # A block scalar is not a name this reader can read, so it reports none
        # rather than the directory-name fallback.
        block = self.roots["a block-scalar name Hermes reads and loads"]
        self.assertIsNone(
            read_manifest_name(os.path.join(block, "shieldcortex.bak-x", "plugin.yaml")))

    def test_the_understood_rule_line_by_line(self):
        understood = [
            "name: shieldcortex\n",
            "name: shieldcortex # backup\n",
            'name: "shieldcortex"\n',
            "version: 1\nname: shieldcortex\nkind: standalone\n",
            "# only a comment\n",
            "",
            "meta:\n  inner: value\n  - item\nname: shieldcortex\n",
        ]
        for body in understood:
            with self.subTest(body=body):
                self.assertTrue(_understand_manifest(body)[1], body)
        not_understood = [
            "name: >-\n  shieldcortex\n",          # block scalar
            "name: |\n  shieldcortex\n",           # literal block scalar
            "name:\n  first: x\n",                 # null name, nested under it
            "name: [shieldcortex]\n",              # flow collection
            "name: &anchor shieldcortex\n",        # anchor
            "name: *alias\n",                      # alias
            "name: !!str shieldcortex\n",          # tag
            "---\nname: shieldcortex\n",           # document marker
            "name: shieldcortex\n...\n",           # end-of-document marker
            "name: shieldcortex\n\tkind: x\n",     # tab
            "name: shieldcortex\ndescription: backup: x\n",   # unquoted `: `
            "- name: shieldcortex\n",              # sequence document
            "name: 'unterminated\n",               # unterminated quote
            "  name: shieldcortex\n",              # nothing at column 0
            "name: shieldcortex\ndeps: [a, b]\n",  # a flow collection anywhere
        ]
        for body in not_understood:
            with self.subTest(body=body):
                self.assertFalse(_understand_manifest(body)[1], body)

    def test_unknown_is_reserved_for_manifests_that_could_be_ours(self):
        # A neighbour's block scalar must not put a permanent "cannot
        # determine" on a host where nothing is wrong.
        tmp = tempfile.mkdtemp(prefix="sc-hermes-unknown-")
        try:
            _manifest(tmp, "zz-other", "name: kanban\ndescription: >-\n  a plugin\n")
            self.assertEqual(classify_plugin_dir(os.path.join(tmp, "zz-other"), "zz-other"),
                             "other")
            # …but the same shape in a directory that could take our key is.
            _manifest(tmp, "zz-maybe", "name: shieldcortex\nkind: [unclosed\n")
            self.assertEqual(classify_plugin_dir(os.path.join(tmp, "zz-maybe"), "zz-maybe"),
                             "unknown")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_could_be_ours_covers_the_three_ways_our_key_can_appear(self):
        self.assertTrue(could_be_ours("shieldcortex", "name: anything\n"))
        self.assertTrue(could_be_ours("other", "name: shieldcortex\n"))
        # A double-quoted escape is the only way to spell the name without the
        # literal bytes, and a backslash is the only way to write one.
        self.assertTrue(could_be_ours("other", 'name: "shieldcorte\\x78"\n'))
        self.assertFalse(could_be_ours("other", "name: kanban\n"))

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
        for case in CASES:
            label, copies, winner = case[0], case[2], case[3]
            with self.subTest(label):
                got_copies, got_winner, reason = _hermes_root_scan(self.roots[label])
                self.assertIsNone(reason, reason)
                self.assertIsNotNone(got_copies)
                self.assertEqual([os.path.basename(c) for c in got_copies], copies)
                self.assertEqual(
                    os.path.basename(got_winner) if got_winner else None, winner)

    def test_the_fallback_never_disagrees_confidently_with_hermes(self):
        """The round-3 contract: same answer, or unknown. Never a third thing."""
        disagreements = []
        for case in CASES:
            label = case[0]
            root = self.roots[label]
            hermes_copies, hermes_winner, reason = _hermes_root_scan(root)
            self.assertIsNone(reason, reason)
            fallback_copies, fallback_winner, unknown = _fallback_root_scan(root)
            hermes_names = [os.path.basename(c) for c in hermes_copies]
            mine = [os.path.basename(c) for c in fallback_copies]
            unknown_names = [os.path.basename(u) for u in unknown]

            # Every copy the fallback NAMES is one Hermes names too: a
            # confident positive is never invented.
            for name in mine:
                if name not in hermes_names:
                    disagreements.append("%s: fallback invented the copy %s" % (label, name))
            # Every copy it MISSES it has flagged unknown: a confident negative
            # is never a real shadow swept under the carpet.
            for name in hermes_names:
                if name not in mine and name not in unknown_names:
                    disagreements.append("%s: fallback silently dropped %s" % (label, name))
            # And the winner is either Hermes' winner or no winner at all.
            mine_winner = os.path.basename(fallback_winner) if fallback_winner else None
            theirs = os.path.basename(hermes_winner) if hermes_winner else None
            if mine_winner is not None and mine_winner != theirs:
                disagreements.append(
                    "%s: fallback named %s, Hermes loads %s" % (label, mine_winner, theirs))
            if mine_winner is None and theirs is not None and not unknown_names:
                disagreements.append(
                    "%s: fallback named no winner and no unknowns, Hermes loads %s"
                    % (label, theirs))
        self.assertEqual(disagreements, [])

    def test_hermes_never_reports_an_unknown_directory(self):
        # The directories the fallback calls `unknown` are, to Hermes, simply
        # copies or not copies — it always has an answer.
        copies, _winner, reason = _hermes_root_scan(
            self.roots["invalid YAML after a valid name: line"])
        self.assertIsNone(reason)
        self.assertEqual(len(copies), 1)


class FallbackReasonTests(unittest.TestCase):
    """Nit 4: keep the REAL reason, not "hermes_cli not importable" for all."""

    def test_an_import_failure_says_so(self):
        if HERMES_IMPORTABLE:
            self.skipTest("hermes_cli imports fine here; the import branch needs a blocked one")
        copies, winner, reason = _hermes_root_scan(tempfile.gettempdir())
        self.assertIsNone(copies)
        self.assertIsNone(winner)
        self.assertIn("not importable", reason)
        self.assertIn("ModuleNotFoundError", reason)

    @unittest.skipUnless(HERMES_IMPORTABLE, "needs a real hermes_cli to make raise")
    def test_a_discovery_failure_is_not_reported_as_an_import_failure(self):
        import hermes_cli.plugins_discovery as discovery
        from unittest import mock

        with mock.patch.object(discovery, "scan_directory",
                               side_effect=RuntimeError("boom")):
            copies, winner, reason = _hermes_root_scan(tempfile.gettempdir())
        self.assertIsNone(copies)
        self.assertIsNone(winner)
        self.assertNotIn("not importable", reason)
        self.assertIn("discovery raised RuntimeError", reason)
        self.assertIn("boom", reason)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
