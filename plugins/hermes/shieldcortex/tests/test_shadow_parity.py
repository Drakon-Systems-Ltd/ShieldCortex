"""
#569 — the start-up detector must never disagree with Hermes about which
directory gets the `shieldcortex` key and which one wins it.

Round 1 mirrored the discovery rules in a line reader. Round 2 asked Hermes on
the primary path but kept a guessing reader for the case where the import
fails. Round 3 narrowed that reader to a grammar it was supposed to be certain
about. Independent review of the sibling Ekho change found a confident wrong
answer in EVERY version:

  - `name: >-` with an indented name (reported clean while Hermes loaded the
    backup);
  - `description: backup: before upgrade` (labelled LOADED where Hermes rejects
    the manifest);
  - `name: "shieldcorte\\u0078"` (the escape left undecoded, so the copy Hermes
    loads was missed);
  - `description: 2026-99-99` (YAML reads an invalid timestamp, construction
    fails, Hermes drops the manifest);
  - `manifest_version: .inf` (YAML builds infinity and Hermes' `int()`
    conversion raises OverflowError).

The last two are ordinary-looking lines: the disagreement lives in YAML's
implicit typing and Hermes' own conversion code, not in exotic syntax. So round
4 removed the reader, and the contract these tests pin is:

    Hermes' own discovery answers, or NOTHING answers. Where it cannot be
    reached this module logs one DEBUG line and produces no verdict at all.

Two halves run over the same trees:

  - the PRIMARY path (`_hermes_root_scan`, which imports
    `hermes_cli.plugins_discovery` and calls the loader's own functions).
    In the gateway it is always available — that is the point of asking
    in-process — so the skip below only fires when these tests are run against
    a bare interpreter;
  - the NO-HERMES path, forced on every fixture, which must stay silent and
    name nothing.

Every `hermes_*` expectation below was recorded by running Hermes' own
`scan_directory` + `resolve_manifest_winners` over these exact trees.
"""
import json
import logging
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import shadow as shadow_module  # noqa: E402
from shadow import _hermes_root_scan, detect_shadow  # noqa: E402

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


# ── The round-3 differential fixtures ─────────────────────────────────────

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


# ── The round-4 fixtures: ordinary lines, typed by YAML ───────────────────

def _case_escaped_name(root):
    # Recorded live: Hermes decodes the escape, keys the backup `shieldcortex`
    # and LOADS it. The literal bytes `shieldcortex` never appear in that name
    # value, so even a raw-substring hint would only find it by folder name.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.bak-esc", 'name: "shieldcorte\\u0078"\n')


def _case_date_shaped(root):
    # Round-4 blocker, half one. `2026-99-99` is a plain scalar every version of
    # the grammar accepted; YAML's implicit typing reads it as a TIMESTAMP,
    # month 99 fails construction, and Hermes rejects the whole manifest.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.bak-date", "name: shieldcortex\ndescription: 2026-99-99\n")


def _case_inf_version(root):
    # Round-4 blocker, half two. `.inf` constructs as a float infinity and
    # Hermes' manifest conversion calls `int()` on it, which raises
    # OverflowError outside the narrow handler. Rejected.
    _manifest(root, "shieldcortex", "name: shieldcortex\n")
    _manifest(root, "shieldcortex.bak-inf", "name: shieldcortex\nmanifest_version: .inf\n")


#: (label, builder, hermes copies, hermes winner)
CASES = [
    ("an inline # comment after the name", _case_comment,
     ["shieldcortex", "shieldcortex.bak-x"], "shieldcortex.bak-x"),
    ("a manifest with no name: at all", _case_no_name, ["shieldcortex"], "shieldcortex"),
    ("quoted names, single and double", _case_quoted,
     ["shieldcortex", "shieldcortex.q"], "shieldcortex.q"),
    ("a portable plugin.json manifest", _case_portable,
     ["shieldcortex", "shieldcortex.portable"], "shieldcortex.portable"),
    ("a plugin.yaml directory beside a valid plugin.yml", _case_dir_manifest,
     ["shieldcortex"], "shieldcortex"),
    ("invalid YAML after a valid name: line", _case_broken_yaml,
     ["shieldcortex"], "shieldcortex"),
    ("dunder, foreign-harness, category, other name, plugin.yml", _case_skips,
     ["shieldcortex", "shieldcortex.yml-spelling"], "shieldcortex.yml-spelling"),
    ("plugin.yaml takes precedence over plugin.json", _case_yaml_beats_json,
     ["shieldcortex"], "shieldcortex"),
    ("an empty plugin.yaml", _case_empty, ["shieldcortex"], "shieldcortex"),
    ("a top-level sequence document", _case_sequence, ["shieldcortex"], "shieldcortex"),
    ("no copy at all", _case_none, [], None),
    ("a block-scalar name Hermes reads and loads", _case_block_scalar,
     ["shieldcortex", "shieldcortex.bak-x"], "shieldcortex.bak-x"),
    ("invalid YAML from a colon in a later value", _case_value_colon,
     ["shieldcortex"], "shieldcortex"),
    ("a plugin.json symlinked outside the plugin root", _case_linked_portable,
     ["shieldcortex"], "shieldcortex"),
    ("a plugin.json with an unknown author field", _case_portable_author,
     ["shieldcortex"], "shieldcortex"),
    ("a unicode escape in a double-quoted name", _case_escaped_name,
     ["shieldcortex", "shieldcortex.bak-esc"], "shieldcortex.bak-esc"),
    ("a date-shaped value YAML cannot construct", _case_date_shaped,
     ["shieldcortex"], "shieldcortex"),
    ("an infinite manifest_version Hermes cannot convert", _case_inf_version,
     ["shieldcortex"], "shieldcortex"),
]

#: The one fixture where Hermes met a filesystem error of its own: its
#: `plugin.yaml` is a DIRECTORY, so `read_text()` raises IsADirectoryError and
#: the child is dropped — with a valid `plugin.yml` naming us sitting beside it
#: and never looked at. Which of the two a given Hermes picks is Hermes'
#: business, so the scan says "I did not read this" rather than certifying the
#: root (#569 r8). The copies and the winner below are still Hermes' own answer.
UNREADABLE_CASE = "a plugin.yaml directory beside a valid plugin.yml"


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


class NoHermesTests(ParityFixtures):
    """Round-4 blocker: with no Hermes discovery there is no verdict at all.

    Every fixture, including the two that no grammar could ever have got right,
    and including the ones a grammar WOULD have got right — because "sometimes
    correct" is precisely the property that made the previous three rounds
    unshippable.
    """

    def _unavailable(self, module_reason):
        return mock.patch.object(
            shadow_module, "_hermes_root_scan",
            return_value=(None, None, module_reason, []))

    def test_every_fixture_produces_no_verdict_and_one_debug_line(self):
        reason = ("hermes_cli is not importable "
                  "(ModuleNotFoundError: No module named 'hermes_cli')")
        logger = logging.getLogger("shieldcortex.hermes")
        for case in CASES:
            label = case[0]
            with self.subTest(label):
                loaded = os.path.join(self.roots[label], "shieldcortex")
                with self._unavailable(reason):
                    with self.assertLogs(logger, level="DEBUG") as captured:
                        report = shadow_module.detect_shadow(loaded)
                # No report at all: no winner, no "others", nothing to mistake
                # for an answer.
                self.assertIsNone(report, label)
                self.assertIsNone(shadow_module.shadow_error_line(report))
                # Exactly one line, at DEBUG, carrying the real reason.
                self.assertEqual(len(captured.records), 1, [r.getMessage() for r in captured.records])
                self.assertEqual(captured.records[0].levelno, logging.DEBUG)
                self.assertIn("ModuleNotFoundError", captured.records[0].getMessage())

    def test_no_verdict_even_when_this_copy_is_the_backup(self):
        # The one thing that would still be free to compute — our own directory
        # name — is not reported either. Hermes could not be asked, so the
        # start-up line stays quiet and `shieldcortex doctor` is where the
        # operator learns that, with the remedy attached.
        label = "an inline # comment after the name"
        loaded = os.path.join(self.roots[label], "shieldcortex.bak-x")
        with self._unavailable("hermes_cli discovery raised RuntimeError: boom"):
            with self.assertLogs(logging.getLogger("shieldcortex.hermes"), level="DEBUG"):
                self.assertIsNone(shadow_module.detect_shadow(loaded))

    def test_a_discovery_failure_is_not_reported_as_an_import_failure(self):
        # The reason has to survive verbatim: "not importable" is wrong for
        # every failure after a successful import.
        label = "an inline # comment after the name"
        loaded = os.path.join(self.roots[label], "shieldcortex")
        with self._unavailable("hermes_cli discovery raised RuntimeError: boom"):
            with self.assertLogs(logging.getLogger("shieldcortex.hermes"), level="DEBUG") as cap:
                self.assertIsNone(shadow_module.detect_shadow(loaded))
        line = cap.records[0].getMessage()
        self.assertIn("discovery raised RuntimeError", line)
        self.assertNotIn("not importable", line)


@unittest.skipUnless(HERMES_IMPORTABLE, "hermes_cli is not importable in this interpreter")
class HermesPrimaryTests(ParityFixtures):
    def _assert_read_failures(self, label, unreadable):
        """Every fixture is readable; one holds a manifest nobody can read."""
        if label != UNREADABLE_CASE:
            self.assertEqual(unreadable, [])
            return
        self.assertEqual(len(unreadable), 1, unreadable)
        self.assertIn("plugin.yaml", unreadable[0])
        self.assertIn("IsADirectoryError", unreadable[0])

    def test_hermes_reports_the_recorded_copies_and_winner(self):
        for label, _build, copies, winner in CASES:
            with self.subTest(label):
                got_copies, got_winner, reason, unreadable = _hermes_root_scan(self.roots[label])
                self.assertIsNone(reason)
                self._assert_read_failures(label, unreadable)
                self.assertEqual(sorted(os.path.basename(c) for c in got_copies), sorted(copies))
                self.assertEqual(
                    os.path.basename(got_winner) if got_winner else None, winner)

    def test_hermes_answers_every_fixture(self):
        # The contract that replaced the differential one: where Hermes
        # answers, the answer is complete. There is no third state.
        for label, _build, _copies, _winner in CASES:
            with self.subTest(label):
                copies, _got_winner, reason, unreadable = _hermes_root_scan(self.roots[label])
                self.assertIsNotNone(copies)
                self.assertIsNone(reason)
                self._assert_read_failures(label, unreadable)

    def test_detect_shadow_names_the_copies_hermes_passed_over(self):
        label = "an inline # comment after the name"
        root = self.roots[label]
        report = detect_shadow(os.path.join(root, "shieldcortex"))
        self.assertIsNotNone(report)
        self.assertEqual(report["others"], [os.path.join(root, "shieldcortex.bak-x")])
        self.assertFalse(report["misnamed"])

    def test_a_fixture_hermes_calls_clean_produces_no_report(self):
        # `description: 2026-99-99` — the backup is not a copy to Hermes, so
        # there is nothing to report. A grammar said otherwise.
        root = self.roots["a date-shaped value YAML cannot construct"]
        self.assertIsNone(detect_shadow(os.path.join(root, "shieldcortex")))


class FallbackReasonTests(unittest.TestCase):
    """The reason a scan could not be done travels verbatim (#569 r3)."""

    def test_an_import_failure_says_so(self):
        with mock.patch.dict(sys.modules, {"hermes_cli": None}):
            copies, winner, reason, unreadable = _hermes_root_scan(tempfile.gettempdir())
        self.assertIsNone(copies)
        self.assertIsNone(winner)
        self.assertIn("not importable", reason)
        # A scan that never ran read nothing; the non-answer is `reason`.
        self.assertEqual(unreadable, [])

    @unittest.skipUnless(HERMES_IMPORTABLE, "hermes_cli is not importable in this interpreter")
    def test_a_discovery_failure_is_not_reported_as_an_import_failure(self):
        import hermes_cli.plugins_discovery as discovery

        with mock.patch.object(discovery, "scan_directory",
                               side_effect=RuntimeError("disk on fire")):
            copies, _winner, reason, unreadable = _hermes_root_scan(tempfile.gettempdir())
        self.assertIsNone(copies)
        self.assertEqual(unreadable, [])
        self.assertIn("discovery raised RuntimeError", reason)
        self.assertNotIn("not importable", reason)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
