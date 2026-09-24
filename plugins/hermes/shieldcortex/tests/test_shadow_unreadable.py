"""
#569 r8 — the start-up check may not call a root clean on a manifest it did
not read.

Two different things hid a copy from this check while the gateway loaded it:

  * it STATTED the manifest and stopped there. Stat and open are two different
    permissions, and a portable `plugin.json` written 0600 by another account
    stats for everybody and opens for nobody else — so the file whose contents
    decide the key was never consulted;
  * Hermes WRAPS what it hit. `agent_plugins._read_json_object` turns a
    PermissionError into an `AgentPluginError` — a ValueError — with
    `raise ... from exc`, and `plugins_discovery` logs the wrapper. On its own
    type that is indistinguishable from a schema rejection, and a schema
    rejection is an ANSWER: "this is not a plugin".

The layout throughout is the one the review reproduced: the installed
`plugins/shieldcortex` beside a VALID portable package in
`plugins/shieldcortex.bak-portable`, which sorts later and therefore wins.

This module is a start-up diagnostic, so the contract is narrow on purpose: it
never produces a verdict from an incomplete scan, it says so once at DEBUG, and
it never raises. `shieldcortex doctor` is where uncertainty is reported with a
remedy attached.
"""
import json
import logging
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shadow import (  # noqa: E402
    _manifest_read_problems,
    _os_error_in_chain,
    _unreadable_from_records,
    detect_shadow,
)

try:
    import hermes_cli.plugins_discovery  # noqa: F401

    HERMES_IMPORTABLE = True
except Exception:  # pragma: no cover - depends on the interpreter under test
    HERMES_IMPORTABLE = False

needs_hermes = unittest.skipUnless(
    HERMES_IMPORTABLE, "hermes_cli is not importable in this interpreter")

#: Root reads everything, so the real-mode cases cannot be staged there.
IS_ROOT = hasattr(os, "getuid") and os.getuid() == 0
unless_root = unittest.skipIf(IS_ROOT, "running as root: a mode cannot deny this process")

PORTABLE_SCHEMA = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"


class PortableLayout(unittest.TestCase):
    """`plugins/shieldcortex` plus a portable backup that sorts after it."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.plugins = os.path.join(self._tmp.name, "plugins")
        os.makedirs(self.plugins)
        self.canonical = os.path.join(self.plugins, "shieldcortex")
        os.makedirs(self.canonical)
        with open(os.path.join(self.canonical, "plugin.yaml"), "w", encoding="utf-8") as fh:
            fh.write("name: shieldcortex\nkind: standalone\nversion: 5.1.0\n")
        self.backup = os.path.join(self.plugins, "shieldcortex.bak-portable")
        os.makedirs(self.backup)
        self.manifest = os.path.join(self.backup, "plugin.json")
        self.write_manifest()
        with open(os.path.join(self.backup, "plugin.py"), "w", encoding="utf-8") as fh:
            fh.write("def register(*a, **k):\n    pass\n")

    def write_manifest(self, schema=PORTABLE_SCHEMA):
        body = {"$schema": schema, "name": "shieldcortex", "version": "1.0.0"}
        with open(self.manifest, "w", encoding="utf-8") as fh:
            fh.write(json.dumps(body) + "\n")

    def make_unreadable(self, target):
        """`chmod 000`, put back however the test ends."""
        previous = stat.S_IMODE(os.stat(target).st_mode)
        self.addCleanup(lambda: os.chmod(target, previous))
        os.chmod(target, 0o000)

    def detect(self):
        """`(report, debug lines)` for a scan of the canonical copy."""
        logger = logging.getLogger("shieldcortex.hermes")
        # A DEBUG floor with one guaranteed record: `assertLogs` fails an empty
        # log, and "nothing was said" is an outcome these cases assert.
        with self.assertLogs(logger, level="DEBUG") as captured:
            logger.debug("[test] marker")
            report = detect_shadow(self.canonical)
        return report, [r.getMessage() for r in captured.records]


@needs_hermes
class ReadableLayoutIsAShadow(PortableLayout):
    """The premise: readable, this layout IS a shadow and is reported."""

    def test_the_portable_backup_is_named(self):
        report, _logs = self.detect()
        self.assertIsNotNone(report)
        self.assertEqual(report["others"], [self.backup])
        self.assertFalse(report["misnamed"])


@needs_hermes
class AnUnreadableManifestIsNotACleanRoot(PortableLayout):
    @unless_root
    def test_a_manifest_this_process_cannot_read_is_said_out_loud(self):
        self.make_unreadable(self.manifest)
        # The premise: the directory lists and the file stats. Only the READ
        # fails, which is exactly what the stat-only check could not see.
        self.assertIn("plugin.json", os.listdir(self.backup))
        self.assertTrue(os.path.isfile(self.manifest))

        report, logs = self.detect()

        # Hermes dropped the manifest, so there is no copy to name — and that
        # is precisely why the root may not be called clean.
        self.assertIsNone(report)
        line = next((m for m in logs if "incomplete" in m), None)
        self.assertIsNotNone(line, logs)
        self.assertIn(self.manifest, line)
        self.assertIn("PermissionError", line)

    @unless_root
    def test_the_pre_read_alone_finds_it(self):
        # The half that does not depend on Hermes logging anything: our own
        # open of every candidate that is there.
        self.make_unreadable(self.manifest)
        problems = _manifest_read_problems(self.plugins)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(self.manifest, problems[0])
        self.assertIn("PermissionError", problems[0])

    def test_the_cause_chain_finds_it_when_the_file_is_readable(self):
        # The other half, driven where a mode change cannot reach: the file is
        # perfectly readable, our pre-read finds nothing, and HERMES fails on
        # it in the shape `agent_plugins` produces.
        from hermes_cli import plugins_discovery
        from hermes_cli.agent_plugins import AgentPluginError

        def wrapped(child, source, prefix):
            try:
                raise PermissionError(13, "injected: refusing to read")
            except PermissionError as exc:
                raise AgentPluginError(
                    "plugin.json is not valid readable JSON: injected") from exc

        self.assertEqual(_manifest_read_problems(self.plugins), [])
        with mock.patch.object(plugins_discovery, "portable_plugin_manifest", wrapped):
            report, logs = self.detect()

        self.assertIsNone(report)
        line = next((m for m in logs if "incomplete" in m), None)
        self.assertIsNotNone(line, logs)
        self.assertIn("injected: refusing to read", line)
        self.assertIn("PermissionError", line)

    @unless_root
    def test_a_second_candidate_hermes_never_opened_is_still_a_gap(self):
        # The leg that does not depend on Hermes logging anything. A readable
        # `plugin.yaml` is what `scan_directory` selects, parses and says
        # nothing at all about — the `plugin.json` beside it is never opened,
        # so there is no record for the cause chain to classify. The pre-read
        # opens EVERY candidate that is there, which is what keeps this check
        # independent of Hermes' log wording, its log level, and of which of
        # the three names a given Hermes version selects.
        second = os.path.join(self.canonical, "plugin.json")
        with open(second, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"$schema": PORTABLE_SCHEMA, "name": "shieldcortex"}) + "\n")
        self.make_unreadable(second)

        problems = _manifest_read_problems(self.plugins)

        self.assertEqual(len(problems), 1, problems)
        self.assertIn(second, problems[0])

    def test_a_schema_rejection_is_an_answer_and_stays_quiet(self):
        # The control. Hermes rejects this manifest for its `$schema`, with no
        # OSError anywhere in the chain: that is a verdict — "this is not a
        # plugin" — and the root really is clean.
        self.write_manifest(schema="https://example.invalid/not-the-schema.json")

        report, logs = self.detect()

        self.assertIsNone(report)
        self.assertEqual([m for m in logs if "incomplete" in m], [])

    def test_a_known_shadow_is_still_reported_when_something_is_unreadable(self):
        # Uncertainty widens the answer; it does not delete the part that is
        # certain. A plain YAML backup is a copy Hermes named, and an
        # unreadable third directory must not swallow it.
        plain = os.path.join(self.plugins, "shieldcortex.bak-x")
        os.makedirs(plain)
        with open(os.path.join(plain, "plugin.yaml"), "w", encoding="utf-8") as fh:
            fh.write("name: shieldcortex\nversion: 0.1.0\n")
        self.write_manifest(schema="https://example.invalid/not-the-schema.json")
        if not IS_ROOT:
            self.make_unreadable(self.manifest)

        report, _logs = self.detect()

        self.assertIsNotNone(report)
        self.assertIn(plain, report["others"])


class CauseChainTests(unittest.TestCase):
    """What counts as a filesystem failure underneath a wrapper."""

    def test_a_wrapped_permission_error_is_found(self):
        try:
            raise PermissionError(13, "denied")
        except PermissionError as exc:
            wrapper = ValueError("not valid readable JSON")
            wrapper.__cause__ = exc
        self.assertIsInstance(_os_error_in_chain(wrapper), PermissionError)

    def test_a_plain_schema_error_is_not_one(self):
        self.assertIsNone(_os_error_in_chain(ValueError("unsupported schema")))

    def test_a_missing_file_is_not_one_at_any_depth(self):
        # A manifest that went away mid-scan was discovered by nobody.
        inner = FileNotFoundError(2, "no such file")
        wrapper = ValueError("not valid readable JSON")
        wrapper.__cause__ = inner
        self.assertIsNone(_os_error_in_chain(inner))
        self.assertIsNone(_os_error_in_chain(wrapper))

    def test_a_context_cycle_terminates(self):
        left = ValueError("left")
        right = ValueError("right")
        left.__context__ = right
        right.__context__ = left
        self.assertIsNone(_os_error_in_chain(left))

    def test_the_chain_is_bounded(self):
        # Deeper than the bound, with the only OSError at the bottom: a
        # diagnostic walks a fixed distance and gives up rather than a host's.
        deepest = PermissionError(13, "denied")
        current = deepest
        for _ in range(40):
            outer = ValueError("wrapper")
            outer.__cause__ = current
            current = outer
        self.assertIsNone(_os_error_in_chain(current))

    def test_context_is_followed_when_there_is_no_cause(self):
        try:
            raise PermissionError(13, "denied")
        except PermissionError:
            wrapper = ValueError("while handling")
            wrapper.__context__ = sys.exc_info()[1]
        self.assertIsInstance(_os_error_in_chain(wrapper), PermissionError)


class RecordClassificationTests(unittest.TestCase):
    """The record is read by its arguments, not by its wording."""

    @staticmethod
    def _record(msg, args, exc_info=None):
        return logging.LogRecord("hermes_cli.plugins", logging.WARNING, __file__, 1,
                                 msg, args, exc_info)

    def test_the_path_argument_names_the_failure(self):
        try:
            raise PermissionError(13, "denied")
        except PermissionError as exc:
            wrapper = ValueError("plugin.json is not valid readable JSON")
            wrapper.__cause__ = exc
        found = _unreadable_from_records([
            self._record("Failed to parse %s: %s", (Path("/p/plugin.json"), wrapper))])
        self.assertEqual(len(found), 1, found)
        self.assertIn("/p/plugin.json", found[0])
        self.assertIn("PermissionError", found[0])

    def test_an_attached_exception_counts_too(self):
        # `parse_manifest_file` passes `exc_info=` under the plugins debug flag,
        # and which one is populated is a Hermes-side setting.
        exc = PermissionError(13, "denied")
        found = _unreadable_from_records([
            self._record("Failed to parse %s", (Path("/p/plugin.yaml"),),
                         exc_info=(type(exc), exc, None))])
        self.assertEqual(len(found), 1, found)
        self.assertIn("/p/plugin.yaml", found[0])

    def test_a_record_with_no_exception_is_not_a_failure(self):
        self.assertEqual(
            _unreadable_from_records([self._record("Scanning %s", ("/p",))]), [])

    def test_a_failure_with_no_path_argument_still_reports_the_filename(self):
        exc = PermissionError(13, "denied")
        exc.filename = "/p/plugin.json"
        found = _unreadable_from_records([self._record("Trouble: %s", (exc,))])
        self.assertEqual(len(found), 1, found)
        self.assertIn("/p/plugin.json", found[0])


class NeverRaisesTests(unittest.TestCase):
    """A start-up diagnostic must not be able to stop the gate registering."""

    def test_a_root_that_is_not_there_answers_empty(self):
        missing = os.path.join(tempfile.gettempdir(), "sc569-not-here-at-all")
        self.assertEqual(_manifest_read_problems(missing), [])

    def test_an_unlistable_root_answers_with_its_own_reason(self):
        with mock.patch("os.scandir", side_effect=PermissionError(13, "denied")):
            problems = _manifest_read_problems(tempfile.gettempdir())
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("PermissionError", problems[0])

    def test_a_manifest_candidate_that_is_a_directory_is_never_opened(self):
        # Nobody reads a directory as a manifest, and a FIFO named
        # `plugin.json` would hang start-up rather than answer it. Hermes meets
        # its own error on such a path and logs it; the PRE-READ leaves it be.
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "odd", "plugin.yaml"))
            self.assertEqual(_manifest_read_problems(tmp), [])

    def test_a_record_that_is_nothing_like_a_log_record_is_survived(self):
        self.assertEqual(_unreadable_from_records([object()]), [])
        self.assertEqual(_unreadable_from_records(None), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
