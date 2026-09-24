"""
#569 — the plugin's own start-up signal for a shadowing copy.

Hermes keys plugins on the manifest `name:`, walks `plugins/` in sorted order
and lets the LAST manifest win silently. A backup left beside the live plugin
(`plugins/shieldcortex.bak-<ts>/`) therefore loads INSTEAD of the upgrade, and
nothing in the gateway log says so.

Whichever copy is executing is by definition the one that won discovery, so
`register()` can name it. These tests drive `register()` against fake plugin
roots in a temp dir, and check both halves of the contract: the ERROR line is
there when it should be, and registration succeeds either way — a diagnostic
must never cost the host its gate.
"""
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# `plugins/hermes` on the path makes `shieldcortex` importable as the package
# Hermes itself loads (`entrypoint: __init__:register`).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import shieldcortex  # noqa: E402
from shadow import detect_shadow, read_manifest_name, shadow_error_line  # noqa: E402


class FakeCtx:
    """The one thing Hermes' ctx has to offer `register`."""

    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn


def make_plugin_dir(root, name, manifest_name="shieldcortex", manifest_file="plugin.yaml"):
    """A plugin directory under `root` declaring `manifest_name`."""
    directory = os.path.join(root, name)
    os.makedirs(directory, exist_ok=True)
    if manifest_name is not None:
        with open(os.path.join(directory, manifest_file), "w", encoding="utf-8") as fh:
            fh.write("# a manifest\nname: %s\nkind: standalone\n" % manifest_name)
    return directory


class ShadowSignalTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.plugins = os.path.join(self._tmp.name, "plugins")
        os.makedirs(self.plugins)
        self.addCleanup(self._tmp.cleanup)

    def register_from(self, package_dir):
        """Run `register()` as if loaded from `package_dir`; return (result, errors)."""
        ctx = FakeCtx()
        logger = logging.getLogger("shieldcortex.hermes")
        with mock.patch.object(shieldcortex, "_package_dir", return_value=package_dir):
            # INFO, not ERROR: `register` always logs one INFO line, so the
            # context manager has a record either way and the clean case can
            # assert the ABSENCE of an ERROR rather than fail on an empty log.
            with self.assertLogs(logger, level="INFO") as captured:
                result = shieldcortex.register(ctx)
        errors = [r.getMessage() for r in captured.records if r.levelno >= logging.ERROR]
        return ctx, result, errors

    def test_error_line_when_loaded_from_a_backup_copy(self):
        make_plugin_dir(self.plugins, "shieldcortex")
        backup = make_plugin_dir(self.plugins, "shieldcortex.bak-x")

        ctx, result, errors = self.register_from(backup)

        self.assertEqual(len(errors), 1, errors)
        line = errors[0]
        self.assertIn(backup, line)
        self.assertIn(os.path.join(self.plugins, "shieldcortex"), line)
        self.assertIn("--fix-hermes-plugin-copies", line)
        # Registration still happened.
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")

    def test_error_line_when_a_sibling_shadow_exists(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        backup = make_plugin_dir(self.plugins, "shieldcortex.bak-x")

        ctx, result, errors = self.register_from(canonical)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn(backup, errors[0])
        self.assertIn("--fix-hermes-plugin-copies", errors[0])
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")

    def test_no_error_line_in_the_clean_case(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        # A category directory (no manifest) and a differently-named plugin are
        # both discovery-safe: neither can take the `shieldcortex` key.
        make_plugin_dir(self.plugins, "memory", manifest_name=None)
        make_plugin_dir(os.path.join(self.plugins, "memory"), "provider")
        make_plugin_dir(self.plugins, "zz-other", manifest_name="ekho")

        ctx, result, errors = self.register_from(canonical)

        self.assertEqual(errors, [])
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")

    def test_registration_survives_an_unreadable_plugin_root(self):
        # The signal is best-effort; a parent it cannot list must not raise.
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        with mock.patch("os.listdir", side_effect=OSError("denied")):
            ctx, result, errors = self.register_from(canonical)
        self.assertEqual(errors, [])
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")


class ShadowDetectionTests(unittest.TestCase):
    """The discovery rules the signal mirrors, tested directly."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.plugins = os.path.join(self._tmp.name, "plugins")
        os.makedirs(self.plugins)
        self.addCleanup(self._tmp.cleanup)

    def test_dunder_directories_are_skipped(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        make_plugin_dir(self.plugins, "__pycache__")
        self.assertIsNone(detect_shadow(canonical))

    def test_plugin_yml_spelling_counts(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        make_plugin_dir(self.plugins, "shieldcortex.old", manifest_file="plugin.yml")
        report = detect_shadow(canonical)
        self.assertIsNotNone(report)
        self.assertEqual(report["others"], [os.path.join(self.plugins, "shieldcortex.old")])

    def test_malformed_manifest_is_skipped(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        broken = make_plugin_dir(self.plugins, "shieldcortex.broken", manifest_name=None)
        with open(os.path.join(broken, "plugin.yaml"), "w", encoding="utf-8") as fh:
            fh.write(":\n  not: [a manifest\n")
        self.assertIsNone(detect_shadow(canonical))

    def test_manifest_name_reader_handles_quotes_comments_and_nesting(self):
        directory = make_plugin_dir(self.plugins, "p", manifest_name=None)
        manifest = os.path.join(directory, "plugin.yaml")
        with open(manifest, "w", encoding="utf-8") as fh:
            fh.write("meta:\n  name: not-the-plugin-key\nname: 'shieldcortex'  # live\n")
        self.assertEqual(read_manifest_name(manifest), "shieldcortex")

    def test_clean_report_has_no_error_line(self):
        self.assertIsNone(shadow_error_line(None))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
