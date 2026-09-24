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
import importlib.util
import logging
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

# `plugins/hermes` on the path makes `shieldcortex` importable as the package
# Hermes itself loads (`entrypoint: __init__:register`).
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import shieldcortex  # noqa: E402
import shadow as shadow_module  # noqa: E402
from shadow import detect_shadow, read_manifest_name, shadow_error_line  # noqa: E402

#: The real package directory, used as the source for the copies the
#: loader-level tests import.
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FILES = ("__init__.py", "shadow.py", "sc_client.py", "policy.py", "plugin.yaml")


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


class SymlinkedInstallationTests(unittest.TestCase):
    """#569 blocker 5 — the signal has to survive a symlinked plugin directory.

    Hermes loads a directory plugin with
    `spec_from_file_location(..., submodule_search_locations=[plugin_dir])`
    where `plugin_dir` is the unresolved child of `plugins/` it discovered. If
    the plugin then asks for its own location through anything that resolves
    symlinks, `plugins/shieldcortex.bak-x -> /srv/sc-old` hands back
    `/srv/sc-old`, whose parent is not a `plugins/` root — and the diagnostic
    quietly finds nothing in the exact case it exists for.

    These tests load a REAL copy of the package through a REAL symlink with the
    loader's own machinery. Nothing is monkeypatched: `_package_dir` is the
    thing under test, so a test that replaced it would prove nothing.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.plugins = os.path.join(self._tmp.name, "plugins")
        os.makedirs(self.plugins)
        self._loaded = []
        self.addCleanup(self._unload)
        self.addCleanup(self._tmp.cleanup)

    def _unload(self):
        for name in self._loaded:
            for cached in [k for k in sys.modules if k == name or k.startswith(name + ".")]:
                sys.modules.pop(cached, None)

    @staticmethod
    def copy_package(dest):
        """A working copy of the plugin package at `dest`."""
        os.makedirs(dest, exist_ok=True)
        for name in PACKAGE_FILES:
            shutil.copy2(os.path.join(PACKAGE_ROOT, name), os.path.join(dest, name))
        return dest

    def load_like_hermes(self, plugin_dir, slug):
        """Import `plugin_dir` the way `PluginManager._load_directory_module` does."""
        parent = "sc569_test_plugins"
        if parent not in sys.modules:
            namespace = types.ModuleType(parent)
            namespace.__path__ = []
            namespace.__package__ = parent
            sys.modules[parent] = namespace
        full = "%s.%s" % (parent, slug)
        spec = importlib.util.spec_from_file_location(
            full, os.path.join(plugin_dir, "__init__.py"),
            submodule_search_locations=[str(plugin_dir)])
        module = importlib.util.module_from_spec(spec)
        module.__package__ = full
        module.__path__ = [str(plugin_dir)]
        sys.modules[full] = module
        self._loaded.append(full)
        spec.loader.exec_module(module)
        return module

    def register(self, module):
        ctx = FakeCtx()
        with self.assertLogs(logging.getLogger("shieldcortex.hermes"), level="INFO") as captured:
            result = module.register(ctx)
        errors = [r.getMessage() for r in captured.records if r.levelno >= logging.ERROR]
        return ctx, result, errors

    def test_error_fires_when_loaded_through_a_symlinked_plugin_dir(self):
        # The layout from the review: the loaded copy is a link out of the tree.
        target = self.copy_package(os.path.join(self._tmp.name, "srv", "sc-old"))
        canonical = self.copy_package(os.path.join(self.plugins, "shieldcortex"))
        link = os.path.join(self.plugins, "shieldcortex.bak-x")
        os.symlink(target, link)
        # The premise: resolving would move the answer out of `plugins/`.
        self.assertNotEqual(os.path.realpath(link), link)
        self.assertNotEqual(os.path.dirname(os.path.realpath(link)), self.plugins)

        module = self.load_like_hermes(link, "symlinked")

        # The discovery path survives: this is the whole fix.
        self.assertEqual(module._package_dir(), link)

        ctx, result, errors = self.register(module)

        self.assertEqual(len(errors), 1, errors)
        self.assertIn(link, errors[0])
        self.assertIn(canonical, errors[0])
        self.assertIn("--fix-hermes-plugin-copies", errors[0])
        # And the gate still registered.
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")

    def test_no_error_when_the_real_loader_loads_the_canonical_copy(self):
        canonical = self.copy_package(os.path.join(self.plugins, "shieldcortex"))

        module = self.load_like_hermes(canonical, "canonical")

        self.assertEqual(module._package_dir(), canonical)
        ctx, result, errors = self.register(module)
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


class UndeterminedStartupTests(unittest.TestCase):
    """#569 r3: "I could not tell" is a thing this must be able to say.

    Round 2 appended a note about the directories it would not read and then
    reported the install clean anyway. On a host where the unreadable directory
    IS the shadow, that is the check certifying the exact state it exists to
    catch. The fallback now gives the root no verdict at all, and the start-up
    line says so at WARNING — not ERROR, because nothing is known to be wrong,
    and not silence, because nothing is known to be right.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.plugins = os.path.join(self._tmp.name, "plugins")
        os.makedirs(self.plugins)
        self.addCleanup(self._tmp.cleanup)
        # This box has a working hermes_cli, and the primary path never reports
        # an unknown — so the fallback is forced, with the reason it would
        # really carry on a host that has no Hermes to ask.
        #
        # Both module objects, deliberately: these tests import `shadow` as a
        # top-level module, while `register()` goes through the package's
        # `shieldcortex.shadow`. They are two distinct objects under one file,
        # and patching only one silently leaves the other live.
        reason = ("hermes_cli is not importable "
                  "(ModuleNotFoundError: No module named 'hermes_cli')")
        for module in (shadow_module, shieldcortex.shadow):
            patched = mock.patch.object(module, "_hermes_root_scan",
                                        return_value=(None, None, reason))
            patched.start()
            self.addCleanup(patched.stop)

    def register_from(self, package_dir):
        ctx = FakeCtx()
        logger = logging.getLogger("shieldcortex.hermes")
        with mock.patch.object(shieldcortex, "_package_dir", return_value=package_dir):
            with self.assertLogs(logger, level="DEBUG") as captured:
                result = shieldcortex.register(ctx)
        by_level = {
            "error": [r.getMessage() for r in captured.records if r.levelno >= logging.ERROR],
            "warning": [r.getMessage() for r in captured.records
                        if r.levelno == logging.WARNING],
            "debug": [r.getMessage() for r in captured.records if r.levelno == logging.DEBUG],
        }
        return ctx, result, by_level

    def test_an_unreadable_neighbour_is_a_warning_not_a_clean_start(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        murky = make_plugin_dir(self.plugins, "zz-murky", manifest_name=None)
        with open(os.path.join(murky, "plugin.yaml"), "w", encoding="utf-8") as fh:
            # Mentions our key, so it could be the shadow; a block scalar, so
            # this reader will not say whether it is.
            fh.write("name: >-\n  shieldcortex\n")

        ctx, result, logs = self.register_from(canonical)

        self.assertEqual(logs["error"], [])
        line = next(m for m in logs["warning"] if "shieldcortex" in m)
        self.assertIn("could not determine which plugin copy Hermes loads", line)
        self.assertIn(murky, line)
        # And the real reason travels with it, rather than being flattened.
        self.assertIn("ModuleNotFoundError", line)
        # The gate registered regardless.
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")

    def test_a_real_shadow_beside_an_unknown_is_still_an_error(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        backup = make_plugin_dir(self.plugins, "shieldcortex.bak-x")
        murky = make_plugin_dir(self.plugins, "zz-murky", manifest_name=None)
        with open(os.path.join(murky, "plugin.yaml"), "w", encoding="utf-8") as fh:
            fh.write("name: >-\n  shieldcortex\n")

        _ctx, _result, logs = self.register_from(canonical)

        self.assertEqual(len(logs["error"]), 1, logs)
        self.assertIn(backup, logs["error"][0])
        self.assertIn(murky, logs["error"][0])

    def test_the_fallback_reason_is_the_real_one(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        make_plugin_dir(self.plugins, "shieldcortex.bak-x")
        report = detect_shadow(canonical)
        self.assertTrue(report["approximate"])
        self.assertIn("ModuleNotFoundError", report["reason"])
        self.assertIn(report["reason"], shadow_error_line(report))


class StartupRootSizeTests(unittest.TestCase):
    """#569 r3 nit: the start-up check declines an enormous plugins root.

    Whichever half answers, the cost is a manifest read per child — and Hermes'
    own discovery recurses into category dirs and reads each manifest whole.
    Fine for the tens of entries a real root holds; not something to do
    synchronously inside `register()` for thousands. `doctor` has no such cap.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.plugins = os.path.join(self._tmp.name, "plugins")
        os.makedirs(self.plugins)
        self.addCleanup(self._tmp.cleanup)

    def _fill(self, count):
        for index in range(count):
            os.makedirs(os.path.join(self.plugins, "filler-%04d" % index), exist_ok=True)

    def test_a_huge_root_is_skipped_and_said_so_at_debug(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        # A genuine shadow, which the check would otherwise report.
        make_plugin_dir(self.plugins, "shieldcortex.bak-x")
        self._fill(shadow_module.MAX_STARTUP_ROOT_ENTRIES + 1)

        logger = logging.getLogger("shieldcortex.hermes")
        with self.assertLogs(logger, level="DEBUG") as captured:
            self.assertIsNone(detect_shadow(canonical))
        debug = [r.getMessage() for r in captured.records if r.levelno == logging.DEBUG]
        self.assertTrue(any("skipped at start-up" in m for m in debug), debug)

    def test_the_same_root_under_the_cap_still_reports(self):
        canonical = make_plugin_dir(self.plugins, "shieldcortex")
        backup = make_plugin_dir(self.plugins, "shieldcortex.bak-x")
        self._fill(10)
        report = detect_shadow(canonical)
        self.assertIsNotNone(report)
        self.assertEqual(report["others"], [backup])

    def test_our_own_directory_name_is_still_read_past_the_cap(self):
        # It costs no I/O at all, and it is the strongest signal there is:
        # whichever copy is executing won discovery, so a non-canonical name IS
        # the shadow.
        backup = make_plugin_dir(self.plugins, "shieldcortex.bak-x")
        make_plugin_dir(self.plugins, "shieldcortex")
        self._fill(shadow_module.MAX_STARTUP_ROOT_ENTRIES + 1)

        report = detect_shadow(backup)
        self.assertIsNotNone(report)
        self.assertTrue(report["misnamed"])
        self.assertEqual(report["others"], [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
