"""#866: outage fallback log names the deciding tier, not a sibling flag."""
import logging
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sc_client import ActionGuardVerdict  # noqa: E402


class FallbackLogLabel(unittest.TestCase):
    def _hook(self):
        pkg_parent = str(Path(__file__).resolve().parents[2])
        if pkg_parent not in sys.path:
            sys.path.insert(0, pkg_parent)
        import shieldcortex as plugin

        self._home = tempfile.mkdtemp(prefix="sc-hermes-866-")
        self._saved = {k: os.environ.get(k) for k in ("HOME", "SHIELDCORTEX_ENFORCE")}
        os.environ["HOME"] = self._home
        os.environ["SHIELDCORTEX_ENFORCE"] = "0"
        down = (
            plugin.ActionGuardVerdict("allow", [], "scanner unavailable", available=False)
            if hasattr(plugin, "ActionGuardVerdict")
            else ActionGuardVerdict("allow", [], "scanner unavailable", available=False)
        )
        self._plugin = plugin
        self._orig = {
            "evaluate_tool_call": plugin.evaluate_tool_call,
            "fallback_catastrophic_match": plugin.fallback_catastrophic_match,
            "fallback_dangerous_match": plugin.fallback_dangerous_match,
            "fallback_self_protection_match": plugin.fallback_self_protection_match,
            "fallback_write_target_match": plugin.fallback_write_target_match,
        }
        plugin.evaluate_tool_call = lambda *_a, **_k: down
        plugin.fallback_catastrophic_match = lambda *_a, **_k: False
        plugin.fallback_dangerous_match = lambda *_a, **_k: True
        plugin.fallback_self_protection_match = lambda *_a, **_k: True
        plugin.fallback_write_target_match = lambda *_a, **_k: None
        hooks = {}

        class Ctx:
            def register_hook(self, name, fn):
                hooks[name] = fn

        plugin.register(Ctx())
        return hooks["pre_tool_call"]

    def tearDown(self):
        import shutil

        if hasattr(self, "_plugin") and hasattr(self, "_orig"):
            for name, value in self._orig.items():
                setattr(self._plugin, name, value)
        for k, v in getattr(self, "_saved", {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if hasattr(self, "_home"):
            shutil.rmtree(self._home, ignore_errors=True)

    def test_self_protection_outage_log_names_self_protection_tier(self):
        hook = self._hook()
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())

        lg = logging.getLogger("shieldcortex.hermes")
        handler = Capture()
        lg.addHandler(handler)
        old_level = lg.level
        lg.setLevel(logging.WARNING)
        try:
            d = hook("terminal", {"command": "ls -la"})
            self.assertIsNotNone(d)
            self.assertEqual(d["action"], "block")
            joined = "\n".join(records)
            self.assertIn("FALLBACK_BLOCK (self-protection)", joined)
            self.assertNotIn("FALLBACK_BLOCK (dangerous)", joined)
        finally:
            lg.removeHandler(handler)
            lg.setLevel(old_level)


if __name__ == "__main__":
    unittest.main()
