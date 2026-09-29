"""
#509 R4-1: the guard self-protection floor on the Hermes surface. A verdict
carrying a self-protection signal blocks even in advisory (enforce=False); an
ordinary dangerous verdict in advisory still does not.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sc_client import (  # noqa: E402
    SELF_PROTECTION_SIGNALS,
    ActionGuardVerdict,
    fallback_self_protection_match,
)
from policy import action_guard_decision  # noqa: E402


class SelfProtectionFloor(unittest.TestCase):
    def test_every_floor_signal_blocks_in_advisory(self):
        for sig in SELF_PROTECTION_SIGNALS:
            d = action_guard_decision(ActionGuardVerdict("require_approval", [sig], "guard state"), enforce=False)
            self.assertIsNotNone(d, sig)
            self.assertEqual(d["action"], "block")

    def test_ordinary_dangerous_still_advisory(self):
        self.assertIsNone(
            action_guard_decision(ActionGuardVerdict("require_approval", ["sudo"], "ask"), enforce=False)
        )

    def test_outage_scan_floor_blocks_in_advisory(self):
        for cmd in (
            "echo x >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl",
            "cp forged.json ~/.shieldcortex/approvals/guard-readiness.json",
            "shieldcortex config --action-guard-disable",
            "echo {} > ~/.shieldcortex/config.json",
        ):
            self.assertTrue(fallback_self_protection_match(cmd), cmd)
        v = ActionGuardVerdict("allow", [], "down", available=False)
        d = action_guard_decision(v, enforce=False, fallback_dangerous=True, fallback_self_protected=True)
        self.assertEqual(d["action"], "block")
        self.assertIsNone(action_guard_decision(v, enforce=False, fallback_dangerous=True))
        self.assertFalse(fallback_self_protection_match("ls -la"))


class OutageFloorLockPaths(unittest.TestCase):
    """#509 r5 finding 9: with SHIELDCORTEX_ENFORCE=0 and the scanner down,
    the REGISTERED hook denies writes to the harness settings and the policy
    lock, like the approvals path — and still lets reads of them through."""

    def _hook(self):
        import os
        import tempfile

        pkg_parent = str(Path(__file__).resolve().parents[2])
        if pkg_parent not in sys.path:
            sys.path.insert(0, pkg_parent)
        import shieldcortex as plugin  # the package, as Hermes loads it

        self._home = tempfile.mkdtemp(prefix="sc-hermes-r5-")
        self._saved = {k: os.environ.get(k) for k in ("HOME", "SHIELDCORTEX_ENFORCE")}
        os.environ["HOME"] = self._home
        os.environ["SHIELDCORTEX_ENFORCE"] = "0"
        down = plugin.ActionGuardVerdict("allow", [], "scanner unavailable", available=False) \
            if hasattr(plugin, "ActionGuardVerdict") else ActionGuardVerdict("allow", [], "scanner unavailable", available=False)
        self._orig_eval = plugin.evaluate_tool_call
        plugin.evaluate_tool_call = lambda *_a, **_k: down
        self._plugin = plugin
        hooks = {}

        class Ctx:
            def register_hook(self, name, fn):
                hooks[name] = fn

        plugin.register(Ctx())
        return hooks["pre_tool_call"]

    def tearDown(self):
        import os
        import shutil

        if hasattr(self, "_plugin"):
            self._plugin.evaluate_tool_call = self._orig_eval
        for k, v in getattr(self, "_saved", {}).items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        if hasattr(self, "_home"):
            shutil.rmtree(self._home, ignore_errors=True)

    def test_settings_and_policy_lock_writes_denied_in_advisory_outage(self):
        hook = self._hook()
        for cmd in (
            "echo {} > ~/.claude/settings.json",
            "echo {} > /etc/shieldcortex/policy.json",
            "echo {} >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl",
            "SHIELDCORTEX_DIST_ROOT=/tmp/evil shieldcortex doctor",
            "echo {} > ~/.openclaw/openclaw.json",
        ):
            d = hook("terminal", {"command": cmd})
            self.assertIsNotNone(d, cmd)
            self.assertEqual(d["action"], "block", cmd)

    def test_reads_and_ordinary_ops_still_pass_in_advisory_outage(self):
        hook = self._hook()
        for cmd in ("cat ~/.claude/settings.json", "ls /etc/shieldcortex", "sudo systemctl stop ssh", "ls -la"):
            self.assertIsNone(hook("terminal", {"command": cmd}), cmd)
        self.assertIsNone(hook("read_file", {"path": "/etc/shieldcortex/policy.json"}))


if __name__ == "__main__":
    unittest.main()
