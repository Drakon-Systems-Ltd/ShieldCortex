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


if __name__ == "__main__":
    unittest.main()
