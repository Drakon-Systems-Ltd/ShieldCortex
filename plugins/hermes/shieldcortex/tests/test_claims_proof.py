"""
Claims-proof rows for the Hermes plane (docs/CLAIMS-PROOF.md, claim 18).

README: "Hermes gates tool calls once you enable its plugin and the local API
is up; … Hermes has no approval prompt, so a call Action Guard would hold is
blocked while enforcing." and "The enabled plugin enforces by default …
Advisory mode still blocks Action Guard's hard-block verdicts and recognised
calls that would change the guard's own state or config."

Each test fires the real policy module with a real verdict shape and asserts
the Hermes hook decision. `npm test` never loads this plane; CI runs these with
`python3 -m unittest discover -s plugins/hermes/shieldcortex/tests`.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sc_client import ActionGuardVerdict  # noqa: E402
from policy import action_guard_decision, resolve_enforce  # noqa: E402


def _blocked(decision):
    return isinstance(decision, dict) and decision.get("action") == "block"


class TestClaim18HermesPlane(unittest.TestCase):
    def test_enforces_by_default_and_only_an_explicit_word_opts_out(self):
        # "The enabled plugin enforces by default, whatever the shared Action Guard setting says."
        for unset in (None, "", "  ", "yes", "garbage"):
            self.assertTrue(resolve_enforce(unset), unset)
        for word in ("0", "false", "no", "off", "advisory", " Advisory "):
            self.assertFalse(resolve_enforce(word), word)

    def test_would_hold_call_is_blocked_while_enforcing(self):
        # Hermes has no approval prompt: require_approval becomes a block.
        d = action_guard_decision(ActionGuardVerdict("require_approval", ["privilege-escalation"], "requires approval"), enforce=True)
        self.assertTrue(_blocked(d))
        self.assertIn("ShieldCortex blocked this action", d["message"])

    def test_would_hold_call_proceeds_in_advisory(self):
        d = action_guard_decision(ActionGuardVerdict("require_approval", ["privilege-escalation"], "requires approval"), enforce=False)
        self.assertIsNone(d)

    def test_hard_block_verdict_blocks_in_both_postures(self):
        v = ActionGuardVerdict("block", ["recursive-force-delete"], "catastrophic")
        self.assertTrue(_blocked(action_guard_decision(v, enforce=True)))
        self.assertTrue(_blocked(action_guard_decision(v, enforce=False)))

    def test_self_protection_floor_blocks_even_in_advisory(self):
        # A call that would switch the guard off or change its config is never advisory.
        v = ActionGuardVerdict("require_approval", ["disable-action-guard"], "could switch off ShieldCortex")
        self.assertTrue(_blocked(action_guard_decision(v, enforce=False)))

    def test_allow_verdict_is_allowed(self):
        self.assertIsNone(action_guard_decision(ActionGuardVerdict("allow", [], ""), enforce=True))

    def test_api_unreachable_fallback_is_bounded(self):
        # "While the API is unreachable, its bounded fallback scan blocks the
        # self-protection and catastrophic shapes it recognises in every mode,
        # and recognised dangerous shapes while enforcing."
        down = ActionGuardVerdict("allow", [], "unreachable", available=False)
        self.assertTrue(_blocked(action_guard_decision(down, enforce=False, fallback_blocked=True)))
        self.assertTrue(_blocked(action_guard_decision(down, enforce=False, fallback_self_protected=True)))
        self.assertTrue(_blocked(action_guard_decision(down, enforce=True, fallback_dangerous=True)))
        self.assertIsNone(action_guard_decision(down, enforce=False, fallback_dangerous=True))
        # Nothing recognised: fail open, so a down scanner does not wedge normal work.
        self.assertIsNone(action_guard_decision(down, enforce=True))


if __name__ == "__main__":
    unittest.main()
