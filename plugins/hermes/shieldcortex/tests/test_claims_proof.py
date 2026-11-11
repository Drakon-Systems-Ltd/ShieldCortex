"""
Claims-proof rows for the Hermes plane (docs/CLAIMS-PROOF.md, claim 18).

README: "Hermes gates tool calls once you enable its plugin and the local API
is up; … Hermes has no approval prompt, so a call Action Guard would hold is
blocked while enforcing." and "The enabled plugin enforces by default …
Advisory mode still blocks Action Guard's hard-block verdicts and recognised
calls that would change the guard's own state or config."

`TestClaim18HermesPlane` fires the real policy module with a real verdict
shape and asserts the Hermes hook decision. `TestClaim18OutageRecognition`
registers the real plugin (`register()` → `pre_tool_call`) with ONLY the API
client stubbed unreachable, so a command string is recognised by the real
fallback recognisers and carried through the real wiring to the decision.
`npm test` never loads this plane; CI runs these with
`python3 -m unittest discover -s plugins/hermes/shieldcortex/tests`.
"""
import os
import shutil
import sys
import tempfile
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

    def test_api_unreachable_flag_handling_is_bounded(self):
        # "While the API is unreachable, its bounded fallback scan blocks the
        # self-protection and catastrophic shapes it recognises in every mode,
        # and recognised dangerous shapes while enforcing."
        # This row proves the POLICY's handling of the three recogniser flags
        # only. Recognition of real command strings, and the wiring that turns
        # a match into these flags, is proven by TestClaim18OutageRecognition.
        down = ActionGuardVerdict("allow", [], "unreachable", available=False)
        self.assertTrue(_blocked(action_guard_decision(down, enforce=False, fallback_blocked=True)))
        self.assertTrue(_blocked(action_guard_decision(down, enforce=False, fallback_self_protected=True)))
        self.assertTrue(_blocked(action_guard_decision(down, enforce=True, fallback_dangerous=True)))
        self.assertIsNone(action_guard_decision(down, enforce=False, fallback_dangerous=True))
        # Nothing recognised: fail open, so a down scanner does not wedge normal work.
        self.assertIsNone(action_guard_decision(down, enforce=True))


class TestClaim18OutageRecognition(unittest.TestCase):
    """Claim 18, API-down half, through the real plugin wiring.

    `register()` is the real entrypoint; `pre_tool_call` is the real hook. The
    one stub is `evaluate_tool_call`, replaced with a function that returns the
    `available=False` verdict a dead local API produces — the recognisers and
    the policy are untouched. One representative `terminal` command per tier
    drives the three command recognisers (`fallback_catastrophic_match`,
    `fallback_self_protection_match`, `fallback_dangerous_match`); removing one
    of those, or disconnecting it from the decision, fails the matching test
    here, which the flag-handling row above could not see. Each recognition
    test also asserts the stub was the path taken for that very call.

    Not driven here: the #505 tool-write target branch
    (`fallback_write_target_match`, a Write/Edit whose path is a startup file);
    its own cases live in `test_self_protection_floor.py`. The full shape
    matrices (wrappers, quoting, posture spellings, lock paths) are proven in
    `test_self_protection_floor.py`, `test_fallback_regex_bounds.py` and
    `test_client_policy.py`, not re-proven here.
    """

    CATASTROPHIC = "rm -rf /"
    SELF_PROTECTION = "shieldcortex config --action-guard-disable"
    DANGEROUS = "sudo systemctl stop nginx"
    BENIGN = ("ls -la", "git status")

    def setUp(self):
        pkg_parent = str(Path(__file__).resolve().parents[2])
        if pkg_parent not in sys.path:
            sys.path.insert(0, pkg_parent)
        import shieldcortex as plugin  # the real package, as Hermes loads it

        self.plugin = plugin
        self.home = tempfile.mkdtemp(prefix="sc-hermes-claim18-")
        self.saved = {k: os.environ.get(k) for k in ("HOME", "SHIELDCORTEX_CONFIG_DIR", "SHIELDCORTEX_ENFORCE")}
        # The posture reporter writes under the config dir; keep it off the
        # operator's real ~/.shieldcortex.
        os.environ["HOME"] = self.home
        os.environ["SHIELDCORTEX_CONFIG_DIR"] = os.path.join(self.home, ".shieldcortex")
        self.calls = []
        down = ActionGuardVerdict("allow", [], "scanner unavailable", available=False)

        def unreachable(tool_name, args, *_a, **_k):
            self.calls.append((tool_name, args))
            return down

        self.orig_evaluate = plugin.evaluate_tool_call
        plugin.evaluate_tool_call = unreachable

    def tearDown(self):
        self.plugin.evaluate_tool_call = self.orig_evaluate
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.home, ignore_errors=True)

    def _hook(self, enforce_env):
        """Register the real plugin under a posture and return its pre_tool_call."""
        if enforce_env is None:
            os.environ.pop("SHIELDCORTEX_ENFORCE", None)  # shipped default: enforce
        else:
            os.environ["SHIELDCORTEX_ENFORCE"] = enforce_env
        hooks = {}

        class Ctx:
            def register_hook(self, name, fn):
                hooks[name] = fn

        self.plugin.register(Ctx())
        return hooks["pre_tool_call"]

    def _postures(self):
        # (label, SHIELDCORTEX_ENFORCE, enforcing?) — the shipped default and the explicit opt-out.
        return (("enforcing (default)", None, True), ("advisory", "0", False))

    def _decide(self, hook, command, label):
        """Run one real `pre_tool_call` and prove the outage path was taken for
        THIS call: the stubbed client recorded exactly this tool and args, so the
        decision came from the fallback recognisers, not from a live verdict."""
        before = len(self.calls)
        d = hook("terminal", {"command": command})
        self.assertEqual(self.calls[before:], [("terminal", {"command": command})], label)
        return d

    def test_recognised_catastrophic_command_is_blocked_in_both_postures(self):
        for label, env, _ in self._postures():
            d = self._decide(self._hook(env), self.CATASTROPHIC, label)
            self.assertTrue(_blocked(d), label)
            self.assertIn("catastrophic pattern", d["message"], label)

    def test_recognised_self_protection_command_is_blocked_in_both_postures(self):
        for label, env, _ in self._postures():
            d = self._decide(self._hook(env), self.SELF_PROTECTION, label)
            self.assertTrue(_blocked(d), label)
            self.assertIn("guard's own state or config", d["message"], label)

    def test_recognised_dangerous_command_is_blocked_only_while_enforcing(self):
        for label, env, enforcing in self._postures():
            d = self._decide(self._hook(env), self.DANGEROUS, label)
            if enforcing:
                self.assertTrue(_blocked(d), label)
                self.assertIn("dangerous pattern", d["message"], label)
            else:
                self.assertIsNone(d, label)

    def test_unrecognised_command_fails_open_in_both_postures(self):
        # Bounded: a down scanner never wedges ordinary work.
        for label, env, _ in self._postures():
            hook = self._hook(env)
            for cmd in self.BENIGN:
                self.assertIsNone(self._decide(hook, cmd, f"{label}: {cmd}"), f"{label}: {cmd}")

    def test_a_stub_that_never_fires_is_caught(self):
        # The per-call check in _decide is itself load-bearing: a hook that
        # bypassed the client would leave `calls` empty and fail there.
        hook = self._hook(None)
        self.assertEqual(self.calls, [])
        self._decide(hook, self.CATASTROPHIC, "first call")
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
