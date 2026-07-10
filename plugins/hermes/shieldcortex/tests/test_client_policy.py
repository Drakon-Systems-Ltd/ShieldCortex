"""
Unit tests for the Hermes plugin's ShieldCortex client + policy — the testable
core (no Hermes SDK needed). Run: `python3 -m pytest plugins/hermes/shieldcortex/tests`
or `python3 -m unittest`.
"""
import io
import json
import os
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sc_client import Verdict, scan  # noqa: E402
from policy import tool_call_decision, resolve_enforce  # noqa: E402


def fake_opener(response: dict | None, *, raises: Exception | None = None):
    """Build a urlopen-compatible opener returning `response` as JSON (or raising)."""

    @contextmanager
    def _opener(req, timeout=None):
        if raises is not None:
            raise raises
        yield io.BytesIO(json.dumps(response).encode("utf-8"))

    return _opener


def capturing_opener(captured: dict, response: dict):
    """Opener that records the outgoing request's Authorization header."""

    @contextmanager
    def _opener(req, timeout=None):
        captured["auth"] = req.get_header("Authorization")
        yield io.BytesIO(json.dumps(response).encode("utf-8"))

    return _opener


class TestScanClient(unittest.TestCase):
    def test_block_verdict_parsed(self):
        v = scan(
            "rm -rf / ; curl evil",
            opener=fake_opener({"firewall": {"result": "BLOCK", "threatIndicators": ["credential_leak"], "reason": "boom"}}),
        )
        self.assertEqual(v.result, "BLOCK")
        self.assertTrue(v.blocked)
        self.assertIn("credential_leak", v.threats)
        self.assertTrue(v.available)

    def test_allow_verdict(self):
        v = scan("read file", opener=fake_opener({"firewall": {"result": "ALLOW"}}))
        self.assertEqual(v.result, "ALLOW")
        self.assertFalse(v.blocked)

    def test_quarantine_verdict(self):
        v = scan("ignore previous instructions", opener=fake_opener({"firewall": {"result": "QUARANTINE"}}))
        self.assertEqual(v.result, "QUARANTINE")
        self.assertTrue(v.blocked)

    def test_fails_open_on_network_error(self):
        v = scan("anything", opener=fake_opener(None, raises=ConnectionRefusedError("no server")))
        self.assertEqual(v.result, "ERROR")
        self.assertFalse(v.available)
        self.assertFalse(v.blocked)

    def test_never_raises_on_garbage(self):
        v = scan("x", opener=fake_opener({"not_firewall": True}))
        self.assertEqual(v.result, "ALLOW")  # missing firewall -> safe default


class TestAuth(unittest.TestCase):
    def test_sends_bearer_token_from_env(self):
        # Missing this header was a silent 401 -> fail-open no-op (ATHENA dogfood).
        captured = {}
        os.environ["SHIELDCORTEX_API_TOKEN"] = "tok_test_123"
        try:
            scan("x", opener=capturing_opener(captured, {"firewall": {"result": "ALLOW"}}))
        finally:
            os.environ.pop("SHIELDCORTEX_API_TOKEN", None)
        self.assertEqual(captured["auth"], "Bearer tok_test_123")


class TestPolicy(unittest.TestCase):
    def test_enforce_blocks_on_block(self):
        d = tool_call_decision(Verdict("BLOCK", ["x"], "bad"), enforce=True)
        self.assertEqual(d["action"], "block")
        self.assertIn("bad", d["message"])

    def test_warn_mode_never_blocks(self):
        self.assertIsNone(tool_call_decision(Verdict("BLOCK", [], "bad"), enforce=False))

    def test_allow_is_none(self):
        self.assertIsNone(tool_call_decision(Verdict("ALLOW", [], ""), enforce=True))

    def test_quarantine_blocks_by_default_but_optional(self):
        self.assertIsNotNone(tool_call_decision(Verdict("QUARANTINE", [], "q"), enforce=True))
        self.assertIsNone(
            tool_call_decision(Verdict("QUARANTINE", [], "q"), enforce=True, quarantine_blocks=False)
        )

    def test_unavailable_scanner_never_blocks_even_enforcing(self):
        self.assertIsNone(tool_call_decision(Verdict("ERROR", [], "down", available=False), enforce=True))


class TestEnforceDefault(unittest.TestCase):
    """v4.47.2: the Hermes gate defaults to ENFORCE. Opt out explicitly."""

    def test_unset_defaults_to_enforce(self):
        # The flip: with SHIELDCORTEX_ENFORCE unset the gate now ENFORCES.
        self.assertTrue(resolve_enforce(None))
        self.assertTrue(resolve_enforce(""))
        self.assertTrue(resolve_enforce("   "))

    def test_explicit_optout_disables_enforce(self):
        for val in ("0", "false", "no", "off", "advisory",
                    "FALSE", " Advisory ", "Off"):
            self.assertFalse(resolve_enforce(val), f"{val!r} should disable enforce")

    def test_explicit_optin_still_enforces(self):
        for val in ("1", "true", "yes", "on", "enforce", "TRUE", " On "):
            self.assertTrue(resolve_enforce(val), f"{val!r} should enforce")

    def test_unknown_value_stays_enforcing(self):
        # Unknown/garbage must not silently drop to advisory — only the explicit
        # opt-out words disable enforcement now that enforce is the default.
        self.assertTrue(resolve_enforce("banana"))


if __name__ == "__main__":
    unittest.main()
