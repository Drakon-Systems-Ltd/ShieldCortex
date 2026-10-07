"""
#613 — the Hermes plugin's process-side posture self-report.

The plugin process is the only place that knows whether the gate loaded and
what `SHIELDCORTEX_ENFORCE` resolved to, so it writes a small versioned file
the CLI reads. The report is best-effort by contract:

* written atomically (temp + rename), mode 0600, bounded in size;
* NEVER raises into register() or pre_tool_call;
* NEVER changes an allow / block decision, even when writing fails.

Every test points SHIELDCORTEX_CONFIG_DIR at a temp dir; nothing here writes
to the real home.
"""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import shieldcortex  # noqa: E402
from shieldcortex import posture  # noqa: E402
from shieldcortex.sc_client import ActionGuardVerdict  # noqa: E402

SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
REQUIRED_KEYS = {
    "schema", "version", "runtime", "profile", "plane", "instance", "runtime_version", "plugin",
    "heartbeat_at", "loaded", "configured_posture", "scanner", "policy_hash", "degraded_intervals", "denials",
}
DENIAL_KEYS = {"at", "tested_path", "instance", "plugin_hash", "policy_hash", "configured_posture"}


class FakeCtx:
    def __init__(self):
        self.hooks = {}

    def register_hook(self, name, fn):
        self.hooks[name] = fn


class PostureCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.config_dir = os.path.join(self._tmp.name, ".shieldcortex")
        env = {"SHIELDCORTEX_CONFIG_DIR": self.config_dir, "HOME": self._tmp.name}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("SHIELDCORTEX_ENFORCE", None)
        os.environ.pop("HERMES_HOME", None)

    def report_path(self, profile="default"):
        return posture.report_path(self.config_dir, profile)

    def read_report(self, profile="default"):
        with open(self.report_path(profile), encoding="utf-8") as fh:
            return json.load(fh)


class WriterTests(PostureCase):
    def test_writes_the_v1_schema(self):
        self.assertTrue(posture.write_self_report(
            self.config_dir, profile="default", configured_posture="enforce",
            scanner="available", policy={"enforce": True}))
        r = self.read_report()
        self.assertEqual(set(r), REQUIRED_KEYS)
        self.assertEqual(r["schema"], posture.SCHEMA)
        self.assertEqual(r["version"], 1)
        self.assertEqual(r["runtime"], "hermes")
        self.assertEqual(r["plane"], "tool-gate")
        self.assertIs(r["loaded"], True)
        self.assertRegex(r["policy_hash"], SHA)
        self.assertRegex(r["plugin"]["hash"], SHA)
        self.assertEqual(r["instance"]["liveness"], "process")
        self.assertEqual(r["instance"]["pid"], os.getpid())
        self.assertEqual(os.path.basename(self.report_path()), r["instance"]["key"] + ".json")
        self.assertEqual(r["denials"], {"blocked_action": None, "synthetic_probe": None, "blocked_action_count": 0})

    def test_atomic_private_and_bounded(self):
        posture.write_self_report(
            self.config_dir, profile="default", configured_posture="enforce",
            scanner="degraded", degraded_reason="x" * 10_000)
        d = os.path.dirname(self.report_path())
        self.assertEqual(os.listdir(d), [os.path.basename(self.report_path())])
        self.assertEqual(os.stat(self.report_path()).st_mode & 0o077, 0)
        for directory in (d, os.path.dirname(d), os.path.dirname(os.path.dirname(d))):
            self.assertEqual(os.stat(directory).st_mode & 0o077, 0)
        self.assertLessEqual(os.path.getsize(self.report_path()), posture.MAX_BYTES)
        r = self.read_report()
        self.assertLessEqual(len(r["degraded_intervals"][0]["reason"]), 120)

    def test_never_raises_when_the_directory_is_unwritable(self):
        os.makedirs(self.config_dir)
        with open(os.path.join(self.config_dir, "posture"), "w") as fh:
            fh.write("a file, not a dir")
        self.assertFalse(posture.write_self_report(
            self.config_dir, profile="default", configured_posture="enforce"))

    def test_rejects_values_outside_the_closed_sets(self):
        self.assertFalse(posture.write_self_report(
            self.config_dir, profile="default", configured_posture="enforced"))
        self.assertFalse(os.path.exists(self.report_path()))

    def test_profile_from_hermes_home(self):
        self.assertEqual(posture.profile_id(None), "default")
        self.assertEqual(posture.profile_id("/home/u/.hermes"), "default")
        self.assertEqual(posture.profile_id("/home/u/.hermes/profiles/Work"), "work")
        self.assertEqual(posture.profile_id("/home/u/.hermes/profiles/../../etc"), "default")

    def test_heartbeat_never_refreshes_a_denial(self):
        posture.write_self_report(self.config_dir, profile="default", configured_posture="enforce",
                                  scanner="available", policy={"enforce": True}, denial=True,
                                  denial_path="pre_tool_call:terminal", now=1_790_000_000.0)
        posture.write_self_report(self.config_dir, profile="default", configured_posture="enforce",
                                  scanner="available", policy={"enforce": True}, now=1_790_000_600.0)
        r = self.read_report()
        self.assertEqual(set(r["denials"]["blocked_action"]), DENIAL_KEYS)
        self.assertEqual(r["denials"]["blocked_action"]["at"], posture._iso(1_790_000_000.0))
        self.assertEqual(r["heartbeat_at"], posture._iso(1_790_000_600.0))
        self.assertNotEqual(r["heartbeat_at"], r["denials"]["blocked_action"]["at"])
        self.assertEqual(r["denials"]["blocked_action"]["tested_path"], "pre_tool_call:terminal")
        self.assertEqual(r["denials"]["blocked_action_count"], 1)

    def test_probe_is_separate_and_never_counted(self):
        posture.write_self_report(self.config_dir, profile="default", configured_posture="enforce",
                                  scanner="available", denial=True, denial_kind="synthetic-probe",
                                  denial_path="probe:terminal")
        r = self.read_report()
        self.assertIsNone(r["denials"]["blocked_action"])
        self.assertEqual(r["denials"]["synthetic_probe"]["tested_path"], "probe:terminal")
        self.assertEqual(r["denials"]["blocked_action_count"], 0)

    def test_a_denial_from_another_instance_is_never_carried_forward(self):
        posture.write_self_report(self.config_dir, profile="default", configured_posture="enforce",
                                  scanner="available", denial=True)
        path = self.report_path()
        with open(path, encoding="utf-8") as fh:
            body = json.load(fh)
        body["denials"]["blocked_action"]["instance"] = "p1-s1"
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        posture.write_self_report(self.config_dir, profile="default", configured_posture="enforce",
                                  scanner="available")
        self.assertIsNone(self.read_report()["denials"]["blocked_action"])

    def test_open_interval_closes_when_scanner_recovers(self):
        posture.write_self_report(self.config_dir, profile="default",
                                  configured_posture="enforce", scanner="degraded",
                                  degraded_reason="scanner-unreachable")
        posture.write_self_report(self.config_dir, profile="default",
                                  configured_posture="enforce", scanner="available")
        r = self.read_report()
        self.assertEqual(len(r["degraded_intervals"]), 1)
        self.assertIsNotNone(r["degraded_intervals"][0]["to"])


class RegisterTests(PostureCase):
    def test_register_reports_loaded_enforce(self):
        ctx = FakeCtx()
        shieldcortex.register(ctx)
        r = self.read_report()
        self.assertIs(r["loaded"], True)
        self.assertEqual(r["configured_posture"], "enforce")

    def test_register_reports_advisory_on_opt_out(self):
        os.environ["SHIELDCORTEX_ENFORCE"] = "0"
        shieldcortex.register(FakeCtx())
        self.assertEqual(self.read_report()["configured_posture"], "advisory")

    def test_register_reports_the_hermes_profile(self):
        os.environ["HERMES_HOME"] = os.path.join(self._tmp.name, ".hermes", "profiles", "ops")
        shieldcortex.register(FakeCtx())
        self.assertEqual(self.read_report("ops")["profile"], "ops")

    def test_register_survives_a_writer_that_raises(self):
        ctx = FakeCtx()
        with mock.patch.object(posture, "write_self_report", side_effect=RuntimeError("boom")):
            result = shieldcortex.register(ctx)
        self.assertIn("pre_tool_call", ctx.hooks)
        self.assertEqual(result["name"], "shieldcortex")

    def test_denial_is_recorded(self):
        ctx = FakeCtx()
        shieldcortex.register(ctx)
        block = ActionGuardVerdict("block", ["x"], "no")
        with mock.patch.object(shieldcortex, "evaluate_tool_call", return_value=block):
            out = ctx.hooks["pre_tool_call"]("terminal", {"command": "whatever"})
        self.assertEqual(out["action"], "block")
        denied = self.read_report()["denials"]["blocked_action"]
        self.assertEqual(denied["tested_path"], "pre_tool_call:terminal")
        self.assertEqual(denied["configured_posture"], "enforce")


VERDICTS = [
    ActionGuardVerdict("allow", []),
    ActionGuardVerdict("block", ["x"], "nope"),
    ActionGuardVerdict("require_approval", ["y"], "ask"),
    ActionGuardVerdict("allow", [], "down", available=False),
]


class DecisionInvarianceTests(PostureCase):
    """A self-report failure must never change an allow / deny decision."""

    def decisions(self, enforce_env=None):
        if enforce_env is not None:
            os.environ["SHIELDCORTEX_ENFORCE"] = enforce_env
        ctx = FakeCtx()
        shieldcortex.register(ctx)
        out = []
        for v in VERDICTS:
            with mock.patch.object(shieldcortex, "evaluate_tool_call", return_value=v):
                with mock.patch.object(shieldcortex, "_audit_gate_degraded"):
                    out.append(ctx.hooks["pre_tool_call"]("terminal", {"command": "crontab -e"}))
        return out

    def test_identical_with_the_writer_raising(self):
        normal = self.decisions()
        with mock.patch.object(posture, "write_self_report", side_effect=OSError("disk gone")):
            broken = self.decisions()
        self.assertEqual(normal, broken)
        self.assertTrue(any(d is None for d in normal))
        self.assertTrue(any(d is not None for d in normal))

    def test_identical_with_the_directory_blocked(self):
        normal = self.decisions()
        os.makedirs(self.config_dir, exist_ok=True)
        import shutil
        shutil.rmtree(os.path.join(self.config_dir, "posture"), ignore_errors=True)
        with open(os.path.join(self.config_dir, "posture"), "w") as fh:
            fh.write("blocked")
        blocked = self.decisions()
        self.assertEqual(normal, blocked)

    def test_identical_in_advisory(self):
        normal = self.decisions("0")
        with mock.patch.object(posture, "write_self_report", side_effect=OSError("x")):
            broken = self.decisions("0")
        self.assertEqual(normal, broken)


if __name__ == "__main__":
    unittest.main()
