#!/usr/bin/env python3
"""Tests for approval_policy_check.py. Stdlib only: python3 -m unittest -v test_approval_policy_check
Fixture cases live in fixtures/cases.json; each names its inputs and the expected state plus
substrings that must appear in the reasons."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import approval_policy_check as apc  # noqa: E402

POLICY = os.path.join(HERE, "fixtures", "policy-basic.yml")
HEAD = "a" * 40
OLD = "b" * 40


def base_case():
    return {
        "pr": {"number": 7, "head_sha": HEAD, "title": "fix: thing", "state": "open", "draft": False,
               "labels": [], "changed_files": 1, "author": "lane-bot"},
        "files": [{"filename": "src/app.ts", "patch": "+x"}],
        "reviews": [],
        "comments": [{"user": "lane-bot", "created_at": "2026-11-28T10:00:00Z",
                      "body": "REVIEW head %s | sol: APPROVE | reports: r/7-sol.md" % HEAD}],
        "checks": [{"name": "test", "status": "completed", "conclusion": "success"}],
        "statuses": [],
    }


def run(case, policy=None):
    p = policy or apc.load_policy(POLICY)
    return apc.evaluate(p, case["pr"], case["files"], case["reviews"], case["comments"],
                        case["checks"], case["statuses"])


def apply_patch(case, patch):
    c = copy.deepcopy(case)
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(c.get(k), dict):
            c[k].update(v)
        else:
            c[k] = v
    if "files" in patch and "changed_files" not in patch.get("pr", {}):
        c["pr"]["changed_files"] = len(c["files"])
    return c


class FixtureCases(unittest.TestCase):
    def test_cases_json(self):
        with open(os.path.join(HERE, "fixtures", "cases.json"), encoding="utf-8") as f:
            cases = json.load(f)
        self.assertGreater(len(cases), 15)
        for case in cases:
            with self.subTest(case["name"]):
                body = json.loads(json.dumps(apply_patch(base_case(), case.get("patch", {})))
                                  .replace("<HEAD>", HEAD).replace("<OLD>", OLD))
                res = run(body)
                self.assertEqual(res["state"], case["expect"], "%s: %s" % (case["name"], res["reasons"]))
                joined = " | ".join(res["reasons"])
                for needle in case.get("reasons_contain", []):
                    self.assertIn(needle, joined, case["name"])
                for cls in case.get("classes", []):
                    self.assertIn(cls, res["classes"], case["name"])


class ParserFailsClosed(unittest.TestCase):
    def bad(self, text, needle=None):
        with self.assertRaises(apc.PolicyError) as cm:
            apc.validate_policy(apc.parse_yaml_subset(text))
        if needle:
            self.assertIn(needle, str(cm.exception))

    def good_text(self):
        with open(POLICY, encoding="utf-8") as f:
            return f.read()

    def test_good_policy_parses(self):
        p = apc.validate_policy(apc.parse_yaml_subset(self.good_text()))
        self.assertEqual([c["name"] for c in p["classes"]][-1], "default")

    def test_tabs_rejected(self):
        self.bad(self.good_text().replace("  owner: [owner-login]", "\towner: [owner-login]"), "tabs")

    def test_unknown_top_key(self):
        self.bad(self.good_text() + "\nautomerge: true\n", "unknown top-level")

    def test_unknown_requirement(self):
        self.bad(self.good_text().replace("      owner: true", "      owner: true\n      skip: true"), "unknown requirement")

    def test_unknown_seat(self):
        self.bad(self.good_text().replace("seats: [sol]\n", "seats: [grok]\n"), "unknown seat")

    def test_ci_cannot_be_switched_off(self):
        self.bad(self.good_text().replace("      any_seats: 1", "      any_seats: 1\n      ci: false"), "ci cannot")

    def test_class_must_require_something(self):
        self.bad(self.good_text().replace("      any_seats: 1", "      fable: true"), "must require")

    def test_alias_and_anchor_rejected(self):
        self.bad(self.good_text().replace("lane: test0000", "lane: &x test0000"), "unsupported")

    def test_yes_no_ambiguous(self):
        self.bad(self.good_text().replace("fleet_stand_in: true", "fleet_stand_in: yes"), "ambiguous")

    def test_duplicate_key(self):
        self.bad(self.good_text() + "version: 1\n", "duplicate")

    def test_bad_version(self):
        self.bad(self.good_text().replace("version: 1", "version: 2"), "version")

    def test_bad_indent(self):
        self.bad(self.good_text().replace("  lane: [lane-bot]", "   lane: [lane-bot]"))

    def test_empty(self):
        self.bad("# nothing\n", "empty")

    def test_block_scalar_rejected(self):
        self.bad(self.good_text().replace('purpose: "Existing lane rule: Sol plus green CI."', "purpose: |"))

    def test_bad_regex(self):
        self.bad(self.good_text().replace("titles: ['^release\\b']", "titles: ['(']"), "bad regex")

    def test_default_class_must_exist(self):
        self.bad(self.good_text().replace("default_class: default", "default_class: nope"), "default_class")


class FailClosedEvaluation(unittest.TestCase):
    def test_unclassified_path_without_default(self):
        p = apc.load_policy(POLICY)
        p["classes"] = [c for c in p["classes"] if c["name"] != "default"]
        p.pop("default_class")
        res = run(base_case(), p)
        self.assertEqual(res["state"], "failure")
        self.assertIn("unclassified path: src/app.ts", res["reasons"])

    def test_cli_policy_error_is_failure(self):
        with tempfile.TemporaryDirectory() as d:
            pol = os.path.join(d, "p.yml")
            with open(pol, "w") as f:
                f.write("version: 1\nrepo: [broken\n")
            fx = os.path.join(d, "fx.json")
            with open(fx, "w") as f:
                json.dump(base_case(), f)
            r = subprocess.run([sys.executable, os.path.join(HERE, "approval_policy_check.py"),
                                "--fixture", fx, "--policy", pol], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("policy error", r.stdout)
            r = subprocess.run([sys.executable, os.path.join(HERE, "approval_policy_check.py"),
                                "--validate", pol], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)

    def test_cli_fixture_success(self):
        with tempfile.TemporaryDirectory() as d:
            fx = os.path.join(d, "fx.json")
            with open(fx, "w") as f:
                json.dump(base_case(), f)
            r = subprocess.run([sys.executable, os.path.join(HERE, "approval_policy_check.py"),
                                "--fixture", fx, "--policy", POLICY], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout)

    def test_description_fits_status_limit(self):
        c = apply_patch(base_case(), {"files": [{"filename": "f%d/x.ts" % i} for i in range(1)],
                                       "comments": [], "checks": []})
        res = run(c)
        self.assertLessEqual(len(apc.describe(res)), 140)


class Globs(unittest.TestCase):
    def m(self, pat, path):
        return bool(apc.glob_to_regex(pat).match(path))

    def test_globs(self):
        self.assertTrue(self.m("**/*.md", "README.md"))
        self.assertTrue(self.m("**/*.md", "a/b/c.md"))
        self.assertTrue(self.m(".github/**", ".github/workflows/ci.yml"))
        self.assertFalse(self.m(".github/**", "x/.github/workflows/ci.yml"))
        self.assertTrue(self.m("CODEOWNERS", "docs/CODEOWNERS"))
        self.assertTrue(self.m("/CLAUDE.md", "CLAUDE.md"))
        self.assertFalse(self.m("/CLAUDE.md", "pkg/CLAUDE.md"))
        self.assertTrue(self.m("src/auth/**", "src/auth/a/b.ts"))
        self.assertFalse(self.m("src/auth/**", "src/authx/b.ts"))
        self.assertTrue(self.m("**/*crypto*", "src/lib/webcrypto.ts"))
        self.assertTrue(self.m("lefthook*", "lefthook.yml"))


if __name__ == "__main__":
    unittest.main()
