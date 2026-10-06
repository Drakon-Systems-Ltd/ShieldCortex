"""
#509 r7/r8 (PR #610 review): the two r5/r6 self-protection rows of the Hermes
outage fallback.

r7: they backtracked quadratically on long non-matching input. Fixed by
excluding `\\n` from the blank run after a separator and stopping the argument
gap at `(`.

r8 (2026-10-05): r7 also put `{0,512}` / `{0,4096}` length bounds on the gaps.
The 512 bound let padding INSIDE the 4096-character scan cap hide a real match;
the 4096 bound is a no-op behind that cap. Both are gone. This suite holds, all
through the capped path production runs (fallback_surface ->
fallback_self_protection_match):

  1. LONG POSITIVES: a padded command inside the cap is still detected.
     Re-adding a numeric bound on the argument gap fails these.
  2. TIMING AT THE CAP: pathological padding, cut to the cap by
     fallback_surface itself, stays inside a budget.

The measurement runs in a CHILD interpreter with a timeout: a regression here
can be a long hang, and unittest has no per-test clock.
"""
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
CAP = 4096
PAD = 100 * 1024
# Measured at the cap (min-of-3, arm64 CPython 3.12): ~3 ms for every shape
# except the backtick-anchor run (~75 ms) and the repeated `cd` (~28 ms), which
# are still quadratic in the capped length. The r7 newline regression costs
# over a second at the cap, so this budget still fails it.
BUDGET_MS = 750.0
SC = "~/." + "shieldcortex"
RM = "r" + "m"


def pad_to(head, tail, length):
    """`head` + filler + `tail`, exactly `length` characters."""
    room = length - len(head) - len(tail)
    return head + "a " * (room // 2) + " " * (room % 2) + tail


def long_positives():
    """Padded guard-state access, all inside the cap. The first two are the
    review's reproductions; the list mirrors the Jest suite's, row for row."""
    return [
        ("verb, 30 repeated flags (772)", "mv " + "--strip-trailing-slashes " * 30 + ".shieldcortex moved"),
        ("verb, 300 padding tokens (622)", f"{RM} -rf " + "a " * 300 + SC),
        ("verb, target ends just under the cap (4090)", pad_to("mv ", f"{SC} /tmp/x", CAP - 6)),
        ("verb, target ends exactly at the cap (4096)", pad_to("mv ", SC, CAP)),
        ("cd, relative state write 3.6k later (3638)", f"cd {SC} && " + "echo hi; " * 400 + f"{RM} -rf approvals"),
        ("cd, state name ends exactly at the cap (4096)", pad_to(f"cd {SC}; ", " approvals", CAP)),
        ("cd, padded verb + glob just under the cap (4090)", pad_to(f"cd {SC}; mv ", "* /tmp/x", CAP - 6)),
    ]


def short_twins():
    return [
        "mv .shieldcortex moved",
        f"mv {SC} /tmp/x",
        'sudo mv "$HOME/.shieldcortex/" /tmp/x',
        f"cp -r /tmp/forged/. {SC}/",
        # A blank-padded line after a separator: the `\n` is the anchor and
        # the blanks after it are the (newline-free) gap.
        f"true\n\n    mv {SC} /tmp/x",
        f"cd {SC}; printf x > approvals/y",
        f"cd {SC} && echo {{}} > config.json",
        f"cd {SC}; mv * /tmp/x",
        f"cd {SC}\n\n   mv ./* /tmp/x",
    ]


def negatives():
    return [
        "ls -la", "cat notes.txt", f'echo "{RM} {SC}"', "cd /tmp/build && mv ./* /tmp/out",
        "mv a b && cd .shieldcortex-docs",
        # Padding alone is not a match, at any length inside the cap.
        "mv " + "--strip-trailing-slashes " * 30 + "notes moved",
        pad_to("mv ", "notes.txt", CAP),
        # A target that starts past the cap is not seen: the cap is the limit.
        pad_to("mv ", SC, CAP + len(SC) + 2),
    ]


def shapes():
    """Padding shapes, 100 KiB each; fallback_surface cuts them to the cap."""
    return {
        "newlines": "\n" * PAD,
        "cd+newlines": f"cd {SC}\n" + "\n" * PAD,
        "newlines+assignments": "\n" * (CAP // 2) + "A=b " * (PAD // 8),
        "paren-verb-spam": "(mv " * (PAD // 4),
        "cd+paren-verb-spam": f"cd {SC}\n" + "(mv " * (PAD // 4),
        "backtick-verb-spam": "`mv " * (PAD // 4),
        "semicolon-verb-spam": "; mv " * (PAD // 5),
        "cd-spam": f"cd {SC} " * (PAD // 16),
        "words": "a " * (PAD // 2),
        "verb+words": "mv " + "a " * (PAD // 2),
        "cd+words": f"cd {SC}; " + "a " * (PAD // 2),
        "spaces": " " * PAD,
        "semicolons": ";" * PAD,
    }


def report():
    """Detection and min-of-3 timing through the capped production path.
    Importable from the Jest suite too."""
    sys.path.insert(0, str(HERE.parent))
    from sc_client import fallback_self_protection_match, fallback_surface

    def capped(cmd):
        surface = fallback_surface({"command": cmd})
        assert len(surface) <= CAP, len(surface)
        return bool(fallback_self_protection_match(surface, "terminal"))

    def best(fn):
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            hit = fn()
            times.append((time.perf_counter() - t0) * 1000)
        return round(min(times), 2), hit

    return {
        "budget_ms": BUDGET_MS,
        "positives": [(name, len(cmd), capped(cmd)) for name, cmd in long_positives()]
        + [(cmd[:40], len(cmd), capped(cmd)) for cmd in short_twins()],
        "negatives": [(cmd[:40], len(cmd), capped(cmd)) for cmd in negatives()],
        "timings": {name: best(lambda: capped(text)) for name, text in shapes().items()},
    }


class OutageFallbackRegexBounds(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        child = subprocess.run(
            [sys.executable, "-c",
             "import json, sys; sys.path.insert(0, sys.argv[1]); "
             "import test_fallback_regex_bounds as t; print(json.dumps(t.report()))",
             str(HERE)],
            capture_output=True, text=True, timeout=120,
        )
        assert child.returncode == 0, child.stderr
        cls.result = json.loads(child.stdout.strip().splitlines()[-1])

    def test_long_positives_are_the_lengths_they_claim(self):
        self.assertEqual([len(c) for _, c in long_positives()], [772, 622, 4090, 4096, 3638, 4096, 4090])

    def test_padding_inside_the_cap_never_hides_a_match(self):
        self.assertEqual(len(self.result["positives"]), len(long_positives()) + len(short_twins()))
        for name, length, hit in self.result["positives"]:
            self.assertTrue(hit, f"{name} ({length} chars) must be on the self-protection floor")

    def test_padding_alone_and_lookalikes_stay_off_the_floor(self):
        self.assertEqual(len(self.result["negatives"]), len(negatives()))
        for name, length, hit in self.result["negatives"]:
            self.assertFalse(hit, f"{name} ({length} chars) must not match")

    def test_neither_gap_carries_a_length_bound(self):
        import re
        sys.path.insert(0, str(HERE.parent))
        from sc_client import _FALLBACK_SELF_PROTECTION

        rows = [p.pattern for p, _lock in _FALLBACK_SELF_PROTECTION if "(?:mv|cp|rm|rmdir|rsync|ln|install)" in p.pattern]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertIsNone(re.search(r"\{\d+,\d*\}", row), row)
            # The two r7 edits that fix the cost are still there.
            self.assertIn(r"[^\S\n]*", row)
            self.assertIn(r"[^;&|\n(]*?", row)

    def test_capped_path_stays_under_budget_on_pathological_padding(self):
        self.assertEqual(set(self.result["timings"]), set(shapes()))
        for name, (ms, hit) in self.result["timings"].items():
            self.assertFalse(hit, f"{name}: padding must not match")
            self.assertLess(ms, BUDGET_MS, f"{name}: took {ms} ms at the cap")


if __name__ == "__main__":
    unittest.main()
