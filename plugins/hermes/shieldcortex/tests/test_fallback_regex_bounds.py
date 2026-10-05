"""
#509 r7 (PR #610 review): the two r5/r6 self-protection rows of the Hermes
outage fallback backtracked quadratically on long non-matching input — 136 KB
took 13.8 s through fallback_self_protection_match. Every gap between an
anchor and the required literal is now bounded, so 100 KiB of padding, in the
shapes that used to be pathological, must complete in under 50 ms per row.

The measurement runs in a CHILD interpreter with a timeout: a regression here
is a multi-minute hang, not a slow test, and unittest has no per-test clock.
"""
import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAD = 100 * 1024
BUDGET_MS = 50.0
VERB_ROW = "(?:mv|cp|rm|rmdir|rsync|ln|install)"
CD_ROW = "(?:cd|pushd)"


def shapes():
    sc = "~/." + "shieldcortex"
    return {
        "newlines": "\n" * PAD,
        "cd+newlines": f"cd {sc}\n" + "\n" * PAD,
        "newlines+assignments": "\n" * (PAD // 2) + "A=b " * (PAD // 8),
        "paren-verb-spam": "(mv " * (PAD // 4),
        "cd+paren-verb-spam": f"cd {sc}\n" + "(mv " * (PAD // 4),
        "words": "a " * (PAD // 2),
        "verb+words": "mv " + "a " * (PAD // 2),
        "cd+words": f"cd {sc}; " + "a " * (PAD // 2),
        "spaces": " " * PAD,
        "semicolons": ";" * PAD,
    }


def measure():
    """Min-of-3 wall time, in ms, of each bounded row and of the whole matcher
    on every shape. Importable from the Jest parity suite too."""
    sys.path.insert(0, str(HERE.parent))
    from sc_client import _FALLBACK_SELF_PROTECTION, fallback_self_protection_match

    rows = {}
    for pattern, _lock in _FALLBACK_SELF_PROTECTION:
        if VERB_ROW in pattern.pattern:
            rows["r6-cd" if CD_ROW in pattern.pattern else "r5-verb"] = pattern
    assert set(rows) == {"r5-verb", "r6-cd"}, sorted(rows)

    def best(fn):
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            hit = fn()
            times.append((time.perf_counter() - t0) * 1000)
        return round(min(times), 2), hit

    out = {}
    for name, text in shapes().items():
        out[name] = {}
        for label, pattern in rows.items():
            out[name][label] = best(lambda: pattern.search(text) is not None)
        out[name]["all-rows"] = best(lambda: fallback_self_protection_match(text))
    return out


class OutageFallbackRegexBounds(unittest.TestCase):
    def test_bounded_rows_stay_under_budget_on_100kib_padding(self):
        child = subprocess.run(
            [sys.executable, "-c",
             "import json, sys; sys.path.insert(0, sys.argv[1]); "
             "import test_fallback_regex_bounds as t; print(json.dumps(t.measure()))",
             str(HERE)],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout.strip().splitlines()[-1])
        self.assertEqual(set(result), set(shapes()))
        for name, timings in result.items():
            for label in ("r5-verb", "r6-cd"):
                ms, hit = timings[label]
                self.assertFalse(hit, f"{name}: padding must not match {label}")
                self.assertLess(ms, BUDGET_MS, f"{name}: {label} took {ms} ms")
            # The whole matcher is ten more rows of plain CPython `re` cost; it
            # is held to an order of magnitude, which a regression still fails.
            ms, hit = timings["all-rows"]
            self.assertFalse(hit, name)
            self.assertLess(ms, BUDGET_MS * 10, f"{name}: all rows took {ms} ms")

    def test_bounded_rows_still_fire_on_the_shapes_they_exist_for(self):
        sys.path.insert(0, str(HERE.parent))
        from sc_client import fallback_self_protection_match

        sc = "~/." + "shieldcortex"
        for cmd in (
            f"mv {sc} /tmp/x",
            f'sudo mv "$HOME/.shieldcortex/" /tmp/x',
            f"cp -r /tmp/forged/. {sc}/",
            # A blank-padded line after a separator: the `\\n` is the anchor and
            # the blanks after it are the (newline-free) gap.
            f"true\n\n    mv {sc} /tmp/x",
            f"cd {sc}; printf x > approvals/y",
            f"cd {sc} && echo {{}} > config.json",
            f"cd {sc}; mv * /tmp/x",
            f"cd {sc}\n\n   mv ./* /tmp/x",
        ):
            self.assertTrue(fallback_self_protection_match(cmd), cmd)
        for cmd in ("ls -la", f'echo "rm {sc}"', "cd /tmp/build && mv ./* /tmp/out"):
            self.assertFalse(fallback_self_protection_match(cmd), cmd)


if __name__ == "__main__":
    unittest.main()
