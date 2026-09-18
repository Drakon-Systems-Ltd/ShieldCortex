# ShieldCortex #522 — Tars round-7 exact-head review, two blockers fixed

**Branch** `jarvis/501-policy-lock` · **Base at start** `1d2b7346` (Tars's exact
reviewed head, `1d2b7346f66a620d9887fd2454735db544f32bbd`)
**Date** 2026-09-18 · **Worktree** `~/sc-wt-501` · local only, nothing pushed
**Final commit** `3dcd5696`

## Starting state

`git status` showed 4 modified files (`CHANGELOG.md`, `README.md`,
`src/cli/__tests__/protect-501.test.ts`, `src/cli/protect.ts`) already
uncommitted in the worktree — a prior fix-lane session (per memory, restarted
after a worker died mid-queue) had already implemented both P1 and P2 findings
from Tars's round-7 review, including tests. I read the whole diff against
Tars's two findings before doing anything else, so this session's actual work
was: verify it, adversarially review it, fix what that review found, and
verify again before committing. Nothing here duplicates a prior retry — the
prior work is the base this session built on.

## The two blockers, as found already fixed

1. **Identity bug (P1).** `agentSeam()` used to compute `Number.parseInt(process.env.SUDO_UID ?? '', 10)`, falling back to `65534` ("nobody") whenever `SUDO_UID` was absent or invalid — exactly the state of a privileged run with no `SUDO_UID` (a system service, an already-privileged shell, or an unprivileged `--dry-run` in a directory with no world-writable ancestor). Judged as nobody, an agent-owned `0755` directory reads as "owned by another uid", so the destination falsely verified.
   Fix already in place: `resolveAgentUid()` — a new `--agent-uid <uid>` flag, else `SUDO_UID`, else (only when this process is itself unprivileged) its own `euid` — refuses with `code: 1` and writes/prints nothing when a privileged process has none of those, **including under `--dry-run`**.
2. **Config-silent-defaults bug (P2).** `--from-config` with a missing or corrupt `config.json` fell through to `raw = {}` and printed `"pinning defaults"`. An empty config maps to Action Guard `OFF`, so a privileged run silently froze the guard off under reassuring prose.
   Fix already in place: `readSourceConfig()` refuses, writing nothing, when the source is missing, unparseable, or not a JSON object — for both the real write and `--dry-run`, and strictly before the destination is even judged.

Both were covered by dedicated tests (`#522 r7 (Tars)` describe block), 71/71
green as found, including the exact macOS CI reproduction case ("an
unprivileged `--dry-run` with no `SUDO_UID` is judged as its own uid — the
macOS CI case").

## macOS CI failure — inspected read-only, confirmed as this bug, not a flake

`gh run view 35310595403 --job 105491648633` (token from 1Password item
`pdbx2uydknaqsfveq642gwr6ii`, field `7qqcsxhipaagfexc7gf2u55jnq` — no rerun
issued):

```
X macos-test in 7m3s (ID 105491648633)
  ✓ Build
  X Test
```

`gh run view --log-failed` isolates exactly one failing test in the whole
macOS run — `protect-501.test.ts`, `--dry-run reports whether the destination
would verify for the agent`:

```
Expected pattern: /would be REFUSED/
Received string:  "Pinning the safe posture; config.json is not read...
Would write /var/folders/36/tjdph2t965j8snz9_vkdnw0r0000gn/T/sc-501-protect-root-xpDeGF/policy.json...
```

`/var/folders/.../T/...` is macOS's per-user temp root — `0700`-ish, no
world-writable ancestor. The old code judged this unprivileged `--dry-run` as
`nobody` (no `SUDO_UID` set), and to `nobody` a SELF-owned root reads as
verifying — the false green the fix exists to close. The new "macOS CI case"
test reproduces this exact shape locally and passes under the fix. Run was 26
minutes old when inspected (fresh, not stale).

## Independent adversarial review, and what it found

Dispatched a second agent (no visibility into this session, told only the two
findings' descriptions and the file paths) to try to break the guarantees.
Confirmed intact: refusal-before-any-mutation/print ordering, the preflight→
write TOCTOU window (closed by `verifyProtectedDirectoryChain` refusing first,
the tmp-file `renameSync` not following a planted symlink), `resolveRootForProtect`
never reaching `running-as-root`, the `#209` alias-merge order in
`buildLockedPolicy`, the flag-less path never reading config.json, no `memory`
block pinned by default, and no other caller in the codebase (`grep` for
`runProtect`/`preflightLockDestination`/`resolveRootForProtect`/`agentSeam`/
`verifyAsAgent`/`resolveAgentUid` outside `protect.ts` itself and its test) —
the signature changes are self-contained.

It found two real gaps, both fixed in this session before commit:

1. **`SUDO_UID` outranked this process's own uid unconditionally**, even while
   this process was itself unprivileged. `SUDO_UID` names whoever *launched*
   the run, not necessarily this process — a launch targeted at a different
   account, or a value inherited from an unrelated earlier context, leaves it
   set on a process that is really someone else. Concretely, an operator
   previewing as a specific account while a differently-scoped `SUDO_UID`
   lingers in the environment got judged against that stale value instead of
   the account actually running. Writes were never at risk (the real write
   still separately requires `euid === 0`), but `--dry-run` could false-green
   exactly the way the P1 fix exists to prevent. **Fix**: this process's own
   `euid` now outranks `SUDO_UID` whenever this process is not itself
   elevated; `SUDO_UID` is consulted only in the one state where this process
   cannot answer for its own identity.
2. **`readSourceConfig` had no symlink guard and echoed the raw parser
   message** (new in this diff — the prior code swallowed the exception into
   a generic string). The source path is built from the *same account* whose
   config it is (`resolveSourceConfigPath`), so an unconditional
   `readFileSync` would follow a symlink planted at that path to any other
   file this elevated process can read — and `JSON.parse`'s own error message
   quotes back up to ~10 characters of whatever it actually read (confirmed:
   `JSON.parse('SECRETXYZ garbage')` → `"Unexpected token 'S', \"SECRETXYZ \"...
   is not valid JSON"` on this Node 24 runtime). Together: a route for a
   same-uid symlink to make a privileged `protect` run leak a content fragment
   of an arbitrary readable file to the operator's terminal. **Fix**: the
   source must be a plain, non-symlink file — checked with `lstat`, before it
   is ever opened — and the refusal text no longer repeats the parser's own
   message.

Nit noted, not fixed (informational only, doesn't affect either blocker): a
`--dry-run` whose preflight fails still returns `code: 0`, so `protect
--dry-run && protect` proceeds to the real (correctly refusing) run rather
than short-circuiting. Left alone — matches every other `--dry-run` exit code
in this file and the real run still refuses correctly.

## Delete-the-fix — all four behaviours, individually

Baseline before any revert: `protect-501.test.ts` 75/75 (71 as found + 4 added
by the code-review fixes).

| # | Reverted | Result | Restored |
|---|---|---|---|
| P1 | `resolveAgentUid`'s final branch made to return `{ok:true, uid:65534}` (the old nobody fallback) instead of refusing | **4 failed / 67 passed** — both P1 "refused" assertions, the null-euid unit test, and the dry-run-no-false-verify test | 75/75 |
| P2 | `readSourceConfig` reverted to `raw = {}` on any failure, generic "pinning defaults" line | **7 failed / 64 passed** — every P2 refusal case (missing/corrupt/non-object/dry-run) | 75/75 |
| review-1 | `SUDO_UID` branch moved back ahead of the own-`euid` branch | **3 failed / 72 passed** — the new stale-SUDO_UID unit test, the stale-SUDO_UID dry-run test, and (collaterally, from the marker text) the SUDO_UID positive control | 75/75 |
| review-2 | Symlink/regular-file guard removed from `readSourceConfig`, error message echo restored | **1 failed / 74 passed** initially — the symlink test caught it, but the *first* version of the message-leak test did not (see below) | 75/75 |

**The message-leak test needed a fix of its own first.** My first draft
asserted the *entire* string `'DEFINITELY-NOT-JSON-...'` did not appear in
the refusal text — but V8's `JSON.parse` truncates its quoted excerpt to
roughly 10 characters (`"DEFINITELY"...`, not the full string), so the
assertion never actually exercised the leak and passed even against the
reverted, vulnerable code. Verified the exact truncation behaviour directly
(`node -e "JSON.parse('SECRETXYZ garbage')"` → confirms a 9-character token
survives intact, a 12-character one is cut). Rewrote the test around a
9-character marker; re-ran delete-the-fix — now **2 failed / 73 passed**
against the reverted code (symlink test + the corrected leak test), restored
to 75/75. Left as a note for anyone who reads this: a leak-assertion against a
V8 error message has to know V8 truncates it, or it proves nothing.

## Verification

| Command | Result |
|---|---|
| `npx tsc -p tsconfig.build.json --noEmit` | clean |
| `npx tsc -p tsconfig.openclaw-plugin.json --noEmit` | clean |
| `npm run build` (`build:ts` + dashboard) | exit 0 |
| `npm test` (`scripts/run-jest.mjs`, builds `dist` first) | **566/566 suites, 9075/9087 tests passed (7 skipped, 5 todo — pre-existing, unrelated)** |
| `npm run test:dist` | `OK: no ESM-unsafe require() in dist.` |
| Four targeted suites alone (`protect-501`, `policy-lock-dist-regression-501`, `enforcement-surface-parity`, `protected-root-501`) | **172/172** |

A bare `npx tsc --noEmit` against the root `tsconfig.json` reports ~40
pre-existing errors across unrelated files (`benchmark/` imports outside
`rootDir`, `.mjs` modules without declarations, `src/setup/__tests__` and
`src/integrations/__tests__` type mismatches, etc.) — none mention `protect`,
none touched here, not the project's real typecheck path (`build:ts` uses
`tsconfig.build.json` + `tsconfig.openclaw-plugin.json`, both clean, matching
the round-6 report's note on the same pre-existing gap).

## Preserved (checked, not re-litigated)

- `#209` reviewedScripts canonical+alias merge order in `buildLockedPolicy` (`{...alias, ...guardTop}`, top-level wins) — unchanged, covered by the still-green `enforcement-surface-parity` and `policy-lock-dist-regression-501` suites.
- Flag-less `protect` pins the fixed `balanced`-floor safe posture and never opens `config.json` — `buildLockedPolicy`'s early `if (!opts.fromConfig) return safeDefaultPolicy();` is untouched by this diff.
- `memory` is omitted from the default posture (`safeDefaultPolicy()` has no `memory` key) — unchanged.
- Both CHANGELOG bullet sets from round-6 (items 1–3) are untouched context in this diff — only two new bullets were appended for r7, plus two more for the code-review hardening.
- The documented #189 residual (a verified lock's permitted reviewed entry still skips that file's body ahead of the catastrophic scan) — untouched, still named in the round-6 CHANGELOG bullet this diff did not touch.

## Gap noted, not fixed (documentation drift, out of scope)

The adversarial reviewer also flagged `docs/design/2026-09-16-501-policy-lock.md:284`,
which shows `sudo node dist/index.js protect --from-config` with the implicit
assumption that a missing `~/.shieldcortex/config.json` "pins defaults" —
that recipe now exits 1 under the P2 fix. No script or CI job in this repo
actually runs that recipe (`grep` across `.github/` and `scripts/` for
`protect` found nothing), so nothing breaks today, but the doc text is now
wrong. Left alone — a docs-only fix, not a blocker, and not touched here to
keep this change scoped to `protect.ts` and its direct callers/tests.

## Not done / out of scope

- No `git push`, no merge, no `npm publish`. Nothing installed to
  `/etc/shieldcortex`; `shieldcortex protect` was never run for real.
- The macOS CI job was inspected read-only (`gh run view`) — not rerun.
- `DECISIONS.md` and leases untouched — local source work, no live
  security-config or install/publish/restart action taken.
- The design-doc drift noted above is left alone.
- The pre-existing root-tsconfig errors are left alone (not introduced here).

## Final state

```
3dcd5696 fix(cli): #522 r7 (Tars) — protect resolves the agent uid and the --from-config source, never guesses either
1d2b7346 docs: #522 report — GPT-6 round-6 fixes, verification and delete-the-fix evidence
a21f2833 fix(cli): #522 r6-3 — a flag-less protect pins the safe posture, reading no config
```

Working tree clean apart from this report. Branch `jarvis/501-policy-lock` is
42 commits ahead of `origin/main`, all local, nothing pushed.
