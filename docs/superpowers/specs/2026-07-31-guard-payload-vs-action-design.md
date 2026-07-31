# Action Guard — payload-vs-action precision pass (#89)

Date: 2026-07-31 · Branch: `fix/89-payload-vs-action` · Base: `main` @ 4.47.17

## Problem

4.47.17 (#138) folds an invoked script's **contents** into the Action Guard's scan
surface. That closed a real bypass and must stay. But every rule in the guard is
written for **shell command text**, and the folded surface now also carries:

- Python / JavaScript / Ruby **source** — whose lines are not shell statements and
  whose string literals are not commands.
- Heredoc bodies consumed by an interpreter — same thing.
- Long quoted **message bodies** (`--text`, `--body`) that discuss commands.

The guard cannot tell "this text appears in the payload" from "this action is
being executed", so it gates — and sometimes hard-denies — read-only work.

Measured on this box: 34% of 1,271 real Claude Code tool calls in July were
stopped. Replaying the 429-event deduplicated stop corpus through
`evaluateToolCall` on 4.47.17 reproduces 129 stops, of which the classes below
are false positives.

## Non-goals

- Reverting or weakening #138's script folding.
- Softening the catastrophic tier for a genuinely executed command.
- Touching `autoApprove` / one-shot approvals (#127), promptless deny (#139),
  doctor (#133/#140), or the `at=` assignment lookahead (#135).

## Design

### 1. Typed scan regions

`evaluateToolCall` currently concatenates `execCommand`, `path`, `url` and the
folded script content into one flat string. Replace the flat concatenation with a
builder that keeps the same concatenated text (so no rule regex changes) plus a
list of **regions**:

| region kind | source |
|---|---|
| `shell` | the command string, `path`, `url` |
| `script:<lang>` | folded script sources (lang from the invoking interpreter / file extension) |
| `script:<lang>` | heredoc bodies consumed by an interpreter (lang from the intro line) |
| `script:<lang>` | inline `-c` / `-e` / `-r` programs (lang from the interpreter) |

Regions are byte ranges into the concatenated surface. Span classification then
asks "what kind of text is this match sitting in?" before deciding.

A `script:sh` region is shell — it keeps today's behaviour exactly. Only
`python` / `node` / `ruby` / `perl` / `php` regions get interpreter-source rules.

### 2. Interpreter-source rules inside a `script:<lang>` region

Three facts hold for interpreter source:

- **A comment is never executed.**
- **A string literal is only a command if it reaches a shell-out sink**
  (`os.system`, `subprocess`, `popen`, `child_process`, `execSync`, `eval`,
  `shell=True`, backticks, …).
- **A literal that IS a sink call's argument is a command** — `os.system('rm -rf /')`.

So, within a script region:

| content | verdict contribution |
|---|---|
| comment | dropped (mention) |
| literal whose own line calls a sink | **executed** — unchanged, still hard-blocks |
| literal, region has no sink anywhere | dropped (mention) |
| literal, region has a sink elsewhere, region folded from a file | **payload**: catastrophic → dangerous, dangerous stays dangerous |
| literal, region has a sink elsewhere, region written by the caller | **executed** — unchanged |
| bare code | unchanged (fail-closed) |

Sink attribution is by line, deliberately — the cheap, conservative half. When it
misses (a call split over lines, or the string bound to a variable first) the
literal falls back to the payload tier, which still gates. It never becomes an
allow.

The caller-written / folded split matters: an inline `python3 -c '…'` program or
a heredoc body is the exec surface the caller authored and is the classic RCE
vector, so a shell-out sink there keeps every literal executed, exactly as #84's
adversarial floor requires. Only a file the guard chose to fold in gets the
payload tier — that folding is what introduced the conflation in the first place.

Bare code is untouched, which is what keeps #138's parity fixture
(`python3 /tmp/a.py` containing `sudo rm -r /var/lib/thing`) at
`require_approval` with `privilege-escalation`.

Regions come from three places: files folded by #138, heredoc bodies an
interpreter consumes, and inline `-c`/`-e`/`-r` programs. A heredoc that is
**redirected to a file the same command then executes** is excluded — it
generates the shell that runs, so its text is a command source after all (#86.2).

### 3. Line anchors are shell-only

Several rules anchor to command position with `(?:^|[;&|(\n]|\$\()` — and `\n`
is in that class, so **every line start is a shell command boundary**. Inside a
Python or JS region that is wrong: `at = tok['access_token']` is an assignment,
not `at(1)`.

Rule: a match that lies inside a `script:<lang>` region (non-shell language) and
**begins by consuming a shell anchor character** — `\n`, `;`, `&`, `(`, `$(` —
is anchored in the wrong language, and is classified as a mention. Inside Python
or JS those are ordinary punctuation: `at = tok[…]` is an assignment and
`print(at[:4])` is a call. `|` and `>` are deliberately **not** anchor characters
here — `redirect-to-block-device` is an unanchored rule that starts with one.

This is the general form of #135's `at\b(?!\s*=)` lookahead. #135 fixes the token;
this fixes the anchor. They compose and neither duplicates the other.

### 4. Shell-region precision: fixes to `buildSpanCtx`

**4a. Reactivator scoping.** Today a single `$(`, backtick, `${`, `$VAR` or
`eval` **anywhere** in the text disables *all* quoted-data downgrades. Real
commands almost always contain one, so #84's classifier is effectively off. Replace
the blunt global switch with the three precise conditions it was standing in for:

1. `eval` anywhere → no downgrade (unchanged; `eval` can re-run captured text).
2. A command-substitution span (`$(…)`, `` `…` ``) **inside** a quote is excised
   from that quote's data range — so `echo "$(rm -rf /)"` stays executed.
3. A quote in **assignment position** (`X="…"`) is never data, and a quote
   **inside** a substitution (`Y=$(echo "…")`) is never data — so
   `VAR="rm -rf /" && $VAR` and `Y=$(echo "rm -rf /"); $Y` stay executed.

Every adversarial-floor case in `span-classifier-84.test.ts` is covered by one of
these three; the global switch was strictly coarser.

**4b. `DATA_COMMAND` gains read-only search verbs** — `git grep`, `git log`, `jq`.
`sed` and `awk` are deliberately excluded (`s///e`, `system()`).

**4c. Text-flag values are data.** A quoted span that is the value of a
long-form text flag — `--text --body --message --comment --description --title
--content --caption --note --summary --prompt --subject` — is a payload for the
command, not code, whatever the command word is. Guarded by an explicit
interpreter/remote-exec denylist so `bash --text` style constructions cannot use it.

### 4d. Bounds

The span cap rises from 8k to 32k so a real folded script is classified at all.
Everything the old cap protected is re-bounded explicitly: the quote-prefix slice
is capped at 512 chars (it was O(n²) on a quote-dense command), the JS
regex-position lookback is a bounded backward scan rather than a prefix slice
(O(n²) otherwise), the re-scan budget is shared across patterns and shrinks on a
large surface, and the region map is not built at all above the cap. Every cut
fails **closed**.

### 5. npx/bunx: parse argv instead of pattern-matching the statement

`isGatedNpxBunx` scans the whole statement for `-p`, `-c`, `./…`. Those are npx's
own flags **only before the package spec** — after it they belong to the invoked
binary, which is why `npx tsc -p tsconfig.json` and `npx tsx ./probe.mts` gate today.

Replace with a small argv walk: npx options run until the first non-option token
(the package spec). Gate flags are looked for in the option region only; version
pins and remote refs in the package spec only. Also admit transparent wrappers
(`timeout`, `env`, `nohup`, …) at command position — which **closes** a false
negative found while writing this: `timeout 30 npx -y pkg@latest` is not gated today.

### 6. Venv-scoped pip installs

`pip install` into an explicitly non-system prefix mutates that prefix, not the
host. Downgrade to the existing sensitive-but-allowed tier when the invocation is
scoped:

- the pip executable is path-qualified into a non-system prefix
  (`.venv/bin/pip`, `/tmp/x-venv/bin/pip`) — `/usr`, `/usr/local`, `/opt/homebrew`
  and a bare `pip` are **not** scoped;
- `--target <dir>` / `--prefix <dir>` / `-t <dir>`;
- `uv pip … --python <path>`.

`pip install --user`, `sudo pip install`, bare `pip install` and every system
package manager keep gating. The `install-package` bridge is also tightened from
`[^|\n]*` to `[^|;&\n]*` so a `pip` in one statement cannot pair with an
`install` in another.

## Verification

- Failing-first: every class ships a fixture that is RED on `main` and green after.
  New pack: `src/defence/iron-dome/__tests__/payload-vs-action-89.test.ts`.
- Zero regression: full suite green, and the adversarial floors in
  `span-classifier-84`, `script-file-bypass`, `guard-bypasses-4475`,
  `fp-precision-88-89`, `guard-tune-91-89`, `rm-flag-fp` unmodified.
- Corpus replay: `scripts/replay-guard-corpus.mts` reports before/after stop counts
  over the 429-event corpus, and flags any event that got *tighter*.
- Performance measured against `origin/main` on the same inputs: 0.4ms typical,
  ~3ms for a 250KB fold, and within 2–7% of main on the pathological synthetic
  shapes (quote-dense, pipe-dense, 789-heredoc).

## Known-out-of-scope findings (reported, not fixed)

Measured while building this; each needs its own decision:

1. `rm -rf <specific scratch path>` (`rm -rf .next`, `rm -rf /tmp/scratch`) is
   **catastrophic / auto-denied** — the largest single benign-stop class in the
   corpus. Softening it is a catastrophic-tier decision, not a precision pass.
2. Read-only access to a sensitive path (`ls ~/.ssh/`, `grep … .env.example`)
   gates as `touch-sensitive-path`; `.env.example`/`.env.sample` are secret-free
   templates that `\.env\b` matches.
3. `kill <pid>` / `pkill -f <test pattern>` for the agent's own background jobs.
4. `pipe-download-to-shell`'s `(?:[^\n|]*\|)*` bridge is still quadratic on a
   pipe-dense string — a 22k one-liner costs ~12s on `main` and the same after
   this change. Pre-existing (the sibling of #92 must-fix 1), unaffected here,
   and worth its own issue.
