# #853 Plane A proof step: Claude Code PreToolUse hook timeout and kill semantics

Status: evidence, Step 1 of the Plane A plan in Jarvis's ruling on #853
(issuecomment-6313152247, 21 Oct 2026). Serves #875 principle 2 ("Approvals hold and resume").
Date run: 2026-10-21, 10:25–10:30Z (debug-log timestamps; C6 is the last, torn down at 10:29:33Z). Host: `aiquant` (a dev box, **not clawdbot1**).
No guard code, installed hook, or live config was changed.

## TL;DR

| Question | Answer | Evidence |
|---|---|---|
| Can a PreToolUse hook keep the original call pending past 10 s and then allow it? | **Yes, up to 130 s.** Held 20 s (C1) and 130 s (C5); on `allow` the same tool call ran 0.09–0.11 s later, in the same turn. Longer holds are **not proven**: the 620 s case (C6) is **inconclusive** (see §2). | C1, C5 (C6 inconclusive) |
| Deny after a long hold? | **Yes.** Denied at 20 s; nothing ran; the model got the reason as an error tool result. | C4 |
| What does timeout do by default? | **Fails open, silently.** The hook gets SIGTERM at the timeout, its output is dropped, and **the tool call runs** (the hook meant to deny). The model sees a normal successful tool result with no hook-error notice. | C2 |
| Can a timeout be made to fail closed? | **Yes**, with `"onFailure": "block"` on the hook entry. The tool call is blocked and the model gets `…timed out; blocking because onFailure is "block"`. | C3, C7 |
| Does `onFailure: "block"` also block on a hook crash? | **Yes.** exit 1 + `onFailure: "block"` blocks (C8). Without it, exit 1 fails open (C9). | C8, C9 |
| What happens to the hook's children on timeout? | The hook's child `sleep` was gone right after the worker exited (no orphan). The hook runs in its own process group (pgid = its parent wrapper). See the limitation note below. | C7 |
| Can the hook learn its configured timeout? | **No.** The payload has no timeout field. The env has no timeout variable. | C1 payload/env |
| Headless launcher budget? | Not measured on clawdbot1. On this box, OpenClaw 2026.7.1-2's bundled docs give a 1800 s exec default, a 600 s default `openclaw agent` timeout, and heartbeat turns capped at 600 s. clawdbot1's actual values are UNKNOWN. | §4 |

**Verdict for the ruling's branch:** the harness does **not** hard-kill regardless of the
configured timeout, within the tested range. Hold-then-allow is proven up to 130 s (C5). Nothing
above 130 s is proven: C6 (620 s) was torn down by its outer session, not the hook harness, and is
inconclusive. In particular, this note does **not** show that a 600 s hold works. So the "hold
and resume" Plane A design is feasible in principle at the default 120 s. The fallback ("card + deny with honest
not-run copy") is not forced by the harness. But the design is only safe if the issues in §3 are
resolved. The worst of them: at default settings, a hook that overruns its timeout **lets the
approvable action run unapproved, with no trace in the transcript.**

## 1. Method

- Claude Code **2.1.306** (`claude --version`), binary `/home/mike/.local/bin/claude`. The model
  for the nested worker was `haiku`; the model is irrelevant to hook semantics.
- Each case is one nested headless worker:

  ```
  timeout --signal=TERM --kill-after=10 <LIM> claude -p "<prompt>" \
    --setting-sources "" --settings /tmp/case853-hookexp/runs/<CASE>.settings.json \
    --strict-mcp-config --permission-mode bypassPermissions --tools Bash --model haiku \
    --max-turns 4 --output-format stream-json --verbose --include-hook-events \
    --debug-file runs/<CASE>/debug.log
  ```

  The prompt asks for exactly one Bash call: `echo RAN-<CASE> $(date +%s.%3N) >> runs/<CASE>/marker.txt`.
  It also says not to retry. A marker line means the original tool call ran, and gives the time.
- **Isolation / recursion control.** `--setting-sources ""` drops user, project and local settings.
  That excludes `~/.claude/settings.json`, which carries the installed
  `shieldcortex hook pre-tool` (timeout 10). `--strict-mcp-config` drops MCP. The only hook is
  the probe from the temp `--settings` file, with matcher `Bash`. Control run C0 (no hooks)
  confirmed this in the debug log: `Registered 0 hooks from 3 plugins` (built-in plugins only),
  0 occurrences of `shieldcortex`, `mcp_servers: []`, `permissionMode: bypassPermissions`. My own
  outer session's probes were plain shell, and no nested worker had the ShieldCortex hook.
- Probe hook (`/tmp/case853-hookexp/probe-hook.sh <case> <sleep> <allow|deny>`). It logs start
  time, pid, ppid and pgid. It saves the stdin payload and the names of the `CLAUDE*` env vars. It
  traps TERM, INT and HUP. It runs `sleep N` as a child and waits on it, then prints a
  `hookSpecificOutput.permissionDecision` JSON and exits 0. The crash variants exit 1 at once.
- Durations are bounded: the longest completed hold is 130 s (C5). A 620 s hold (C6) was attempted
  but did not complete (§2). The only side effect is appending to files under `/tmp/case853-hookexp/`.

## 2. Results

Times are epoch seconds from the hook log and marker. Δ is measured from hook start.

| Case | Hook `timeout` | `onFailure` | Hook behaviour | Hook log | Tool ran? | What the model saw | Worker rc / wall |
|---|---|---|---|---|---|---|---|
| C0 | (no hook) | — | — | — | yes | success | 0 / 3.1 s |
| C1 | 30 | — | sleep 20 → allow | start 314.260, return 334.281 | **yes**, at 334.373 (+0.09 s after return) | success | 0 / 22.9 s |
| C2 | 5 | unset | sleep 20 → deny | start 315.186, **SIGTERM at 320.177 (Δ4.99 s)** | **yes, at 320.262** | normal success; no hook notice | 0 / 9.3 s |
| C3 | 5 | block | sleep 20 → deny | start 314.514, SIGTERM at 319.505 | no | `PreToolUse:Bash hook error: [...]: timed out; blocking because onFailure is "block"` (is_error) | 0 / 8.6 s |
| C4 | 30 | — | sleep 20 → deny | start 315.834, return 335.941 | no | `PreToolUse:Bash hook error: probe C4 deny` (is_error) | 0 / 24.0 s |
| C5 | 150 | — | sleep 130 → allow | start 313.530, return 443.540 | **yes**, at 443.653 (+0.11 s) | success | 0 / 134.3 s |
| C6 | 660 | — | sleep 620 → allow | start 312.660, **SIGTERM at 573.625 (Δ260.97 s), from session teardown, not the hook timeout** | no (no `marker.txt`) | nothing: no tool result, no final `result` event | none recorded (no `result.txt`); **inconclusive** |
| C7 | 3 | block | sleep 45 → deny | start 364.654, SIGTERM at 367.647; child pid 3418032 | no | blocked (onFailure) | 0 / 7.1 s |
| C8 | 10 | block | exit 1 at once | 478.477 | no | `…: failed; blocking because onFailure is "block"` | 0 / 4.3 s |
| C9 | 10 | unset | exit 1 at once | 478.315 | **yes**, at 478.405 | normal success | 0 / 4.0 s |

(Epoch prefix 1792578xxx omitted.)

**C6 is inconclusive.** The outer command that drove the runs was killed at about 420 s
(operator report; not in the artefacts). That
teardown took the C6 worker down with it, and the hook got SIGTERM 260.97 s into a planned 620 s
hold. That is well short of its 660 s timeout. The evidence in `runs/C6/` shows this was session
teardown, not the hook harness:

- `debug.log` has no `timed out after …ms` line, unlike C2, C3 and C7. Instead, at 10:29:33.625Z it
  logs `[uds-messaging] Shutting down` and `LSP server manager shut down successfully`, then
  `Hooks: PreToolUse:Bash [… C6 620 allow] finished with status 1 (260992ms)` and
  `Hook PreToolUse:Bash (PreToolUse) error: status code 1`, then `session.end`.
- The stream-json `hook_response` is `"exit_code": 1, "outcome": "error"`, not `"cancelled"` as on
  a timeout. The stream has no tool result and no final `result` event.
- `run-case.sh` never wrote `result.txt`, so the wrapper itself was killed too. No `marker.txt`: the
  tool did not run.

What C6 does **not** show: that a hold longer than 130 s ends in a run on `allow`, or anything about
600 s. One side observation, not a proof: up to 260.97 s, no harness timeout fired on the pending
hook. A re-run of C6 in a session that outlives it is still needed. It was not done here.

Debug log lines, verbatim:

- C2: `Hooks: PreToolUse:Bash [/tmp/case853-hookexp/probe-hook.sh C2 20 deny] timed out after 5000ms (5011ms)`,
  then `Hook PreToolUse:Bash (PreToolUse) cancelled:`.
- C3: the same, plus `[WARN] Hooks: PreToolUse command hook timed out; blocking (onFailure: "block")`.
- stream-json `hook_response` on a timeout: `"exit_code": 1, "outcome": "cancelled"`, empty stdout.
- The runs in which the tool ran (C0, C1, C2, C5, C9) also log `Execution timeout: 10000ms`. The
  blocked runs and C6 do not. Its source is UNKNOWN. It did not cut short the 20 s or 130 s holds,
  so it is not the hook budget.

Hook environment, observed in C1 and C7. Names: `CLAUDECODE CLAUDE_CODE_CHILD_SESSION CLAUDE_CODE_ENTRYPOINT
CLAUDE_CODE_EXECPATH CLAUDE_CODE_MESSAGING_SOCKET CLAUDE_CODE_MESSAGING_TOKEN
CLAUDE_CODE_SESSION_ATTENDED CLAUDE_CODE_SESSION_ID CLAUDE_EFFORT CLAUDE_PID CLAUDE_PROJECT_DIR`.
Values (C7, non-secret ones only): `CLAUDE_CODE_SESSION_ATTENDED=0`, `CLAUDE_CODE_ENTRYPOINT=sdk-cli`,
`CLAUDE_CODE_CHILD_SESSION=1`. CHILD_SESSION is probably 1 only because the worker was nested in
my session (LIKELY). Payload keys: `cwd effort hook_event_name permission_mode prompt_id
session_id tool_input tool_name tool_use_id transcript_path`. `permission_mode` was
`bypassPermissions`.

These results match the hooks reference (code.claude.com/docs/en/hooks, fetched 21 Oct, read via
a summarising fetch). It says the `command` default is 600 s. It says a timed-out PreToolUse hook
"doesn't block the tool call … To block the call when a command or http hook times out, set
`onFailure: "block"`". It says matching hooks run in parallel. The excerpt I read gave no maximum
timeout.

## 3. Findings against the ruling's Plane A design

The ruling (§2) says: *"Raise the hook's `timeout` from 10 s to a configurable
`actionGuard.holdSeconds` (default 120, cap 600) for approvable calls only; safe/log-only decisions
keep the 10 s fast path … with an internal deadline 10 s before the harness limit."*

**F1. A harness timeout is static and per hook entry. It cannot be "for approvable calls only".**
`timeout` lives in `settings.json` on the hook entry. The only selector is the `matcher`, which is
a tool name. Approvable vs log-only is decided inside our hook, after it starts. So the single
`shieldcortex hook pre-tool` entry (`matcher: '*'`, `src/setup/settings-hooks.ts:52-53`) must carry
`timeout ≥ holdSeconds + margin` for **every** tool call. The "10 s fast path" can then only be a
self-imposed deadline inside the hook process. It is no longer enforced by the harness. A hang on
the safe path (a lock, a slow store) would stall routine calls for up to holdSeconds instead of
10 s. A partial static split is possible: one entry for `Read|Glob|Grep|…` at 10 s, and one for
`Bash|Write|Edit|…` at holdSeconds. Approvable work is mostly `Bash`, though, so most calls would
still sit under the long ceiling. Either way, this has to be stated as an internal deadline.
It is not a harness guarantee.

**F2. On overrun, the default is fail-open and invisible. This is a security property, not a UX
detail (C2).** Suppose our internal deadline is missed: clock skew, slow node start, event-loop
stall, a `holdSeconds` larger than the settings timeout. Then the harness kills the hook and the
**approvable action runs with no approval**. The model's transcript shows a clean success. Under
enforce, that bypasses the hold. Mitigation: `"onFailure": "block"` on the pre-tool entry (C3).
But C8 shows that this also turns **any** hook crash into a block for every tool call, log-only
reads included. That cuts against #875 principle 1 ("routine work never trips it"). So this is a
choice the owner has to make: silent fail-open, or crash = block. Possible mitigation (not
tested): the safe path returns an explicit `allow` quickly, so only true hangs and crashes reach
`onFailure`.

**F3. The hook cannot see its own harness timeout, so the "10 s before the harness limit" deadline
depends on config consistency.** Neither the payload nor the env carries the timeout (C1). The
deadline needs either (a) the hook reading `settings.json`, or (b) `holdSeconds` and the
settings `timeout` always being written together. Today they live in different files. `holdSeconds`
would go in `~/.shieldcortex/config.json`. The comment at `settings-hooks.ts:47-51` says posture
changes "never require re-editing settings.json". Changing `holdSeconds` would break that.
Drift checks miss this case too. `reconcileHookTimeouts` (`settings-hooks.ts:186-207`) and doctor
(`src/cli/doctor.ts:7700-7719`) only flag a timeout *below* the canonical value, which is 10 for
PreToolUse. A box with `holdSeconds: 300` and a settings timeout of 10 would pass doctor, and every
hold would then fail open at 10 s (per F2). The canonical value would need to follow
`holdSeconds`.

**F4. The kill reaches the hook and, apparently, its children (C7). The poll must be
in-process.** The hook got SIGTERM, and its child `sleep 45` was not running ~1.9 s after
SIGTERM, at worker exit. The waiter/poller that keeps the original call pending therefore dies
with the hook on timeout. That fits the ruling: no out-of-band execution. A detached `setsid`
waiter was not tested. Whatever writes the "expired, nothing ran" card outcome must not depend
on the killed process. Either it is written before the internal deadline, or the card side
expires it on its own.

**F5. Outer budgets can be shorter than the hold.** `holdSeconds` cap 600 is the same as the
OpenClaw `openclaw agent` default timeout of 600 s, and the same as the heartbeat-turn cap
(bundled docs on this box, §4). A `claude -p` worker started inside such a turn could be killed
from outside before a 600 s hold resolves. Then nothing runs, but the card outcome must still read
"expired, nothing ran". C6 is an example of this: an outer teardown ended the worker mid-hold, the
hook got SIGTERM, and nothing ran (§2). Default 120 fits inside every default seen here. Lifting the
cap toward 600 needs clawdbot1's real values, and a completed hold test above 130 s, which this note
does not have.

**F6. Not tested, but relevant.** The hooks reference lists `permissionDecision: "defer"`
("ends the turn so the tool can be resumed later", `-p` only). That is a possible alternative
to holding a live process. It is noted only; it was not evaluated, and adopting it would be a
design change.

## 4. Headless launcher budget (partial)

- Claude Code side: no wall-clock limit applied to a pending hook within the tested range, up to
  130 s with a completed allow (C5) in `-p` mode. Beyond that it is unproven (C6 inconclusive). No
  API request is in flight while the hook runs.
- OpenClaw side. These are the docs bundled with the local install
  (`/home/mike/.npm-global/lib/node_modules/openclaw/docs`, `OpenClaw 2026.7.1-2`), **not clawdbot1**:
  `tools.exec.timeoutSec` defaults to `1800` (`tools/exec.md:88`). `openclaw agent --timeout`
  defaults to `600` (`cli/agent.md:33`). Heartbeat turns use `agents.defaults.timeoutSeconds`,
  otherwise "the heartbeat cadence capped at 600 seconds" (`gateway/heartbeat.md:66`). The local
  `openclaw.json` sets no timeout keys.
- UNKNOWN: clawdbot1's cron, sub-agent and heartbeat timeouts, and how its launchers start
  `claude -p`. The launchers are not in this repo. Jarvis should read them on clawdbot1 before
  `holdSeconds` is raised beyond 120.

## 5. Limitations

- No completed hold above 130 s. C6 (620 s) was cut off by session teardown at 260.97 s and is
  inconclusive. A 600 s hold is unproven.
- One host (`aiquant`), one Claude Code version (2.1.306), Bash tool only, Linux. Behaviour may
  differ on other versions. Pin the version in the implementation's real-hook test.
- Children (F4): the gap between SIGTERM and worker exit was about 2 s. I did not separate "the
  harness killed the process group" from "the children were cleaned up at exit". A detached or
  `setsid` child was not tested.
- An interactive (TTY) session was not tested. Only `-p`, `bypassPermissions`.
- A real ShieldCortex hook was not exercised. The probe stands in for it, so node start-up time
  and store latency were not measured.
- The documentation quotes came through a summarising fetch. The experimental results do not
  depend on them.

## 6. Reproduce

The scripts are in `/tmp/case853-hookexp/` (`probe-hook.sh`, `probe-hook2.sh`, `crash-hook*.sh`,
`run-case.sh`, `runs/<CASE>.settings.json`). Per-case artefacts are in `runs/<CASE>/`: `hook.log`,
`marker.txt`, `payload.json`, `stream.jsonl`, `debug.log`, `result.txt` (C6 has no `marker.txt`
or `result.txt`, see §2). The scratch files are
not in the repo. To re-create them, follow §1; each case is one `run-case.sh <CASE> <limit>`.
