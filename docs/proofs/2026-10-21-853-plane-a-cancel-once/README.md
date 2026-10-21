# #853 Plane A proof: controlled cancellation and original-call once-only

Status: evidence for the #853 Plane A plan. It follows
`docs/design/2026-10-21-853-plane-a-hook-timeout-proof.md`, which covered timeout and kill semantics.
Date run: 2026-10-21, 16:26:57Z–16:27:35Z (`date -u` around `run-all.sh`). Host: `aiquant`, a dev
box, **not clawdbot1**. Claude Code **2.1.306**, `claude -p`, `--permission-mode bypassPermissions`, Bash
tool only, model `haiku`.
No guard code, installed hook, guard config or live enforcement was changed. The only hook in each
worker was a temporary probe, wired in through a per-case `--settings` file under `$TMPDIR`.

## TL;DR

| Question | Answer | Cases |
|---|---|---|
| Hold, then `allow`: does the **original** tool call run exactly once? | **Yes.** Each case had 1 hook invocation, 1 `tool_use` and 1 marker line, and the count was still 1 after a 5 s post-exit wait. The call ran 0.08–0.09 s after the hook returned, in the same turn. | O1, O2, O3 |
| Hook-side controlled cancel (the hook sees a cancel signal mid-hold and returns `deny`): does anything run? | **No.** Marker absent, and still absent 28 s after worker exit, which is 6.1 s past the 30 s hold's planned end. The model got `PreToolUse:Bash hook error: probe hold cancelled, nothing ran` (is_error). | X4 |
| Worker cancelled mid-hold (SIGTERM / SIGINT to the `claude` process): does anything run? | **No**, in both cases, including after the 30 s hold would have ended. The hook got SIGTERM 11–12 ms after the controller signalled the worker. | X1, X2 |
| Can a hook turn a cancellation into a run by printing `allow` on SIGTERM? | **No.** The late `allow` JSON was printed to stdout and logged by Claude Code, but the result was `status 1` / `outcome: error`, and nothing ran. | X3 |
| Hook children after cancel | No hook process was left at the end of the post-exit wait (X1–X4). The hold `sleep` child was checked and not alive in X1–X3 only. X4's `cancelfile` probe does not log its 0.2 s polling `sleep` pids, so its `hook_child_alive = no` is the script default, not an observation; cleanup of X4's children was not checked. | X1–X4 (hook process), X1–X3 (hold child) |
| What does the launcher see on a worker cancel? | It differs by signal. SIGTERM: rc 143, **no** tool result and **no** final `result` event. SIGINT: **rc 0**, a tool result `The user doesn't want to proceed with this tool use…`, and final `result` subtype `error_during_execution`. A launcher must not treat rc 0 as success. | X1, X2 |

## 1. Method

Scripts are in this directory and are reproducible as is:

- `probe-hook.sh <runDir> <holdS> <allow|deny|cancelfile> <onSignal: exit|allow>`: the temporary
  PreToolUse hook. It logs its start and `CLAUDE_PID`, then holds. In `allow`/`deny` mode it also logs
  its hold `sleep` child's pid; in `cancelfile` mode it logs no child pids. `allow`/`deny`
  sleep for the hold, then emit that `permissionDecision`. `cancelfile` polls `<runDir>/cancel` every
  0.2 s and emits `deny "probe hold cancelled, nothing ran"` if it appears, else `allow` at the end. It
  traps TERM, INT and HUP. With `onSignal=allow` it prints an `allow` decision and exits 0 on the
  signal.
- `run-case.sh <CASE> <hookTimeoutS> <holdS> <mode> <onSignal> <none|TERM|INT|cancelfile> <atS>`: one
  isolated worker. The controlled action fires `<atS>` s after the hook logs its start. After the
  worker exits it waits `POST_WAIT` s, then checks for leftover hook processes and whether the hold
  child is alive. The child check uses the pid logged by the hook, so it only observes something in
  `allow`/`deny` mode; with no logged pid it reports the default `hook_child_alive=no`.
- `run-all.sh`: the matrix below, cases in parallel.
- `summarize.py <runDir>`: a scrubbed JSON summary (counts, timings, hook/tool outcomes, filtered
  debug lines). It drops session ids, tool-use ids and message ids, and masks `CLAUDE_PID`.

Each worker:

```
timeout --signal=TERM --kill-after=5 55 claude -p "<prompt>" \
  --setting-sources "" --settings "$D/settings.json" --strict-mcp-config \
  --permission-mode bypassPermissions --tools Bash --model haiku --max-turns 4 \
  --output-format stream-json --verbose --include-hook-events \
  --debug-file "$D/debug.log" < /dev/null
```

with `D=$TMPDIR/case853-plane-a-proof2/runs/<CASE>` and `settings.json` =
`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"$TMPDIR/case853-plane-a-proof2/probe-hook.sh $D <hold> <mode> <onSignal>","timeout":<hookTimeout>}]}]}}`.
The prompt asks for exactly one Bash call, `echo RAN-<CASE> $EPOCHREALTIME >> $D/marker.txt`, and says
not to retry. The marker is the only side effect of the guarded call, and it is harmless.

Isolation. `--setting-sources ""` drops user, project and local settings, so the installed
`shieldcortex hook pre-tool` entry in `~/.claude/settings.json` is not loaded. `--strict-mcp-config`
with no `--mcp-config` drops MCP. Every payload logged `permission_mode = bypassPermissions` (the
`payload_summary` field in `evidence/*.json`). Wall-clock limits: each worker is capped at 55 s plus a
5 s kill-after, so 60 s at most. Observed worker walls were 8.1–19.1 s. Each case, post-wait included,
finished within 38.3 s (`time ./run-all.sh`: `real 0m38.245s` for all seven in parallel).

Exact invocation used for the recorded run, from this directory:

```
./run-all.sh
for c in O1 O2 O3 X1 X2 X3 X4; do
  python3 -I summarize.py "$TMPDIR/case853-plane-a-proof2/runs/$c" \
    | sed "s#$TMPDIR#\$TMPDIR#g; s#$HOME#~#g" > evidence/$c.json
done
```

## 2. Matrix and results

Times are epoch seconds (prefix `17926000` omitted), from the hook log, controller log and marker.
`Δ` is measured from the hook start.

| Case | Hook timeout / hold / mode | Controlled action | Hook log | Hook outcome (stream) | Tool results | Marker | Worker rc / wall |
|---|---|---|---|---|---|---|---|
| O1 | 40 / 15 / allow | none | start 19.458, allow 34.474 | success, exit 0 | 1, ok | **1 line**, 34.564 (+0.090 s) | 0 / 18.6 s |
| O2 | 40 / 15 / allow | none | start 19.647, allow 34.663 | success, exit 0 | 1, ok | **1 line**, 34.750 (+0.087 s) | 0 / 19.1 s |
| O3 | 40 / 8 / cancelfile (none sent) | none | start 19.443, allow 27.063 | success, exit 0 | 1, ok | **1 line**, 27.143 (+0.080 s) | 0 / 11.6 s |
| X1 | 50 / 30 / allow | SIGTERM → `claude` at 25.783 (Δ6.04) | signal-TERM at 25.795 | **error, exit 1** | **0** | **none** | 143 / 8.8 s |
| X2 | 50 / 30 / allow | SIGINT → `claude` at 24.959 (Δ6.03) | signal-TERM at 24.970 | **cancelled, exit 1** | 1, is_error: `The user doesn't want to proceed with this tool use…` | **none** | **0** / 8.1 s; final `error_during_execution` |
| X3 | 50 / 30 / allow, onSignal=allow | SIGTERM → `claude` at 26.094 (Δ6.03) | signal-TERM 26.106, late-allow-emitted 26.106 | **error, exit 1** (stdout had the allow JSON) | **0** | **none** | 143 / 9.1 s |
| X4 | 50 / 30 / cancelfile | cancel file at 25.683 (Δ6.09) | cancel-file-seen → deny at 25.786 | success, exit 0 (deny) | 1, is_error: `PreToolUse:Bash hook error: probe hold cancelled, nothing ran` | **none** | 0 / 10.2 s |

All seven cases: `hook_invocations = 1`, `stream_tool_use_count = 1`, `hook_procs_left = 0`,
`hook_child_alive = no`. `hook_child_alive = no` is an observation only for O1, O2 and X1–X3, which
logged a hold child pid; for O3 and X4 (`cancelfile`) no child pid was logged, so it is the default.
Post-exit waits: 5 s (O1–O3) and 28 s (X1–X4). The X waits end 4.5–6.1 s after the 30 s hold's
planned end (hook start + 30 s). No marker appeared during them.

Debug-log lines, verbatim (paths shortened to `…` here; full text in `evidence/*.json`):

- X1: `[uds-messaging] Shutting down`, then `Hooks: PreToolUse:Bash […] finished with status 1 (6067ms)`, then `[ERROR] Hook PreToolUse:Bash (PreToolUse) error: status code 1`.
- X2: `[uds-messaging] Shutting down`, then `Hooks: PreToolUse:Bash […] cancelled (6061ms)`, then `Hook PreToolUse:Bash (PreToolUse) cancelled:`.
- X3: `finished with status 1 (6057ms)`, then `[ERROR] "Hook PreToolUse:Bash (PreToolUse) error: status code 1\nstdout:\n{…"permissionDecision":"allow","permissionDecisionReason":"probe late allow after TERM"}}"`. The hook's own exit was 0, so the 1 is Claude Code's status for a hook ended by teardown (LIKELY, inferred from X1/X3).
- X4: `returned permissionDecision: deny (reason: probe hold cancelled, nothing ran)`.

A first run of the same matrix (16:25:35Z–16:26:14Z) gave the same outcome on every case: marker
counts 1/1/1 for O1–O3, none for X1–X4, and identical hook outcomes. Its sub-second timestamps are not
used, because of the `date` defect in §4.

## 3. What this means for Plane A (#875 principle 2, "Approvals hold and resume")

- **Once-only holds at the harness level.** For a single PreToolUse hook entry, an `allow` after a hold
  runs the original call exactly once, in the same turn, and Claude Code issues no second hook call
  or tool call for it (O1–O3). No grant/retry token is needed for that call to run. This is within the
  tested range (holds of 8–15 s; 130 s in C5 of the earlier proof), for one tool, one worker version.
- **Cancellation is fail-closed in every controlled path tested.** A hook-decided cancel (X4), a worker
  SIGTERM (X1) and a worker SIGINT (X2) each ended with nothing run, and nothing ran later. A late
  `allow` from a hook that is already being torn down is ignored (X3). So a card answered *after* the
  worker died cannot run the original call through this hook. Its outcome has to be written by the
  card side as "cancelled/expired, nothing ran", not by the dead hook. This matches F4 in the earlier
  proof.
- **The launcher's exit code is not a reliable signal.** On SIGINT the worker exits 0 (X2). A
  launcher or digest that reads rc must also read the final `result` subtype
  (`error_during_execution`) or the stream's hook outcome.
- **What the model sees on cancel differs.** X4 gives the model our reason string. X2 gives Claude
  Code's generic "user doesn't want to proceed" text. X1/X3 give the model nothing, because the
  process is gone.

## 4. Limitations and caveats

- One host (`aiquant`), Claude Code 2.1.306, Linux, Bash tool only, `-p` with `bypassPermissions`,
  model `haiku`. Not tested: TTY sessions, other tools (Write/Edit), multiple matching hooks running in
  parallel, a real ShieldCortex hook, clawdbot1.
- "Exactly once" here means one marker line and one `tool_use`. It relies on the model following a
  "do not retry" prompt. A model retry would be a *new* `tool_use` with a new hook call, which this
  matrix would show as count 2. None was seen.
- Holds were 8–30 s so that each case stayed within the 60 s limit. Cancellation at longer holds was
  not tested here.
- X1–X3 signal the `claude` process directly. A process-group kill, SIGKILL, or a parent `timeout`
  expiry were not tested as separate cases. (C6 in the earlier proof was an uncontrolled outer
  teardown with the same no-run outcome.)
- **Timestamp defect found.** This host's `date` is uutils coreutils 0.10.0 (`date --version`). Its
  `%s.%3N` output does not match `%s%N` for fractions below 0.1 s: a sample printed `.147` where
  `%s%N` gave `.012…`, and in the first run the hook's `start` line read `.956` while its next line
  read `.112` of the same second. These scripts use bash `$EPOCHREALTIME` instead. The earlier
  timeout proof (`docs/design/2026-10-21-853-plane-a-hook-timeout-proof.md`) used `date +%s.%3N`, so
  its sub-second hook-log and marker times may be wrong for any value whose true fraction was below
  0.1 s. Its whole-second findings and its Claude Code debug-log durations (for example `5011ms`) do
  not depend on `date`.

## 5. Files

- `probe-hook.sh`, `run-case.sh`, `run-all.sh`, `summarize.py`: the scripts.
- `evidence/<CASE>.json`: scrubbed `summarize.py` output for the recorded run (second run). Raw
  `stream.jsonl`, `debug.log` and `hook.log` stay under `$TMPDIR/case853-plane-a-proof2/runs/` and are
  not committed, because they carry session ids, the messaging-socket environment and the user's
  paths.
