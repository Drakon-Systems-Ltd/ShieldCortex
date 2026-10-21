#!/usr/bin/env bash
# Run one isolated nested headless worker for the #853 Plane A cancel/once-only proof.
# Usage: run-case.sh <CASE> <hookTimeoutS> <holdS> <allow|deny|cancelfile> <onSignal> <action> <actionAtS>
#   action: none | TERM | INT (signal the claude worker <actionAtS> s after the hook starts)
#           | cancelfile (create <runDir>/cancel <actionAtS> s after the hook starts)
# Outer wall-clock cap per case: 60 s (timeout --kill-after=5 55).
# All state lives under $TMPDIR/case853-plane-a-proof2 (TMPDIR must be set). Nothing else is written.
set -u
die() { echo "run-case.sh: $*" >&2; exit 2; }
[ "$#" -eq 7 ] || die "expected 7 arguments, got $#"
CASE="$1"; HTO="$2"; HOLD="$3"; MODE="$4"; ONSIG="$5"; ACT="$6"; AT="$7"
# Validate everything before any filesystem write or cleanup; all of these are interpolated
# into paths, JSON, the hook command line, and the prompt.
case "$CASE" in O1|O2|O3|X1|X2|X3|X4) ;; *) die "CASE must be one of O1 O2 O3 X1 X2 X3 X4" ;; esac
case "$MODE" in allow|deny|cancelfile) ;; *) die "mode must be allow|deny|cancelfile" ;; esac
case "$ONSIG" in exit|allow) ;; *) die "onSignal must be exit|allow" ;; esac
case "$ACT" in none|TERM|INT|cancelfile) ;; *) die "action must be none|TERM|INT|cancelfile" ;; esac
int_in() { [[ "$2" =~ ^[0-9]{1,3}$ ]] && [ "$((10#$2))" -ge "$3" ] && [ "$((10#$2))" -le "$4" ] || die "$1 must be an integer in [$3,$4]"; }
int_in hookTimeoutS "$HTO" 1 55
int_in holdS "$HOLD" 1 55
int_in actionAtS "$AT" 0 55
POST_WAIT="${POST_WAIT:-0}"; int_in POST_WAIT "$POST_WAIT" 0 60
[ -n "${TMPDIR:-}" ] || die "TMPDIR must be set (no fallback to system temp dirs)"
[[ "$TMPDIR" =~ ^/[A-Za-z0-9._/-]+$ && "$TMPDIR" != *..* ]] || die "TMPDIR must be an absolute path of [A-Za-z0-9._/-] without '..'"
[ -d "$TMPDIR" ] || die "TMPDIR is not a directory: $TMPDIR"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${TMPDIR%/}/case853-plane-a-proof2"; D="$ROOT/runs/$CASE"
rm -rf "$D"; mkdir -p "$D"; cp "$HERE/probe-hook.sh" "$ROOT/probe-hook.sh"; chmod +x "$ROOT/probe-hook.sh"
cat > "$D/settings.json" <<JSON
{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"$ROOT/probe-hook.sh $D $HOLD $MODE $ONSIG","timeout":$HTO}]}]}}
JSON
PROMPT="Use the Bash tool exactly once to run this exact command: echo RAN-$CASE \$EPOCHREALTIME >> $D/marker.txt ; Do not run any other command and do not retry if it is blocked or fails. Then reply with one line: the tool result or the block reason."
cd "$D"
T0=$EPOCHREALTIME
timeout --signal=TERM --kill-after=5 55 claude -p "$PROMPT" \
  --setting-sources "" --settings "$D/settings.json" --strict-mcp-config \
  --permission-mode bypassPermissions --tools Bash --model haiku --max-turns 4 \
  --output-format stream-json --verbose --include-hook-events \
  --debug-file "$D/debug.log" < /dev/null > "$D/stream.jsonl" 2> "$D/stderr.txt" &
TPID=$!
if [ "$ACT" != none ]; then
  for _ in $(seq 1 300); do grep -q ' start ' "$D/hook.log" 2>/dev/null && break; sleep 0.1; done
  CPID=$(sed -n 's/.* claude_pid=\([0-9]*\).*/\1/p' "$D/hook.log" | head -1)
  sleep "$AT"
  if [ "$ACT" = cancelfile ]; then
    touch "$D/cancel"; echo "$EPOCHREALTIME controller created cancel file" >> "$D/controller.log"
  else
    echo "$EPOCHREALTIME controller sending SIG$ACT to claude_pid=$CPID comm=$(cat /proc/$CPID/comm 2>/dev/null)" >> "$D/controller.log"
    [[ "$CPID" =~ ^[0-9]+$ ]] && kill -s "$ACT" "$CPID"
  fi
fi
wait $TPID; RC=$?
T1=$EPOCHREALTIME
# Observation window after the worker exits: does anything run late?
sleep "$POST_WAIT"
T2=$EPOCHREALTIME
LEFT=$(pgrep -f "$ROOT/probe-hook.sh $D " | wc -l)
CHILD=$(sed -n 's/.* child pid=\([0-9]*\).*/\1/p' "$D/hook.log" | head -1)
CHILD_ALIVE=no; [ -n "$CHILD" ] && kill -0 "$CHILD" 2>/dev/null && CHILD_ALIVE=yes
echo "case=$CASE rc=$RC t0=$T0 t1=$T1 wall=$(echo "$T1-$T0"|bc) post_wait_end=$T2 hook_procs_left=$LEFT hook_child_alive=$CHILD_ALIVE" > "$D/result.txt"
cat "$D/result.txt"
