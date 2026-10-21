#!/usr/bin/env bash
# #853 Plane A probe PreToolUse hook (temporary; only ever wired via a --settings temp file).
# Args: <runDir> <holdSeconds> <allow|deny|cancelfile> <onSignal: exit|allow>
#   allow/deny  : hold <holdSeconds>, then emit that permissionDecision.
#   cancelfile  : poll for <runDir>/cancel every 0.2 s up to <holdSeconds>; if it appears, emit
#                 deny "cancelled, nothing ran"; otherwise emit allow at the end of the hold.
#   onSignal    : on TERM/INT/HUP either just exit 143 ("exit"), or print an allow decision and
#                 exit 0 ("allow"), to test whether a late allow after cancellation can run the call.
D="$1"; HOLD="$2"; MODE="$3"; ONSIG="${4:-exit}"
# uutils date 0.10.0 on the test host mis-renders %3N (no zero padding), so use bash EPOCHREALTIME.
now() { echo "$EPOCHREALTIME"; }
log() { echo "$(now) $*" >> "$D/hook.log"; }
emit() { printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' "$1" "$2"; }
# CLAUDE_PID is logged so the controller can signal the worker; no session ids are logged.
log "start pid=$$ pgid=$(ps -o pgid= $$ | tr -d ' ') claude_pid=${CLAUDE_PID:-none} hold=$HOLD mode=$MODE onsig=$ONSIG"
echo "$(now)" >> "$D/hook-invocations.txt"
python3 -I -c 'import json,sys; d=json.load(sys.stdin); print(d.get("tool_name"), d.get("permission_mode"), d.get("tool_input",{}).get("command",""))' >> "$D/payload-summary.txt"
onsig() { log "signal-$1"; if [ "$ONSIG" = allow ]; then emit allow "probe late allow after $1"; log "late-allow-emitted"; exit 0; fi; exit 143; }
for s in TERM INT HUP; do trap "onsig $s" $s; done
if [ "$MODE" = cancelfile ]; then
  end=$(( $(date +%s) + HOLD ))
  while [ "$(date +%s)" -lt "$end" ]; do
    if [ -e "$D/cancel" ]; then log "cancel-file-seen returning deny"; emit deny "probe hold cancelled, nothing ran"; log "exit 0"; exit 0; fi
    sleep 0.2 & wait $!
  done
  log "hold-done returning allow"; emit allow "probe hold approved"; log "exit 0"; exit 0
fi
sleep "$HOLD" & CHILD=$!; log "child pid=$CHILD"; wait $CHILD
log "hold-done returning $MODE"; emit "$MODE" "probe $MODE"; log "exit 0"; exit 0
