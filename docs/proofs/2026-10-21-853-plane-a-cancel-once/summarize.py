#!/usr/bin/env python3
"""Scrubbed summary of one case dir: counts and timings only, no session/tool ids or tokens."""
import json, os, re, sys
D = sys.argv[1]
def rd(n):
    p = os.path.join(D, n)
    return open(p).read() if os.path.exists(p) else None
ev = [json.loads(l) for l in (rd("stream.jsonl") or "").splitlines() if l.strip()]
tool_uses = [c for e in ev if e.get("type") == "assistant" for c in e["message"].get("content", []) if c.get("type") == "tool_use"]
tool_results = [c for e in ev if e.get("type") == "user" for c in (e["message"].get("content") or []) if isinstance(c, dict) and c.get("type") == "tool_result"]
hooks = [(e.get("subtype"), e.get("outcome"), e.get("exit_code")) for e in ev if e.get("type") == "system" and str(e.get("subtype", "")).startswith("hook_")]
final = [e for e in ev if e.get("type") == "result"]
dbg = rd("debug.log") or ""
dbg_lines = [re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27}", "<uuid>", l) for l in dbg.splitlines()
             if re.search(r"Hooks: PreToolUse|Hook PreToolUse|timed out|cancel|abort|SIGTERM|SIGINT|Shutting down|onFailure", l, re.I)]
out = {
    "marker_lines": (rd("marker.txt") or "").splitlines(),
    "hook_invocations": len((rd("hook-invocations.txt") or "").splitlines()),
    "hook_log": [re.sub(r"claude_pid=\d+", "claude_pid=<pid>", l) for l in (rd("hook.log") or "").splitlines()],
    "controller_log": [re.sub(r"claude_pid=\d+", "claude_pid=<pid>", l) for l in (rd("controller.log") or "").splitlines()],
    "payload_summary": (rd("payload-summary.txt") or "").splitlines(),
    "stream_tool_use_count": len(tool_uses),
    "stream_tool_result_count": len(tool_results),
    "stream_tool_results": [{"is_error": r.get("is_error"), "content": str(r.get("content"))[:240]} for r in tool_results],
    "stream_hook_events": hooks,
    "stream_final_result": [{"subtype": f.get("subtype"), "is_error": f.get("is_error"), "num_turns": f.get("num_turns"), "result": str(f.get("result"))[:240]} for f in final],
    "debug_hook_lines": [l[:300] for l in dbg_lines][:20],
    "result": (rd("result.txt") or "").strip(),
}
print(json.dumps(out, indent=1))
