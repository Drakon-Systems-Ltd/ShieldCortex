# Agent config watch (#916): threat model and limits

The agent config watch hashes the security-relevant keys (hooks, MCP servers,
env, tasks, plugin registrations) of the files that decide what an AI agent or
editor runs on its own, and reports a change ShieldCortex did not make. It runs
at session start in a detached, time-bounded child. Source:
`src/audit/agent-config-watch.ts`.

## What it protects against

- A payload (for example a compromised package's install script) that adds a
  hook, MCP server, task or environment variable to a watched config so it
  re-runs later. The next session start reports the file and the kind of
  change; values are never shown or logged.
- The cheap cover-up of that edit: rewriting the baseline
  (`~/.shieldcortex/state/agent-config-watch.json`) so it already contains the
  change. The baseline is HMAC-SHA256-signed with a key kept apart in
  `~/.shieldcortex/keys/agent-config-watch.key` (directory 0700, file 0600). An
  unsigned, mis-signed, malformed or symlinked baseline, or a baseline deleted
  while its key remains, is **untrusted**: the operator is notified ("watch
  baseline untrusted — review all agent configs"), `doctor` warns, and the
  re-baseline is saved only after the notification and its audit row both
  succeed. Until then nothing is saved and every run re-alerts.
- Using the watcher as a write primitive: state and key writes go through an
  exclusive, randomly named temp file (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600) inside
  directories verified to be real, owned, non-symlink directories. A target that
  is not a regular file is refused (`EUNSAFEPATH`), never replaced.
- Pinning the detached child: watched files are opened non-blocking, `fstat`'d,
  and only regular files up to 1 MiB are read. A FIFO, device, socket or a
  symlink to one is a per-file read error (`ENOTREG`); an oversize file is
  `EFBIG`. Both are reported as health errors and the other files are still
  checked.

## Stated non-goals

- **Same-user tampering is detectable only in its cheap form.** This is
  tamper-evidence, not tamper-proofing. Anything running as the same user can
  read the key, so it can:
  - re-sign a laundered baseline with the readable key, or
  - delete both the baseline and the key, which looks like a first run and is
    baselined silently.
  Neither is detected. Defending against a same-UID attacker who targets
  ShieldCortex specifically needs a key the user cannot read (a separate
  account, OS keychain or hardware key) and is out of scope for this watch.
- **Under `sudo`, own writes do not rebaseline the invoking user's state.** The
  watch uses one home, `os.homedir()`, for the runner, `doctor` and own writes.
  An installer run under sudo writes the rebaseline to root's state, so the
  user's next session start reports ShieldCortex's own change once. This is
  fail-safe (an extra alert, never a missed one).
- A `~/.shieldcortex` or `~/.shieldcortex/state` that is itself a symlink is
  refused (`EUNSAFEPATH`, one audit row per run) rather than written through, so
  the watch records no baseline in that layout.
- Detection is at session start, not live: an edit that is reverted before the
  next session start is not seen. A change made before the very first baseline
  is invisible by design.
