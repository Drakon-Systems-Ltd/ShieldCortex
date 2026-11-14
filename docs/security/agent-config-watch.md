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

## Watched files

| Tool | User file | Project file | Keys |
|---|---|---|---|
| Claude Code | `~/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.claude.json` | `.claude/settings.json`, `.claude/settings.local.json`, `.mcp.json` | hooks, MCP servers, env, `apiKeyHelper` |
| OpenClaw | `~/.openclaw/openclaw.json`, `~/.openclaw/mcp.json` | | hooks, MCP servers, plugin registrations |
| Cursor | `~/.cursor/mcp.json` | `.cursor/mcp.json` | MCP servers |
| Codex | `~/.codex/config.toml` | | hooks, MCP servers, sandbox, trust, provider |
| Gemini CLI (#965) | `~/.gemini/settings.json` | `.gemini/settings.json` | hooks, MCP servers, command settings (`tools.discoveryCommand`, `tools.callCommand`, `mcp.serverCommand`) |
| VS Code | | `.vscode/tasks.json` | tasks |

Gemini CLI's base-URL overrides are environment variables or `.env` entries,
not `settings.json` keys, so there is no Gemini redirect section. The
system-wide Gemini settings file is not watched. The Gemini files were added
after the watch shipped: the first run that knows them baselines them
silently, so upgrading does not alert on settings you already had. For the
project file this is per project root: a run checks only its session's
project, so each known project is baselined silently the first time a run
visits it after the upgrade. Not yet watched: Gemini's
`general.defaultApprovalMode`, `security.folderTrust.enabled`,
`hooksConfig.enabled/disabled` and `.gemini/.env`.

## Planted instruction files and the settings they target (Oct 2026)

Forever Security showed a web page can drop `AGENTS.md` into `~/Downloads`
without a click; a coding agent later opened there obeys it, weakening Codex's
approval/sandbox/trust settings or pointing Claude Code at an attacker
"gateway" that receives the live login token. The watch covers both halves,
all reported as **high severity** (listed first, "HIGH SEVERITY" in the text,
anomaly 0.9 in the ledger). Values are never shown.

- **Codex `~/.codex/config.toml`**: `codex-sandbox` (`approval_policy`,
  `sandbox_mode`, top level and per `[profiles.*]`), `codex-trust` (each
  `[projects."<path>"] trust_level`, named by path), `codex-provider`
  (`model_provider`, each `[model_providers.*] base_url`).
- **Claude Code settings**: `endpoint-redirect` for `env` keys
  `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_API_KEY`,
  `ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL`, `HTTP_PROXY`,
  `HTTPS_PROXY`, `ALL_PROXY`, `NODE_EXTRA_CA_CERTS` (any case) and top-level
  `apiKeyHelper`. Other env keys stay ordinary "environment variable" changes.
- **Planted files**: `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`,
  `GEMINI.md`, `.claude/settings.json`, `.claude/settings.local.json`,
  `.gemini/settings.json` (#965) and one level of a
  `.codex/` directory, in `~/Downloads`, `~/Desktop`, `$HOME` (instruction files
  only; the real `~/.claude` and `~/.codex` are watched above) and `/tmp` (top
  level). Fixed names only, nothing is walked. Whole-file hash; `.codex/`
  entries by name, type, size and mtime. A drop directory seen for the first
  time is baselined silently; after that an added or changed file alerts
  (`planted-instructions` / `planted-agent-config`) and a removal is silent.

Upgrading is silent. The stored state records a version per section and
file. A section added to an existing file (the Codex settings, the redirect
section) or whose extraction changed (`env`, now without the redirect keys)
is re-baselined without an alert the first time the new build sees it. The
`env` split is exact (an entry's hash does not depend on its section), so an
existing `ANTHROPIC_BASE_URL` never shows as "environment variable removed"
plus "endpoint-redirect added", while a redirect value edited before the
first post-upgrade check still alerts. The Codex sections and `apiKeyHelper`
were never watched before, so their first post-upgrade value is the baseline.
Drop directories new to the state baseline silently as above.

Limits: detection is at session start, not live. A file planted and acted on
within one session is reported only at the next session start, after the
agent may already have obeyed it. Instruction files elsewhere (a cloned repo,
a subfolder of Downloads) are not checked.

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

## Package check of added or changed MCP servers (#889)

When a change adds an MCP server whose `command` is `npx` or `uvx`, or changes an existing one that is, the watch also looks the package up (OSV, registry age, install scripts) and sends any finding as a follow-up notification after that file's change notification (the webhook payload marks it `packageCheckFollowUp: true` and, on that follow-up only, carries the findings as `packageChecks`: up to three `{ name, malicious, reasons }` entries, the same sanitised values the `text` sentence is built from; the change notification itself never carries package results). It is report-only and off the delivery path: the lookups start beside delivery, and nothing in delivering, recording or baselining a change waits for them, so the change notification and the baseline behave exactly as they would without the check, however long the lookups take. The lookups for every changed file run at once (at most five entries per file and five files per run) inside one window that closes by the half-way point of the watch's 5 s budget, and at most 2.5 s after it opens. Follow-ups are sent only after every change notification has been handled, and only while the 5 s budget lasts: one starts only if the time left is at least as long as the slowest change notification took that run, none starts after the deadline, and the watch stops waiting for one still in flight at the deadline. A follow-up that is not delivered (no time left, a delivery error, or cut off by the deadline) is recorded as a `notify-error` audit row and is not retried, because the change itself was already reported and baselined. A follow-up goes only with a change notification that was delivered; a change whose notification failed keeps its baseline and is looked up again on the next run. A package with no findings sends no follow-up. A lookup that fails, is skipped for lack of time or over the file limit, or does not finish within that window is shown as `unchecked` with the reason. The window closes when it ends, however long delivery takes: an answer that arrives after it is dropped, not used late. What is bounded is the wait; a lookup still running is not cancelled, it is handed the window as its own budget and its late answer is ignored. See `package-vetting.md`.
