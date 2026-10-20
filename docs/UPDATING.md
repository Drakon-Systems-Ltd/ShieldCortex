# Updating and operations

Operator detail that used to sit on the README: how to update, what 5.3, 5.4 and 5.5 changed, the policy lock, recall prerequisites, and the host-wiring notes. The [changelog](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md) is the release record. Coming from 4.x, read [Upgrading to 5](UPGRADING-5.md) before you install.

ShieldCortex does not replace OpenClaw, Hermes, or Claude memory. Native memory stays the brain. This package is the door.

<a id="node-requirement"></a>

## Node requirement

ShieldCortex 5.x requires Node 22.14+ or Node 24+: Node 22.14 or later within 22.x, or Node 24 or later. Node 20 is no longer supported, and neither is Node 23. npm normally warns on unsupported versions (`EBADENGINE`) and installs anyway; with engine-strict enabled it refuses. On an unsupported Node the database engine fails to load and `shieldcortex doctor` fails. Coming from 4.x, read [Upgrading to 5](UPGRADING-5.md) before you update. Action Guard stays off by default; enable it deliberately.

<a id="updating"></a>

## Updating

Coming from 4.x: back up `~/.shieldcortex` and read [Upgrading to 5](UPGRADING-5.md) first. Within 5.x:

```bash
shieldcortex update
shieldcortex doctor
```

`update` upgrades the package and refreshes the integrations already installed on this box: OpenClaw plugin, skill and hook, Hermes plugin copy, Claude Code hooks, state permissions. It **may restart the OpenClaw gateway**, and on macOS a ShieldCortex dashboard service still serving the old build; running it in a terminal counts as consent, with no further prompt. It asks before wiring hosts that are present but not yet wired; headless runs only list them. Read the final summary even when the command exits 0.

Warnings and re-run commands do not by themselves set the exit code. An npm failure, a failed OpenClaw protection check, or a plugin, hook or Hermes refresh marked unfinished exits 1. Other warnings can exit 0, so read the summary and run `shieldcortex doctor`.

### Restart controls

- `SHIELDCORTEX_SKIP_GATEWAY_RESTART=1` — ShieldCortex never restarts the OpenClaw gateway: not from `update`, not from `shieldcortex openclaw install`, not from npm's postinstall, in a terminal or not. It is checked before any consent. Restart by hand when ready.
- `SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1` and `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1` — a headless `update` (cron, CI, an agent) needs both to apply the OpenClaw protection fix-up and reload the gateway afterwards. Without the first it only reports what it would change; without the second it applies the fix-up but skips the reload.
- `SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1` alone — enough for a headless `shieldcortex openclaw install` to restart the gateway, including the one npm's postinstall runs to refresh an existing OpenClaw integration; that path does not read the reconcile variable.
- `SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1` — set on `npm install -g shieldcortex` to keep postinstall away from `~/.openclaw` entirely: no refresh, no installer, no restart.

### Updating by hand

1. **Package** — `npm install -g shieldcortex@latest`. On a box with an earlier OpenClaw hook or plugin, npm's postinstall refreshes it and can restart the gateway (see Restart controls). How it decides what to refresh: [install-time refresh](openclaw-integration.md#install-time-refresh-postinstall).
2. **Claude Code** — `shieldcortex setup claude` (or the older `shieldcortex install`, the same install) re-runs the hook setup in `~/.claude/settings.json`: missing hooks added, old `npx` entries migrated, timeouts fixed. Existing Stop / SessionEnd opt-ins are left as they are.
3. **OpenClaw** — `openclaw plugins update @drakon-systems/shieldcortex-realtime@latest`, then `openclaw gateway restart` if the hook was refreshed too. `shieldcortex openclaw install` does plugin, hook and restart in one go (`--no-gateway-restart` to skip the restart). Pinned versions, forced reinstall and the update lock: [updating the plugin](openclaw-integration.md#updating-the-plugin).
4. **Hermes** — `shieldcortex hermes install` copies the plugin into `~/.hermes/plugins/shieldcortex`; it gates tool calls once `hermes plugins enable shieldcortex` has run and the local API (`shieldcortex api`) is up. Restart the Hermes gateway after a refresh. `shieldcortex hermes status` reports presence, not enforcement.
5. **Background service** — if you ran `shieldcortex service install`, check `shieldcortex service status`. On `Healthy: no (repair recommended)`, run `shieldcortex service repair` with the mode flag you installed with (`--api`, `--headless` or `--dashboard`). Linux and macOS restart the service; Windows schedules it for the next login.
6. **Doctor** — `shieldcortex doctor` warns when the OpenClaw plugin or Hermes copy is behind the package and names the command to run. It exits 1 on a failure (`--strict` also fails on warnings). Repairs are opt-in flags: `--fix-project-keys`, `--fix-action-guard`, `--fix-hermes-plugin-copies`.

<a id="whats-new-in-510"></a>

## What's new in 5.10

- **One command to keep your memory store tidy.** `shieldcortex maintain` tidies short-term memory when there is too much of it, fills in missing search vectors (once the search model has been downloaded), and shrinks the database file when a fifth or more of it is empty space. It then runs the relevant doctor checks and exits with an error while one still fails, so a scheduled job can alert you; if you have an Action Guard webhook set up, it reports the failing checks there by name, with a note to run `shieldcortex doctor`; the detailed messages stay on your machine and your memories are never sent. It does this at most once a day for the same set. Plain `maintain` makes changes straight away: tidying short-term memory runs the first part of `shieldcortex consolidate` (not its Dream Mode part): it promotes the memories worth keeping, deletes faded short-term ones, removes older unpinned memories from either store when that store is over its limit, and for near-identical long-term memories deletes or downvotes one copy. It never merges memory text and does not archive. Run `shieldcortex maintain --dry-run` first to see what it would do without changing your data; `--json` gives a machine-readable report. See [Storage maintenance](#storage-maintenance). Nothing schedules it yet, and audit-log clean-up is not included yet.
- **`maintain` stays out of the way of a running ShieldCortex.** If another ShieldCortex process is using the database, `maintain` skips the steps that would write to it and still runs the checks, including when that process starts while `maintain` is getting ready and `maintain` detects its live startup lock. The lock itself is hardened in 5.10.3 (see 5.10.3 in the CHANGELOG, #763), and from 5.10.4 a process whose lock record another process has replaced stops claiming the lock at its next check (#813); a brief stale-takeover window remains, see 5.10.4 in the CHANGELOG. Nothing to do on upgrade.
- **5.10.1 — A calmer update screen.** `shieldcortex update` now finishes with one headline (updated, things to check, or failed) and one line per part. Anything that needs you says what happened, why it matters and the one command to run. Action Guard being off is shown as off, not as a warning. A failed OpenClaw protection check always shows red. The full technical detail is still there with `shieldcortex update --verbose`. Nothing to do on upgrade.
- **5.10.1 — Odd file names can no longer scramble your terminal.** The update screen, the allowlist scan and `shieldcortex allowlist` now clean up control and hidden characters in paths, notes and errors before printing them. Ordinary paths look the same. Nothing to do on upgrade.
- **5.10.1 — `service install` and `service status` tell you when something is wrong.** They now exit with an error when the background service cannot be switched on, is not running, or cannot be checked, so a script can notice. Nothing to do on upgrade.
- **5.10.1 — The dashboard is more careful about what it claims.** Needs you says when a number is only the last known count or a minimum, the protection indicator is labelled Iron Dome (it does not cover Action Guard), and "data stays on this computer" follows your cloud sync setting. Scripts reading the X-Ray findings API now get an error, not a zero, when the findings file cannot be read. Nothing to do on upgrade.
- **5.10.2 — Older copies can no longer break `ledger verify`.** If an old ShieldCortex copy (5.2.1 or earlier) shares a database with a current one, it can no longer rewrite the project recorded on chained audit rows, which used to make `ledger verify` fail. It prints an `unexpected migration error ... ShieldCortex #674` line on start-up instead, and carries on. Seeing that line means an old copy is still around: update or remove it. Details: [Older copies sharing a chained database](#mixed-version-ledger).
- **5.10.2 — Repair, doctor and update re-run lines are safe to print.** `shieldcortex repair`, the `doctor` report, the MCP server's start-up error and the re-run lines at the end of `shieldcortex update` now clean up control and hidden characters in paths and error text before printing them, the same way the update screen does. A line break inside an install or log path now shows as `⏎` inside the path instead of starting a separate line. Ordinary text looks the same, and `doctor --json` still shows the raw values. Nothing to do on upgrade.
- **5.10.2 — `allowlist scan --json` escapes hidden characters.** C1 controls, bidi controls, line separators and invisible characters in the JSON output are written as Unicode escapes; the parsed values are unchanged. Nothing to do on upgrade.
- **5.10.3 — More JSON and SARIF output is safe to view in a terminal.** `scan`, `doctor`, `guard readiness`, `maintain`, `ledger verify`, `audit`, `policy-evidence`, `xray`, `mcp scan`, `memories import-native`, `remember` and `env scan` now write control and hidden characters in their JSON or SARIF output as Unicode escapes. Parsed values are unchanged, and output without those characters is the same as before. Nothing to do on upgrade.
- **5.10.3 — X-Ray keeps a findings file it cannot read.** If `xray-findings.json` is damaged or unreadable, a dashboard scan or watch detection that has findings to save no longer replaces it with just the new findings: it leaves the file as it is and reports the problem (the dashboard scan returns the same "could not be read or parsed" error as the findings list, and watch mode prints a warning). Fix or move the file to start recording findings again.
- **5.10.3 — Doctor and `ledger verify` name a likely old copy instead of tampering.** When every problem they report matches the project backfill an old ShieldCortex copy (5.2.1 or earlier) does, the report says that copy is the likely cause and advises upgrading or removing it before repair. Any other damage keeps the existing warning, and checking does not change the database. See [Older copies sharing a chained database](#mixed-version-ledger).
- **5.10.4 — `maintain` stops writing if it loses the database lock mid-run.** If another ShieldCortex process takes over the startup lock while `maintain` is running, `maintain` notices before its next write step and reports that step and the rest as `skipped: locked` instead of carrying on. Nothing to do on upgrade.
- **5.10.5 — `maintain` no longer skips its work after a lock record is copied back.** On a filesystem without hard links, a ShieldCortex process that checked its database lock while its own lock record was being put back could lose the lock for good, so `maintain` went on skipping its write steps as `skipped: locked`. A check at that moment now counts as not owning the lock for that moment only, and the process owns it again once its record is back. Nothing to do on upgrade.
- **5.10.5 — Approving a quarantined item either approves it or says why not.** If the approval re-scan holds the item again, it is now rejected once with the reason (`still held on re-scan: ...`) instead of reappearing as a new pending copy, and the MCP `quarantine_review` reply, the dashboard and `quarantine approve <id>` in the command rail say it was not approved. Nothing to do on upgrade.
- **5.10.5 — The OpenClaw plugin states one minimum: OpenClaw 2026.4.23.** Its peer dependency, manifest and README now match the install compatibility check, which already required 2026.4.23. The README also states the ShieldCortex range the plugin accepts (`^5.0.0`). Nothing to do on upgrade.
- **5.10.5 — Refused approvals are worded by what really happened.** When some items in a bulk or by-source approval cannot be admitted, the dashboard and the `approve_by_source` reply say they were rejected and not added to memory, and the approve dialogs no longer promise promotion or a re-scan. An approval refused because too many memory writes ran in the last minute now says `not admitted (memory write rate limit): ...` instead of `still held on re-scan: ...`. Nothing to do on upgrade.

- **5.10.6 — Public sensitivity types stay as in 5.10.5 (#864).** The attempted four-value compatibility restoration (#859) was fully reverted before release. `SensitivityLevel` still includes `PERSONAL`; public scan and classification results, stored labels, wire payloads and OpenClaw intercept audit entries keep their 5.10.5 sensitivity behaviour. There is no PERSONAL-to-CONFIDENTIAL projection, no precise alias API and no compatibility harness from #859 in this release. Code written against 5.7.0–5.10.5 needs no sensitivity-related source change. Code still written against 5.6.0 that is exhaustive over `SensitivityLevel` needs a `PERSONAL` case; this release does not repair that older source incompatibility. See the changelog's correction to the 5.7.0 notes.
- **5.10.6 — Consolidation keeps tags across overlapping duplicate pairs (#860, PR #862).** When one memory survives several near-duplicate pairs in the same pass, it keeps every deleted duplicate's tags instead of losing tags added by an earlier pair. Memory text is not merged. Nothing to do on upgrade.
- **5.10.6 — Headless denials stay available for review for 48 hours (#682).** `approve --denial` keeps a pending denial identity for 48 hours from its last denial, shows its deadline, and explains an expired or capacity-dropped entry instead of treating it as a typo. The store targets 128 identities, but never drops one with a live card, grant or Deny. Retention grants nothing: approval still makes a one-shot grant lasting 10 minutes by default, at most 60, from approval, not from the next scheduled run. An older binary drops expiry records on its next store write and returns to the old no-match answer. Nothing to do on upgrade.
- **5.10.6 — Help shows usage instead of running the command (#767, #777).** Every dispatched command now honours `--help` and `-h` in an option position, exits successfully and does not open the database, start a server or perform the command's work. A help-looking token consumed as a value remains a value. Top-level `shieldcortex --help` now lists every dispatched command, including the commands for stopping and resuming guarded actions, and describes the full memories group and named-hook invocation correctly. Nothing to do on upgrade.
- **5.10.6 — The update screen only reads Guard posture (#773 follow-up).** Drawing the closing screen no longer rewrites or signs config, creates an integrity key or writes an audit event. If it cannot confirm the setting without writing, it says so and points to `shieldcortex doctor`, rather than claiming Guard is off. Nothing to do on upgrade.
- **5.10.6 — Doctor warns for a fully explained legacy backfill (#834).** When every chained-ledger problem matches the old project backfill and the protecting trigger has the shipped definition on the right table, the row is a warning rather than a failure. Unexplained problems or a missing or different trigger still fail, and ledger verification still reports the inconsistency. Nothing to do on upgrade.
- **5.10.6 — Doctor keeps uncertainty visible while reducing unnecessary warnings (#651, partial).** Confirmed Hermes absence is informational; broken or unreadable paths and an interpreter that cannot be checked remain warnings. The host-table legend explains which configured integrations its gate words cover, and the multiple-install warning lists the observed project directories without claiming any is safe to remove. The Action Guard policy-lock warning is unchanged. Nothing to do on upgrade.
- **5.10.6 — One session can share its lease across the hook and plugin (#854, partial).** The Claude Code hook and OpenClaw plugin now use matching lease identities when both receive the same session id and can derive its key. Leading or trailing spaces in the id and a symlinked ShieldCortex state directory remain exceptions. OpenClaw turns run through the Claude CLI still have different ids and are still refused; that case needs a shared id from OpenClaw. Different sessions remain separate, and an unusable session identity is refused rather than shared. Nothing to do on upgrade.
- **5.10.6 — A startup retry cannot evade a displaced live lock by spelling the database path differently (#837).** Relative paths, normalised paths and symlinked parent directories now resolve to one startup-lock path per database. A retry finds the live record left aside and either refuses before opening SQLite or continues without owning the lock, as for the original spelling. Nothing to do on upgrade.
- **5.10.6 — Quarantine bulk selection counts only items still pending (#831).** After a refresh or an individual review, the selection count, confirmation and submitted ids drop items that left the pending list. Approval and rejection decisions are unchanged. Nothing to do on upgrade.

<a id="whats-new-in-59"></a>

## What's new in 5.9

- **Fewer false stops for scripts that only read a file.** Where the Action Guard is on, a short inline Python, Node, Ruby, Perl or PHP script fed in with `<<` that only reads a data file (for example loading a markdown table or a JSON file and printing it) is allowed again. Only a fixed list of plain read calls qualifies; anything else in the script, such as loading code, running a command or an unusual flag, is checked exactly as before. Nothing to do on upgrade.
- **Checking your global packages no longer blocks other sessions.** Read-only commands such as `npm list -g` or `npm outdated -g` no longer take the session install lock, so they are not refused with "install is held by another session". A real global install (`npm install -g …`, including one run through `npx`, `pnpm dlx` or `bunx`) still takes it. Nothing to do on upgrade.
- **A global install with its output redirected still waits its turn.** A command such as `npm>/dev/null install -g …`, where the redirection is written right against the package-manager name, takes the session install lock again, as it did before the read-only change above. Nothing to do on upgrade.
- **Scripts that run a global install as a list of words now ask first.** Where the Action Guard is on, writing a script file that runs a global package install through a call such as Python `subprocess.run(["npm", "install", "-g", "x"])` or Node `spawn("npm", ["install", "-g", "x"])` now asks for your approval, as the plain `npm install -g x` text already did. Comment lines in a file whose language is known are not counted. Nothing to do on upgrade.

<a id="whats-new-in-58"></a>

## What's new in 5.8

- **Watch what an AI does in a browser or on a desktop.** If you build on the Claude SDK browser-use or computer-use toolsets, the new `shieldcortex/toolsets` export can sit in front of your driver. It labels each click, typed text, page visit and page read, flags typed credentials and unsafe links, scans what the page says back, and writes an audit trail that never stores what was typed or read. By default it only observes and does not change what runs. Set `mode: 'enforce'` and it refuses the riskiest calls outright, holds risky ones (such as irreversible clicks after a page read) for your approval, and lets the rest run. Enforce answers those allowed calls itself without asking the approver you pass to `guard.confirm`, so that approver's own refusals no longer apply to them. Held calls show a short plain-English card that never includes what was typed or the page text; each approval is used once and expires. See `docs/quickstarts/claude-sdk-toolsets.md`.
- **Recall on OpenClaw messages searches what you actually wrote.** OpenClaw 2026.9.x wraps each message in context blocks, and prompt-time recall was searching those blocks instead of your words. It now strips a complete wrapper first. Nothing to do on upgrade.
- **Optional vector recall, off by default.** Prompt-time recall can also rank candidates by meaning: set `"recallVector": true` in the ShieldCortex config file or `SHIELDCORTEX_RECALL_VECTOR=1`. When on, it re-orders and tops up word-matched candidates; it never brings in a memory that shares no word with your prompt.
- **`doctor` spots stuck recall.** A new [Recall repetition](#doctor-recall-repetition) row warns when your last few recalls all returned the same memories. It only reads the recall log and asks you to change nothing.
- **`setup` is the command to start with.** `status`, `doctor` and `--help` now say `shieldcortex setup`, and `shieldcortex setup claude` to repair Claude Code. `install` and `quickstart` still work as before.
- **The threat graph stops at a file it cannot read instead of skipping it.** If a realtime audit day file cannot be read, the threat graph now holds its place at that file and reports the error until the file is readable again, rather than silently moving past it. A damaged saved position now stops realtime updates with a reported error instead of stalling or replaying; restore it or run `shieldcortex threat-graph rebuild`.

<a id="whats-new-in-57"></a>

## What's new in 5.7

- **The bulk Cloud sync button respects your privacy settings.** Syncing held-back items to Cloud from the dashboard now applies the same rules as the automatic sync: confidential items stay on your machine unless you opted in, project and metadata-only settings apply, and personal details and credentials are redacted before anything is sent. A stored item is also graded at least as strictly as when it was first held back, so it cannot slip through as public. The response also reports how many items were skipped. `shieldcortex setup openclaw` now shows every reason the OpenClaw plugin install was refused, and no longer tells npm installs to run `npm run build`. (#711, #723, #715)
- **Action Guard readiness survives upgrades, and memory notes are recorded.** These apply only where the guard is on. With enforce when ready, an upgrade that does not change the guard's policy no longer starts the readiness evidence over; when the policy does change, the old evidence counts at half weight by default (`actionGuard.readiness.priorPolicyCarry` in `~/.shieldcortex/config.json`, 0 to 1; 0 restores "start over") and only after the new policy has its own 100 calls over 48 hours. `shieldcortex guard readiness` and `doctor` show fresh and carried evidence separately. (#719, #721)
- **Writing a memory note that mentions a risky command no longer asks.** Editing `MEMORY.md`, `CLAUDE.md` or a markdown file in a memory folder used to ask for approval when the text named a command such as `sudo` or a service stop. Writing the note runs nothing, so it is now allowed and recorded; catastrophic commands, sensitive paths and running the file are still checked. The guard cannot tell prose from a bare command, so a note that is only a command line is writable too, and on the Hermes REST plane running such a note is not read into the scan. This is part of #629.
- **Automated turns get less of your memory.** When Claude Code recalls memories at the start of a prompt, cron jobs and subagents now get only error, pattern and decision memories, liveness checks get none, and none of them get anything not labelled `PUBLIC`. Your own chat is unchanged. Private-life notes get a new PERSONAL label; run `shieldcortex memories reclassify` to relabel older ones. This covers prompt-time recall only, for turns the hook recognises or that you pin: [Recall lanes](#recall-lanes) lists what it does not cover. (#722, #729)
- **The Claude Code hook reads the right script.** Where the guard is on, a relative script such as `bash scripts/run.sh` is now read from the session's working directory rather than the hook's own. OpenClaw calls with no absolute `workdir` are unchanged. This is part of #634.

## Storage maintenance

`shieldcortex maintain` consolidates STM above its cap, backfills missing vectors (skipped while the embedding model is not cached), and vacuums when at least 20% of database pages are free. When STM is over its cap, plain `maintain` (without `--dry-run`) runs the first phase of `shieldcortex consolidate`, not its Dream Mode phase: it promotes worthy STM, deletes decayed STM, evicts unpinned memories older than one hour in either tier while that tier exceeds `maxShortTermMemories` or `maxLongTermMemories`, and resolves near-identical long-term pairs by deleting or downvoting one of them (memory text is never merged). It does not archive. Run `--dry-run` first to preview. It then runs doctor's Memories, Semantic coverage and Disk checks (not the full doctor) and sends any remaining FAIL, by check name only, to the configured Action Guard webhook; the same FAIL set is sent at most once every 24 hours. While a live ShieldCortex process holds the database, consolidation, embedding and vacuum are skipped, not failed. It exits 1 while a FAIL remains, so a scheduler can alert on it, and exits 2 on an unknown argument. Use `--dry-run` to preview without changing database contents or config; SQLite may create shared-memory sidecar files. Use `--json` for a structured report. Audit-log retention is not included yet (#579), and nothing schedules `maintain` yet.

<a id="whats-new-in-56"></a>

## What's new in 5.6

- **Teardown commands now ask first.** Commands that destroy databases, clusters or cloud resources (for example dropping a table from a database client, an unscoped SQL DELETE, `terraform destroy`, deleting a Kubernetes namespace, `helm uninstall`) used to be allowed and now need your approval. Mentioning them in text, such as a grep pattern or a commit message, does not trigger it. (#503)
- **Clearer approval cards.** A held action's card on your phone now says what the action does, why it was held and who asked, in plain English, without showing the raw command. Targets that match ShieldCortex's credential and secret patterns, or are too long or contain unusual characters, are withheld whole; a secret in a shape those patterns do not know is not guaranteed to be caught. On OpenClaw the approval prompt is marked as a warning whenever it shows one of these cards. (#648)
- **`shieldcortex consolidate` clears short-term memory.** The command doctor recommends for a full short-term store now actually drains it: it promotes, expires and evicts memories before Dream Mode, and can evict long-term memories when that store is over its limit. Doctor's short-term and long-term warnings now follow your configured limits, so `shieldcortex doctor --strict` may exit differently on the same store. (#650)
- **A tidier local dashboard.** The old one-page-per-feature URLs from the first dashboard now redirect to the tab that replaced them, Replay sits in the Memory tab bar, and Protection and Settings tabs switch normally after you arrive from a deep link. (#688)
- **A simpler dashboard layout.** The sidebar is down to five items: Home, Needs you, Memory, Protection and Settings. **Needs you** gathers what is waiting on a person: held-back items, memories that disagree or look duplicated, and new scanner findings, each linking to where you decide. Labels use plain words (Quarantine is now Held back, X-Ray is the Skill & package scanner), the dark theme is the default and text is larger. Every existing URL keeps working. (#690)
- **Fewer false stops from the Action Guard, and fewer ways around it.** Where the guard is on, a script file now follows the nested script calls the guard recognises, as the same line written inline already did (#661). Not every way of running a second file is recognised yet. Short inline scripts fed in with `<<` are still checked as in 5.5.0: a planned relief for them was withdrawn before release because it let code-loading scripts through unchecked (#713 tracks a safer design). A file stored at one of the sensitive paths the guard protects is never read into the guard's scan text; it is asked about on its path and is never auto-allowed (#702). Prose such as "Look at the findings" in source you write no longer reads as a scheduler command; real `at` and `crontab` calls still ask (#691).
- **`--help` is safe.** `shieldcortex install --help`, `setup --help` and `doctor --help` print usage and do nothing else. Before, `install --help` installed, `doctor --help` ran every check, and `setup --help` exited 1 (#707).

<a id="whats-new-in-55"></a>

## What's new in 5.5

- **See how each runtime is configured to enforce.** `shieldcortex policy-evidence` prints a JSON envelope (schema, scope, limitations, summary) with a `records` array: one record per runtime, profile, plane and reporting instance this host has evidence for (Claude Code hook, OpenClaw plugin, Hermes plugin; Codex and Copilot appear as memory-only, not-a-gate records). Each record says whether the integration is installed and loaded, its configured posture, its scanner and any observed real block, each with its own evidence and timestamp. A runtime with no self-report shows as `unobserved`, and stale evidence is marked obsolete rather than trusted; the inventory covers what reported here and does not prove every running process was seen. `shieldcortex doctor` shows the same records as info-only rows. The records are local self-reports, not attestation, and the output says so. They show configuration: with enforce when ready on, a Claude Code record can say `enforce` while the readiness gate still has the guard watching; `shieldcortex guard readiness` shows the live gate. (#613)
- **Dependency security update.** The MCP SDK moves to 1.31.0, past a published advisory in its OAuth client (which ShieldCortex does not use). Production audit: 0 unwaived advisories, 4 waived; reachability notes are in [audit-waivers.md](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/docs/security/audit-waivers.md). (#655)
- **Approving on a Mac works again.** In 5.4.0 `shieldcortex approve` refused every human on macOS, so blocked actions could not be approved there. It now finds your Terminal.app or SSH session correctly and still refuses agent-owned shells. It also refuses, rather than guesses, when it cannot read the whole process tree, so on a Linux host with restricted `/proc` even a real login shell may be unable to approve.
- **No more scan stalls on long blank runs.** A long run of newlines could stall a scan for 30 seconds or more. Detection is unchanged.

Full detail: [CHANGELOG](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md).

<a id="whats-new-in-54"></a>

## What's new in 5.4

- **Action Guard: enforce when ready.** A third posture beside off and enforce. `shieldcortex config --action-guard-enforce-when-ready` (or the new setup question) runs the dangerous tier in shadow, logging what it would have held or blocked while the call proceeds. It enforces only once this install's own audit log shows the guard is operable (low intervention rate, approvals reliably answered through a configured channel) and reviewed effectiveness evidence for the running version exists. No such evidence ships yet, so today this posture stays in shadow and says so. The Claude Code hook and the OpenClaw plugin each measure and promote on their own calls; the Hermes plugin ignores the gate and enforces. (#509)
- **`shieldcortex guard readiness`** shows each surface's posture, mode, thresholds, samples and what is missing. `shieldcortex guard test-approval` sends a labelled synthetic request to prove your approval channel works.
- **Loud demotions.** Falling back from enforcing to shadow prints to stderr, writes an audit row, sends a webhook notice and makes `shieldcortex doctor` fail. Promotions are announced on the same webhook.
- **Guard self-protection floor, in every mode while the guard is on.** Calls that touch the guard's own state, config, lease ledger or policy lock are held or denied even in watch-only and shadow, and only a human answer releases them. This changes behaviour for watch-only installs.

Full detail: [CHANGELOG](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md).

## What's new in 5.3

- **The injection scanner catches more.** Spoofed authority lines inside tool results (`ADMIN: you must …`, `SYSTEM OVERRIDE:`), “repeat everything above” extraction requests, explicit injection phrases in ten languages, and ROT13-encoded instructions. Content that passed before can now be quarantined by the memory firewall. It is a detection floor: reworded attacks in any language still pass. (#506)
- **Chained audit ledger and `shieldcortex ledger verify`.** New audit rows are hash-chained; existing rows are kept as unchained pre-chain history. A `Chained ledger` doctor row reports edits or mid-history deletions; a fully explained legacy `project` backfill with the protecting trigger present is a warning, while other inconsistencies are failures. The chain is local with no external anchor: it cannot show completeness, or detect a chain rewritten as a whole or cut at the tail. (#617, #834)
- **`shieldcortex update` reports OpenClaw plugin installs honestly.** A slow install is no longer called a failure; a plugin or skill step left unresolved is listed in the footer with its exact re-run command, and a native plugin install that failed and did not land exits 1. (#604, #583)
- **Releases ship with npm provenance.** `npm audit signatures` can verify both packages were built by this repository's release workflow. (#608)
- **5.3.1 — Action Guard on OpenClaw's Codex harness.** `gateway_exec` / `gateway_process` calls now resolve to the native exec/process contracts instead of being rejected as unknown tools and cancelled. (#622)

Full detail: [CHANGELOG](https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md).

<a id="mixed-version-ledger"></a>

## Older copies sharing a chained database

One host often has more than one ShieldCortex copy: a global install, a project dependency tree, a cached plugin or a Hermes plugin copy. Copies at 5.2.1 or older predate the chained ledger. Every time one of them starts, it fills in `project` on audit rows that have none. A copy at 5.3 or later skips chained rows. An older copy does not, so it used to change chained rows, and the next `shieldcortex ledger verify` failed. (#674)

The database now refuses that change, whichever copy issues it. Once a current build has opened the database, any change to the `project` of a chained audit row is aborted. An update that leaves the value as it was still goes through.

If an older copy changed chained rows before the trigger was installed, `shieldcortex doctor` shows a warning when every ledger problem matches that legacy `project` backfill and the protecting trigger is present. It still shows a failure for mixed or unexplained problems, or when the trigger is missing. A trigger that only shares the name, with a different definition or on another table, counts as missing. `shieldcortex ledger verify` still reports the ledger as inconsistent. Opening an existing chained database with ShieldCortex 5.10.2 or later recreates the trigger when nothing holds its name. It never replaces a different trigger that already holds the name: remove that trigger first, then open the database with a current ShieldCortex to install the shipped one. `shieldcortex doctor` says which case applies.

What you may see:

- **On an older copy's stderr, at each start:**

  ```
  [database] unexpected migration error in defence_audit/quarantine project backfill (data migration): ShieldCortex #674: project of a chained defence_audit row is immutable (an older ShieldCortex build may be opening this database)
  ```

  This means an old copy started against this database and was stopped before it changed any chained row. The old copy carries on starting. Update or remove that copy. If something alerts on `unexpected migration error`, this line will trigger it.
- **Deferred backfill.** Only the refused statement is rolled back. A backfill statement the old copy completed earlier in that start (for example filling in `project` on unchained rows from their linked memories) stays committed; that is harmless, because unchained rows are outside the chain. The old copy's remaining backfill steps, including held-back (quarantine) items, are skipped for that start. The next start of a current build fills them in. Nothing is lost.

What this does not cover:

- **It is compatibility protection, not a tamper boundary.** Anyone with write access to the database can remove the trigger. Detecting tampering is still the job of `shieldcortex ledger verify` and the `Chained ledger` doctor row. Other columns of chained rows are not guarded, and edits to them are reported by `ledger verify` as before.
- **Older copies still write unchained rows and still delete rows without a checkpoint.** An old copy that logs an audit event adds a row without chain columns, which `ledger verify` reports as `unchained-row-after-start`. An old copy that runs retention deletes rows without recording a checkpoint, which `ledger verify` reports as a gap. Neither is blocked. The fix is to update or remove old copies.
- **`shieldcortex doctor` does not yet look for stale copies.** Finding the old copy is up to you for now.

<a id="policy-lock"></a>

## Policy lock

```bash
sudo shieldcortex protect
shieldcortex config --policy-status
shieldcortex memories reclassify
```

Root, once. A bare `protect` reads nothing from `config.json`: it pins the safe posture — Action Guard **enabled and enforcing**, empty auto-approve and reviewed-script lists, broker off — so this is also the moment Guard turns on. `sudo shieldcortex protect --from-config` pins your current protected settings instead — the Action Guard block, plus defence mode and memory posture where `config.json` sets them — including a Guard that is off. Either way an agent cannot quietly loosen the pinned keys afterwards. There is no `unprotect` command. Recovery is a human at a root shell — [runbook](design/2026-09-16-501-policy-lock.md).

<a id="dashboard-recall-and-cloud"></a>

## Dashboard, recall, and Cloud

Local UI (5.6+): **Home · Needs you · Memory · Protection · Settings**. The Skill & package scanner (formerly X-Ray) is a Protection tab. Memory has Search & browse / Map / Recall / Needs a check / Timeline / Replay / Files. Prompt-time recall into Claude Code needs two things: the Claude Code `UserPromptSubmit` hook, which `shieldcortex setup` adds once you agree to wire Claude Code (or `shieldcortex install`), and `proactiveRecall: true` in `~/.shieldcortex/config.json`. A fresh global, non-CI `npm install -g` with no config file writes one with `proactiveRecall: true` when that write succeeds; local and CI installs do not, an existing config is never changed, and when the key is not set, recall is off. The npm install does not wire Claude Code's `UserPromptSubmit` hook; npm's postinstall can still refresh an existing OpenClaw integration (see [Updating by hand](#updating-by-hand)). Turn it off under Settings → Integrations or with `shieldcortex config --proactive-recall false`.

Two different apps.

- **Local** (`shieldcortex dashboard`) — the npm package UI above. Runs on your machine. The Skill & package scanner (formerly X-Ray) lives here, under Protection.
- **Cloud** — fleet view: Shield, Capture, Recall, Library, Graph, Replay, Review, Quarantine, Dome, Devices, Keys. Default chrome is glass (Shield), not the CIC terminal. Cloud does not ship X-Ray.

Free cloud: 500 scans/month, 7-day retention, 1 member. Enterprise (fleets, SSO, full replica): sales@drakonsystems.com.

<a id="connect-a-box"></a>

### Connect a box

```bash
shieldcortex config --cloud-api-key <key>
shieldcortex config --cloud-enable
shieldcortex service install --headless   # always-on servers
```

On a Linux host without systemd user services (no `systemctl`, or no user bus), `service install --headless` writes the unit but exits non-zero with `Failed to enable service`; run `shieldcortex worker` in the foreground there instead.

<a id="recall-lanes"></a>

### Recall lanes and the PERSONAL tier

Prompt-time recall is scoped by **lane** as well as project, because on a single-workspace box the owner's chat, cron jobs and liveness probes all share one project key. The `UserPromptSubmit` hook decides the lane for each turn from markers that OpenClaw's own prompt builders write (`[cron:…]`, `[Subagent Task]`, `Automated liveness check`, heartbeat prompts) or from an operator pin:

| Lane | Default recall |
|---|---|
| `interactive` | everything (unchanged) |
| `cron` | categories `error`, `pattern`, `decision` |
| `subagent` | categories `error`, `pattern`, `decision` |
| `automation` | none |

Change the categories, or opt `automation` in, with `recallLanes` in `~/.shieldcortex/config.json`, e.g. `"recallLanes": { "automation": { "recall": true } }`. One rule is not configurable: a lane other than `interactive` only ever receives rows labelled `PUBLIC`. Unlabelled rows count as `INTERNAL` and are withheld, and so is any label that is not exactly `PUBLIC` after trimming and ASCII upper-casing (a look-alike such as `publıc` is an unknown label and stays withheld). Withheld rows still appear in the recall log (`~/.shieldcortex/recall-log/`) with a `lane_policy:*` drop reason; the log also records `lane` and `laneSignal` for every turn.

**PERSONAL** is a sensitivity tier between `INTERNAL` and `CONFIDENTIAL` for private-life notes (a family trip, a surprise party, "don't let her know"). New writes are classified automatically. The owner's own interactive recall still sees PERSONAL rows; automated lanes never do. A PERSONAL row that also names an identifier (an email, a tax reference, a salary) is raised to `CONFIDENTIAL` like any other row.

**What lanes do not cover.** Lanes apply only to prompt-time recall in the `UserPromptSubmit` hook, and only to turns that hook detects from a marker or reads from a valid pin; an unmarked, unpinned turn from another scheduler is `interactive`. The stored label is what keeps a private note out: a note the classifier missed and labelled `PUBLIC` can still reach a non-interactive lane. SessionStart context, MCP tool reads (`recall`, `get_context` and the rest) and dashboard previews are not lane-scoped.

#### Pinning a lane: `SHIELDCORTEX_RECALL_LANE`

A job started by something other than OpenClaw (a systemd timer, crontab, CI) writes no marker, so its turns look interactive and get the owner's full recall. Set the pin in that job's environment:

```bash
SHIELDCORTEX_RECALL_LANE=cron       # or automation, subagent, interactive
```

- Valid values: `interactive`, `cron`, `automation`, `subagent` (case and surrounding spaces are ignored). A valid pin wins over any marker in the prompt.
- Unset or blank: no pin; the lane comes from prompt markers, and an unmarked turn is `interactive`.
- **Any other value fails safe:** the turn is treated as `automation` (no recall unless you opted `automation` in, and then PUBLIC rows only). The recall log shows `laneSignal: "env:SHIELDCORTEX_RECALL_LANE:invalid"`, and `shieldcortex doctor` prints a WARN on its **Recall lane** row naming the bad value.

#### Doctor: Recall repetition

`shieldcortex doctor` reads the last few recall-log entries and warns on its **Recall repetition** row when the newest 4 `interactive` runs all returned the same top-k candidate set (at least 3 candidates). That was the sign of #717, where the recall query was built from the OpenClaw envelope instead of your words. The check only reads. It prints counts, never prompts, titles, ids or hashes. It skips cron, automation, subagent and unlabelled runs, and it treats 4 identical prompt hashes as one prompt asked 4 times, which does not warn.

The warning is repetition evidence, not a proven root cause: asking about the same topic repeatedly, or an unmarked scheduled job recalling as `interactive`, does the same. It does not ask you to change any setting. If the log is missing, too short, has a gap with older entries behind it, or is unreadable, corrupt or oversized, the row is INFO "not checked" and never a pass.

<a id="reclassify"></a>

#### Backfilling labels: `shieldcortex memories reclassify`

The classifier only labels new writes, so rows stored before the PERSONAL tier keep the label that let them into automated lanes. `reclassify` re-runs the current classifier over stored rows and **raises** labels that are now too low. It never lowers a label, and it never touches a row whose label is outside the ladder (`PUBLIC` · `INTERNAL` · `PERSONAL` · `CONFIDENTIAL` · `RESTRICTED` · `SECRET`), including non-ASCII look-alikes.

```bash
shieldcortex memories reclassify --project my-project            # dry run (default)
shieldcortex memories reclassify --project my-project --execute  # apply
```

1. **Dry run first.** It prints how many rows were scanned, how many it would raise, the from→to transitions, the classifier labels behind the raises, how many were skipped for an unknown label, and the ids. It lists ids and labels only, never titles or content. If one label accounts for most of the raises, check a few of those rows before applying: that is the usual sign of false positives.
2. **`--execute`** re-plans and writes. Each raise is a compare-and-update: it only lands if the row still has the label, title, content and project the plan saw. The output reports:
   - **Applied**: raises written.
   - **Stale**: rows that changed between plan and write (relabelled, edited, moved to another project, deleted). They are left exactly as the other writer left them, with their ids listed. Re-run to re-plan them.
   - **Skipped (unknown label, never touched)**: rows outside the ladder.

Omit `--project` to scan every project. `--dry-run` and `--execute` cannot be combined.

<a id="claude-code-hook-fallback"></a>

## Claude Code hook fallback

For Claude Code PreToolUse, a hook load failure still blocks recognised catastrophic commands through a bounded fallback scan, even with the guard off (with the guard on, unparseable input gets the same scan). The patterns are blunt text matches, so while the hook is broken they also stop routine recursive force-deletes, such as clearing a build folder; `shieldcortex doctor` shows the repair. Calls that don't match keep the fail-open behaviour so an unavailable guard does not stop other unattended work.

## Doctor and the host table

`shieldcortex doctor` prints the same host table — `memory + tool gate` or `memory only — not a gate` per host. It shows the live Guard posture for Claude Code and OpenClaw; for Hermes the host-table row only reports whether the plugin copy is present. Separate info-only runtime-posture rows (5.5+, see `shieldcortex policy-evidence`) report what each runtime's own self-report says, Hermes included. It will not print “protected” for a host that cannot deny.

Bare `setup` (alias `quickstart`) prints one host table and asks before wiring; `setup <host>` wires that host without asking. Claude Code and OpenClaw get hooks that can **deny**. Hermes gets the plugin copy, which gates tool calls once you run `hermes plugins enable shieldcortex` with the local API up. Codex / Cursor / VS Code get an MCP memory server — a scanner the model may call, not a tool gate.

| Host | Memory scan | Tool gate |
|---|---|---|
| Claude Code | yes | bound (PreToolUse) |
| OpenClaw | yes | bound (`before_tool_call`) |
| Hermes | via local API | bound (`pre_tool_call`) |
| Codex / Cursor / Copilot / MCP | if the agent calls the tools | **unbound** |
| LangChain / Python SDK | if you call `scan` / `save` | **unbound** |

## Integrations

| Platform | Command | Bound? |
|---|---|---|
| Claude Code | `shieldcortex setup` | tool gate |
| OpenClaw | `shieldcortex setup` / plugin `@drakon-systems/shieldcortex-realtime` | tool gate |
| Hermes | `shieldcortex hermes install` + `hermes plugins enable shieldcortex` | tool gate (needs the local API) |
| Codex / VS Code / Cursor | `shieldcortex setup` | MCP only |
| JS | `import … from 'shieldcortex'` | ESM only |
| Python | `pip install shieldcortex` | Cloud `scan()` |

### ESM only

`shieldcortex` ships as ESM only (`"type": "module"`, no CommonJS build). Every entry point works with:

```js
import { runDefencePipeline } from 'shieldcortex';
const shieldcortex = await import('shieldcortex');
```

A bare `require('shieldcortex')` fails on purpose with a fix in the error ([#134](https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/134)).

## CLI

```bash
shieldcortex setup
shieldcortex doctor
shieldcortex update
shieldcortex dashboard
shieldcortex scan "text"
shieldcortex env scan <url>
shieldcortex xray <path>
shieldcortex ledger verify
shieldcortex guard readiness
shieldcortex protect
shieldcortex config --policy-status
```

`shieldcortex --help` is the live list. Config lives in `~/.shieldcortex/config.json` — use `shieldcortex config`. Do not hand-edit signed Guard flags.
