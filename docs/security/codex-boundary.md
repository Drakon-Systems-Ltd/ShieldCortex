# Codex: the Action Guard boundary (#810)

Codex is **observe-only** for Action Guard. On 2026-10-27 the owner decided that
Action Guard deny-holds are not enforced on the Codex harness runtime.
ShieldCortex installs no Codex hook and does not deny or hold Codex-native tool
calls. This decision is about Codex-native tool calls. It does not by itself
set the Action Guard mode of OpenClaw-owned tools on every install; the
OpenClaw plugin's posture row reports that. This page sets out what reaches
ShieldCortex and what does not, and how sure we are of each part.

`shieldcortex doctor` shows this as the info row **Codex tool boundary** when
it finds a Codex or OpenClaw posture record. The row is info-only, so it never
changes doctor's exit code, including under `--strict`.

## What reaches ShieldCortex

| Path | What happens | Evidence |
|---|---|---|
| Bare Codex (Codex CLI, the Codex VS Code extension, the `~/.codex` daemon) | ShieldCortex is an MCP memory server here, not a tool gate. **Native tools are unguarded:** Codex-native shell and `apply_patch` calls never reach ShieldCortex. Only Codex's own sandbox and approval policy apply. | CONFIRMED: `shieldcortex codex install` writes only an `mcp_servers` entry (`src/setup/codex.ts`; ADR-002 coverage table). |
| Codex run by OpenClaw, OpenClaw-owned tools | Calls to OpenClaw-owned tools, including calls nested inside Codex code mode, go through the ShieldCortex OpenClaw plugin's `before_tool_call` check. | CONFIRMED in **observe mode only**, in one live probe (OpenClaw 2026.10.4, 2026-10-16). Every verdict there was allow. This is what that probe observed, not a statement that this path runs observe-only on every install. A deny or hold on this path has not been tested. |
| Codex run by OpenClaw, Codex-native shell / `apply_patch` through OpenClaw's native hook relay | Unknown. | UNVERIFIED: the probe exposed no native shell tool, so this path was not exercised. |

Do not read the OpenClaw plugin's posture row, or the Codex `memory only — not
a tool gate` row, as cover for Codex-native tool calls.

## Why a benign call can leave no audit row

The OpenClaw plugin writes an audit row for a recognised (non-benign) allow.
A benign allow normally writes no row (`plugins/openclaw/interceptor.ts`;
`actionGuard.auditAllows` in `plugins/openclaw/README.md`). The exceptions are
a contract-drift row and a native-exec observation row (#1025). So an empty
audit for a benign Codex-turn call is expected. It does not mean the check was
skipped.

## What not to do

- Do not add a Codex `PreToolUse` hook to close this gap. Enforcement on Codex
  is out of scope by owner decision. A user-level, unmanaged hook in an
  OpenClaw harness's Codex home can also stop OpenClaw's bounded Codex turns
  from running (reported on #810, not tested by ShieldCortex).
- If you need a tool gate for file and shell work, use a host where
  ShieldCortex gates tool calls: Claude Code, OpenClaw-owned tools, or Hermes.
  See the host table in the [README](../../README.md).
