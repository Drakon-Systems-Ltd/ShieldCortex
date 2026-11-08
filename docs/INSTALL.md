# Install details

The README gives the three-line install. This page holds what those commands write, what npm's postinstall step does, how storage maintenance works and how to install without network access to the embedding model. For updating within 5.x see [Updating](UPDATING.md#updating); for the Node floor see [Node requirement](UPDATING.md#node-requirement); upgrading from 4.x starts at [Upgrading to 5](UPGRADING-5.md).

## The three commands

```bash
npm install -g shieldcortex
shieldcortex setup
shieldcortex doctor
```

## What `setup` writes

`setup` is the onboarding command: it prints one host table and asks before wiring each host. `shieldcortex setup claude` skips the table and runs the Claude Code install without asking. That install can write `~/.claude/CLAUDE.md`, `~/.claude.json` and `~/.claude.json.bak-shieldcortex` if it replaces the file, `~/.claude/settings.json` and `~/.claude/settings.json.bak-shieldcortex` if it replaces the file, and `~/.claude/hooks/cortex-memory/` unless any detected hook root already has a cortex-memory directory. If that hook installer runs against a writable OpenClaw root, it can also copy the OpenClaw hook, install or register the realtime plugin, snapshot and rewrite `openclaw.json`, and may restart the gateway. Two older names still work. `quickstart` takes the same targets as `setup`'s guided path, without hook flags or `uninstall`. `install` is not the wizard: it runs that same Claude Code install as `setup claude`, and is kept for existing scripts and the `--without-*` hook opt-outs.

Targets are `claude`, `openclaw`, `hermes`, `copilot`, `codex` and `security`. The hook flags are `--with-stop-hook` (sampled per-turn extraction) and `--with-session-end` (extraction on session exit); absent flags leave existing opt-ins unchanged. [OpenClaw integration](openclaw-integration.md) has the OpenClaw side, including [gateway restart consent](openclaw-integration.md#gateway-restart-consent).

## What postinstall does

If npm skipped the package's lifecycle scripts (for example `--ignore-scripts`, or `ignore-scripts=true` in an npm config), ShieldCortex's postinstall did not run. On a global install that step wires no host. It prints the next step, checks that the database engine loads, writes a default `~/.shieldcortex/config.json` when none exists, refreshes an OpenClaw integration that is already present, and on macOS restarts a dashboard service still running an older build. Skipping it does not skip onboarding: run `shieldcortex setup`, then `shieldcortex doctor`. Without that config file, prompt-time recall stays off until you turn it on. [What postinstall does](openclaw-integration.md#install-time-refresh-postinstall).

## Storage and memory hygiene: `shieldcortex maintain`

For manual storage and memory hygiene, run `shieldcortex maintain`. It consolidates short-term memory (STM) above its cap, backfills missing vectors when the embedding model is cached, vacuums a database with enough free pages, then runs doctor's Memories, Semantic coverage and Disk checks and sends any remaining FAIL to the configured Action Guard webhook (the same FAIL set at most once a day).

The consolidation it applies by default is the first phase of `shieldcortex consolidate`, not Dream Mode: it promotes worthy STM, deletes decayed STM, evicts older unpinned memories from an over-limit tier, and deletes or downvotes near-identical long-term copies. Run `--dry-run` first. A database lock held by another live ShieldCortex process, whether seen before opening or at lock acquisition, skips consolidation, embedding and vacuum. It exits 1 while a FAIL remains. `--dry-run` previews without changing database contents or config, though SQLite may create shared-memory sidecar files. `--json` gives a structured report. Audit-log retention is not part of `maintain` yet (#579), and nothing schedules it yet. [Storage maintenance](UPDATING.md#storage-maintenance) has the thresholds.

## Offline embedding cache

Semantic search downloads a small embedding model on first use. For air-gapped hosts or a mirror, see [Offline embedding cache](offline-embeddings.md). It covers the embedding model only, not every network feature.

## Turning the guard on

Action Guard stays off after install. `shieldcortex doctor` shows the posture per host. A bare `sudo shieldcortex protect` turns it on and pins that posture in a root-owned policy lock; see [Policy lock](UPDATING.md#policy-lock) and [Where it can block](../README.md#where-it-can-block).
