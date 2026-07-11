# OpenClaw plugin-index reconciler fixtures (#74)

Regression fixtures reproducing the conflicted plugin-install metadata states
observed on fleet host **aiquant (Case)**, 2026-07-11 (GitHub issue #74), plus
the healthy control from host **jarvis** the same day.

Each `*.json` file is a self-contained case for the pure reconciler analyzer
(`reconcilePluginState` in `src/integrations/openclaw-plugin-index.ts`):

```jsonc
{
  "description": "...",           // what field state this reproduces
  "input": { ... },               // ReconcileInput (pre-parsed, no disk/sqlite)
  "expected": {                   // the verdict the analyzer must produce
    "state": "...",
    "severity": "ok|warn|fail",
    "recommendedAction": "...",
    "loadedInIndex": true,
    "enabledInConfig": true
  }
}
```

`input` mirrors the parsed shape of the three authoritative layers:
- `config`  — `~/.openclaw/openclaw.json` → `plugins.entries[id].enabled` + `plugins.allow`
- `installsJson` — legacy `~/.openclaw/plugins/installs.json` → `installRecords[id]`
- `index`  — the latest `installed_plugin_index` row from `~/.openclaw/state/openclaw.sqlite`
  (`install_records_json`, `plugins_json`, `warning`)
- `onDiskVersion` — ground truth from the plugin's on-disk `package.json`
- `projectDirs` — `~/.openclaw/npm/projects/*` dirs matching the plugin (duplicate detection)

**The critical case is `enabled-not-loaded.json`** — the security fail-open where
config reports `enabled:true` but the loaded roster (`plugins_json`) omits the
plugin. This must never silently return `healthy`.
