# Pre-install package vetting (Action Guard, #889 phase 1)

When an agent runs a package install, the Action Guard already raises an approval card. Phase 1 adds what the card never knew: facts about the **package** itself, looked up before the install is allowed.

## What is recognised

| Installer | Forms |
|---|---|
| npm family | `npm install\|i\|add`, `pnpm add\|install`, `yarn add`, `bun add`, `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec` |
| Python | `pip`/`pip3 install`, `python -m pip install`, `uv add`, `uv pip install`, `uvx`, `uv tool run\|install`, `pipx install\|run` |
| MCP config | a newly added MCP server whose `command` is `npx` or `uvx` (the #916 agent-config watch; report-only) |

The package name and the requested version (pinned, range, dist-tag or unpinned) are extracted. Paths, URLs, git specs, tarballs and `-r requirements.txt` yield nothing to look up and are skipped. A custom index or registry flag reports `unchecked`, because public records would not describe it.

## What is checked

The requested spec is resolved to the version that would actually install (npm registry, PyPI JSON), then:

1. **OSV** (`api.osv.dev`) is queried for that exact ecosystem, name and version. Any hit is a finding. An id starting `MAL-` means OSV lists the version as **known malicious**.
2. **Version age.** A version published fewer than `minAgeDays` ago (default 7) is a finding.
3. **Install hooks.** An npm version with `preinstall`, `install`, `postinstall` or `prepare` is a finding. A PyPI release that ships only a source distribution (no wheel) is a finding.

Requests are read-only metadata GETs plus one OSV POST. Nothing is downloaded or run.

## What happens

| Finding | Effect |
|---|---|
| `MAL-` hit | **Blocked**, catastrophic tier, on every posture including advisory (`enforce:false`) and shadow. No approval card, because there is nothing to approve. |
| OSV advisory, new version, install hook, source-only | Plain-English reasons are added to the approval card (`OSV: GHSA-… affects this version`, `published 11 h ago`, `runs a postinstall script on install`) and to the audit row (`packageVetting`). The decision is unchanged: age or hooks alone never block. |
| Lookup failed | Reason `unchecked: <why>` on the card and audit row. Never reported as clean. The install proceeds as the guard would have decided. |

## Failure posture and cache

- Hard 3 s budget for the whole command. Past it, the affected packages are `unchecked`.
- Answers are cached per `ecosystem@name@version` in `~/.shieldcortex/state/package-vetting-cache.json` (directory `0700`, file `0600`) for 6 h.
- **Fail open, except for a cached `MAL-` hit.** If the network is away and an unexpired cached record says the package is malicious, the install is still blocked. For an unpinned or range spec the cached version must be one the spec could resolve to.

## Configuration

```json
{ "actionGuard": { "packageVetting": { "enabled": true, "minAgeDays": 7 } } }
```

`enabled: false` turns the check off entirely. Both keys are optional. The same keys are read by the Claude Code hook, the OpenClaw plugin and the agent-config watch.

## Not in phase 1

Deprecated/archived package detection (#989), maintainer-change checks, `.pth` file inspection, hash-locked/pinning policy, Docker image pulls, and per-signal block/card/observe configuration.
