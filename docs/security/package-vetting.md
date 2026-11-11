# Pre-install package vetting (Action Guard, #889 phase 1)

When an agent runs a package install, the Action Guard already raises an approval card. Phase 1 adds what the card never knew: facts about the **package** itself, looked up before the install is allowed.

## What is recognised

| Installer | Forms |
|---|---|
| npm family | `npm install\|i\|add`, `pnpm add\|install`, `yarn add`, `bun add`, `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec` |
| Python | `pip`/`pip3 install`, `python -m pip install`, `uv add`, `uv pip install`, `uvx`, `uv tool run\|install`, `pipx install\|run` |
| MCP config | a newly added MCP server whose `command` is `npx` or `uvx` (the #916 agent-config watch; report-only) |

The package name and the requested version (pinned, range, dist-tag or unpinned) are extracted. Paths, URLs, git specs, tarballs and `-r requirements.txt` yield nothing to look up and are skipped. npm aliases (`foo@npm:<pkg>@1.0.0`) are vetted by their target. A custom index or registry reports `unchecked`, because public records would not describe it: this covers `--registry` / `--index-url` / `-i` flags before or after the verb and the `npm_config_registry`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL` and `UV_*INDEX*` environment variables set on the command.

## What is checked

The requested spec is resolved to the version that would actually install (npm registry, PyPI JSON), then:

1. **OSV** (`api.osv.dev`) is queried for that exact ecosystem, name and version. Any hit is a finding. An id starting `MAL-` (as the record id or as an alias of another record) means OSV lists the version as **known malicious**.
2. **Version age.** A version published fewer than `minAgeDays` ago (default 7) is a finding.
3. **Install hooks.** An npm version with `preinstall`, `install`, `postinstall` or `prepare` is a finding. A PyPI release that ships only a source distribution (no wheel) is a finding.

**The malicious-package check covers every package in the command.** Registry lookups (version, age, hooks) are capped at 8 packages per command, but OSV `querybatch` requests (chunks of at most 500 packages, a few in flight at a time) cover all of them on their own 3 s deadline, by name+version when the spec pins a version and by name alone otherwise. A chunk that fails, or whose answer does not match its queries, is never read as clean: its packages are reported as `the malicious-package check was unavailable` and a cached `MAL-` hit still blocks. A `MAL-` package therefore blocks whatever its position in the command and whatever the registry does. Past the cap, the other facts are `unchecked`, except that a package past the cap with a name-only `MAL-` hit gets the same registry and version lookup as the first eight (at most 8 such extra lookups per command, on the same deadlines).

A custom-index install and a public install of the same package are separate installs: `npm --registry=X install a@1.0.0; npm install a@1.0.0` vets the public one.

Requests are read-only metadata GETs plus one OSV POST. Nothing is downloaded or run.

## What happens

| Finding | Effect |
|---|---|
| `MAL-` hit | **Blocked**, catastrophic tier, on every posture including advisory (`enforce:false`) and shadow. No approval card, because there is nothing to approve. |
| OSV advisory, new version, install hook, source-only | Plain-English reasons are added to the approval card (`OSV: GHSA-… affects this version`, `published 11 h ago`, `runs a postinstall script on install`) and to the audit row (`packageVetting`). The decision is unchanged: age or hooks alone never block. |
| Lookup failed | Reason `unchecked: <why>` on the card and audit row. Never reported as clean. The install proceeds as the guard would have decided. |

The Action Guard webhook card (#815) carries only fixed phrases, so there each finding appears by kind: `installs a package listed as malicious`, `installs a package version with a published security advisory`, `installs a package version published only days ago`, `installs a package that runs scripts during install` / `… runs its setup code during install`, `could not finish the package check`. The package name, version and OSV id never leave the box on that card; they are on the interactive card and the audit row.

## Failure posture and cache

- Hard 3 s budget for the whole command. Past it, the affected packages are `unchecked`.
- Only `MAL-` hits are cached, per `ecosystem@name@version`, in `~/.shieldcortex/state/package-vetting-cache.json` (directory `0700`, file `0600`) for 6 h. A clean answer is never cached: OSV is asked afresh every time, because reports for a new version arrive in the hours after it is published. A later clean answer evicts a stale hit.
- **A malformed answer is an outage, not a clean answer.** An OSV reply that is not in the documented shape (not a JSON object, an error body, a `vulns` that is not a list, an entry without a well-formed id, or more pages than were fetched) is treated like a failed lookup: `unchecked` for the exact query, `the malicious-package check was unavailable` for that package in the batch. It never evicts a cached hit and never outweighs a malicious answer from the other query. A well-formed `MAL-` entry inside an otherwise malformed reply still counts. `{}` and `{"vulns": []}` are clean.
- **Fail open, except for a cached `MAL-` hit.** If the network is away and an unexpired cached record says the package is malicious, the install is still blocked. For an unpinned or range spec the cached version must be one the spec could resolve to.

## Configuration

```json
{ "actionGuard": { "packageVetting": { "enabled": true, "minAgeDays": 7 } } }
```

`enabled: false` turns the check off entirely. Both keys are optional. The same keys are read by the Claude Code hook, the OpenClaw plugin and the agent-config watch.

## Limits

- **Best effort over recognised shapes.** The block applies to the installer forms in the table above. Wrapped or unusual shapes (`sudo -u bob npm i x`, `(npm i x)`, `{ npm i x; }`, `bun x x`, `uv run --with x`) are not recognised and are not vetted.
- **Index configuration in files.** Only flags and environment variables on the command are seen. A registry or index set in `.npmrc`, `pip.conf` or `uv.toml` is not, so such an install is checked against the public registries.
- **Name-only hits and the unconfirmed-version case.** An unpinned or ranged spec is first asked of OSV by name; a `MAL-` record that affects only other versions of the package (as some widely installed packages have) does not block a clean version, because the version this install would fetch is resolved and asked about, and that version-specific answer is final. Where that version cannot be confirmed (the registry did not resolve it, the version query did not answer, or the command is past the extra-lookup limit) the install stays blocked, with a reason that says OSV lists a malicious release under that name, that the version this install would fetch could not be checked, and that pinning a version is the way through. Pinning a clean version passes.
- **Alias lookups past the cap** are limited to a few records per command.
- **Registry resolution** reads the full npm packument inside the 3 s budget; a very large package may come back `unchecked` for age and hooks (the `MAL-` check is unaffected). Range resolution uses the highest satisfying version, while npm prefers the `latest` tag when it satisfies the range, so the vetted version can differ from the installed one.
- `actionGuard.packageVetting.enabled: false` is dropped under a verified or unverifiable policy lock and under the strict fail-closed posture, in both the top-level `actionGuard` block and the deprecated `interceptor.actionGuard` alias.
- **Alias lookups** are budgeted for the whole command, not per chunk. A `MAL-` record reachable only as an alias of a non-`MAL-` id may be missed past that budget (tracked in #1028).
- **Withdrawn records** on a name-only or batch answer are not distinguishable from live ones (tracked in #1028); a version-specific answer ignores withdrawn records.

## Not in phase 1

Deprecated/archived package detection (#989), maintainer-change checks, `.pth` file inspection, hash-locked/pinning policy, Docker image pulls, and per-signal block/card/observe configuration.
