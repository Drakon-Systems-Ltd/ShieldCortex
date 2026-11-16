# Pre-install package vetting (Action Guard, #889 phase 1)

When an agent runs a package install, the Action Guard already raises an approval card. Phase 1 adds what the card never knew: facts about the **package** itself, looked up before the install is allowed.

## What is recognised

| Installer | Forms |
|---|---|
| npm family | `npm install\|i\|add`, `pnpm add\|install`, `yarn add`, `bun add`, `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec` |
| Python | `pip`/`pip3 install`, `python -m pip install`, `uv add`, `uv pip install`, `uvx`, `uv tool run\|install`, `pipx install\|run` |
| MCP config | an added or changed MCP server whose `command` is `npx` or `uvx` (the #916 agent-config watch; report-only) |

The package name and the requested version (pinned, range, dist-tag or unpinned) are extracted. Paths, URLs, git specs, tarballs and `-r requirements.txt` yield nothing to look up and are skipped. npm aliases (`foo@npm:<pkg>@1.0.0`) are vetted by their target. A custom index or registry reports `unchecked`, because public records would not describe it: this covers `--registry` / `--index-url` / `-i` flags before or after the verb and the `npm_config_registry`, `PIP_INDEX_URL`, `PIP_EXTRA_INDEX_URL` and `UV_*INDEX*` environment variables set on the command.

## What is checked

The requested spec is resolved to the version that would actually install (npm registry, PyPI JSON), then:

For npm, exact pins use the per-version manifest endpoint; ranges and tags use abbreviated registry metadata. Publication age comes only from the packument's top-level `time[version]`, never a version manifest's `time`. After resolving the version the checker can make **one full metadata request per command, shared by exact pins and ranges/tags**, to read that entry. If abbreviated metadata lacks the selected manifest, that same allowance can instead fetch full metadata to finish resolution. Selection follows npm-pick-manifest. For a bare install or `@*`, the `latest` tag is taken whatever its version, including a prerelease and a package that only has prereleases. For any other range, `latest` is taken only if it satisfies the range, and a prerelease is not taken unless the range names one (`x` and `>=1` do not). In both cases `latest` must not be deprecated and its `engines.node` must accept the Node that runs the check (see Limits). Otherwise the pick follows npm's fallback order: a version that is both compatible and not deprecated, then compatible, then not deprecated, then the highest version. An explicitly requested tag (`@latest`, `@beta`) resolves to exactly that tag, even when it is deprecated, a prerelease or restricted by `engines`. `engines.npm` is not judged, because the version of the npm that will install is not known. When the selected manifest declares `engines.npm` and npm would pick a different version if the installing npm failed it, that version is still the one checked: its OSV answer, publication age and install hooks are reported. A name-only `MAL-` hit for the package is kept as well, and the install is blocked with a reason that says npm may fetch another version, which was not checked. No second version is looked up. All requests use the same 3 s registry deadline. When the allowance is spent, age reports `unchecked: publication time lookup limit reached (one full npm metadata request per command)`; a missing manifest that needs full metadata reports `unchecked: version resolution metadata lookup limit reached (one full npm metadata request per command)`. Missing time or a failed age request is also reported as unchecked. Version, OSV and install-hook checks continue after an age failure. With `minAgeDays: 0`, no age fallback request is made; a full metadata request is still possible if needed to resolve a missing manifest.

1. **OSV** (`api.osv.dev`) is queried for that exact ecosystem, name and version. Any hit is a finding. An id starting `MAL-` (as the record id or as an alias of another record) means OSV lists the version as **known malicious**.
2. **Version age.** A version published fewer than `minAgeDays` ago (default 7) is a finding.
3. **Install hooks.** An npm registry tarball version with `preinstall`, `install` or `postinstall` is a finding. `prepare` alone does not run on a normal registry tarball install and is not counted. A PyPI release that ships only a source distribution (no wheel) is a finding.

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
- Only `MAL-` hits are cached, per `ecosystem@name@version`, in `~/.shieldcortex/state/package-vetting-cache.json` (directory `0700`, file `0600`) for 6 h. A clean answer is never cached: OSV is asked afresh every time, because reports for a new version arrive in the hours after it is published. A later clean answer evicts a stale hit. Each check writes only the records it added or evicted, on top of the file as it is at that moment. A short lock coordinates separate writers, and a temporary file is renamed into place atomically. A lock older than 30 s is recovered only when its recorded process is gone; a separate exclusive recovery guard serializes the stale check and unlink. Live and ownerless locks are left in place; an abandoned recovery guard conservatively disables automatic recovery until removed externally. Cleanup removes either lock only while its inode still matches the one acquired. An eviction removes only the record its check saw when it started (same time and ids), and never one written in this process after that check started. So when two checks of the same version overlap and one gets a clean answer while the other gets a malicious one, the malicious record is the one left, whichever finishes last; the same holds for two answers about one version inside a single check. Two clean answers evict the record, and so does a clean check that starts after the malicious one has written. An expired record is dropped at the next write and never blocks. A cache lock that cannot be acquired promptly leaves that write unapplied; the current malicious verdict still blocks.
- **A malformed answer is an outage, not a clean answer.** An OSV reply that is not in the documented shape (not a JSON object, a key OSV's answer does not have such as an error body, `results` on a single query or anything else, a `vulns` that is not a list, an entry without a well-formed string id, an entry whose `withdrawn` is not an RFC 3339 date-time with every field in range (an impossible date such as 30 February, or 29 February in a common year, or hour 24 is malformed, not a withdrawal) or whose `aliases` is not a list of strings, or more pages than were fetched) is treated like a failed lookup: `unchecked` for the exact query, `the malicious-package check was unavailable` for that package in the batch. It never evicts a cached hit and never outweighs a malicious answer from the other query. A malformed entry contributes nothing, so a bad `withdrawn` cannot withdraw a record; a well-formed `MAL-` entry inside an otherwise malformed reply still counts (in a batch reply, including one that carries an error key, only when its results still line up one-to-one with the queries). `{}` and `{"vulns": []}` are clean.
- **Malformed cache rows are isolated.** Rows with invalid field types, invalid versions or a key that disagrees with their package identity are ignored individually and removed on the next write, including after a clean check. Valid sibling records are retained. A malformed unchecked sibling cannot cancel an online or valid cached `MAL-` hit.
- **Fail open, except for a cached `MAL-` hit.** If the network is away and an unexpired cached record says the package is malicious, the install is still blocked. For an unpinned or range spec the cached version must be one the spec could resolve to. An ownerless lock left by a crash before its PID was written cannot be safely distinguished from a paused live writer; cache writes remain skipped until that lock is removed externally.

## Configuration

```json
{ "actionGuard": { "packageVetting": { "enabled": true, "minAgeDays": 7 } } }
```

`enabled: false` turns the check off entirely. Both keys are optional. The same keys are read by the Claude Code hook, the OpenClaw plugin and the agent-config watch.

## Limits

- **Best effort over recognised shapes.** The block applies to the installer forms in the table above. Wrapped or unusual shapes (`sudo -u bob npm i x`, `(npm i x)`, `{ npm i x; }`, `bun x x`, `uv run --with x`) are not recognised and are not vetted.
- **Index configuration in files.** Only flags and environment variables on the command are seen. A registry or index set in `.npmrc`, `pip.conf` or `uv.toml` is not, so such an install is checked against the public registries.
- **Name-only hits and the unconfirmed-version case.** An unpinned or ranged spec is first asked of OSV by name; a `MAL-` record that affects only other versions of the package (as some widely installed packages have) does not block a clean version, because the version this install would fetch is resolved and asked about, and that version-specific answer is final. The exception is an npm pick that depends on the installing npm's `engines.npm` (above): there the name-only hit still blocks, and pinning a version is the way through. Where that version cannot be confirmed (the registry did not resolve it, the version query did not answer, or the command is past the extra-lookup limit) the install stays blocked, with a reason that says OSV lists a malicious release under that name, that the version this install would fetch could not be checked, and that pinning a version is the way through. Pinning a clean version passes.
- **The Node and npm that will install are not known.** `engines.node` is judged against the Node running the hook or plugin, which may not be the Node the installer runs under (another `nvm` version, a container, a CI image). If the two disagree about a manifest, npm can pick a different version from the one checked, and that version's facts are not reported. A name-only `MAL-` hit is not kept for this case. For `engines.npm`, a name-only hit is kept as described above, but the other version is not checked. If the name-only answer for the package was unavailable, the checked version is reported and nothing about the other version is.
- **Alias lookups past the cap** are limited to a few records per command.
- `actionGuard.packageVetting.enabled: false` is dropped under a verified or unverifiable policy lock and under the strict fail-closed posture, in both the top-level `actionGuard` block and the deprecated `interceptor.actionGuard` alias. That applies to the tool-call check in the hook and the plugin. The agent-config watch reads `enabled: false` from `config.json` as written, lock or not, so the opt-out always stops its report-only lookups (they cannot block anything either way).
- **Alias lookups** are budgeted for the whole command, not per chunk. A `MAL-` record reachable only as an alias of a non-`MAL-` id may be missed past that budget (rolling follow-up #1075).
- **Withdrawn records** on a name-only or batch answer are not distinguishable from live ones (rolling follow-up #1075); a version-specific answer ignores withdrawn records.

## Not in phase 1

Deprecated/archived package detection (#989), maintainer-change checks, `.pth` file inspection, hash-locked/pinning policy, Docker image pulls, and per-signal block/card/observe configuration.
