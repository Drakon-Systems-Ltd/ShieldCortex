# Skills Directory

This directory holds the canonical ShieldCortex skill source.

## `skills/shieldcortex/SKILL.md`

The single source of truth for the ShieldCortex skill. Used for:

- **ClawHub publishing.** The release workflow at
  [`.github/workflows/publish.yml`](../.github/workflows/publish.yml) runs
  `clawhub publish ./skills/shieldcortex --slug shieldcortex --version <release>`
  on every tag push.
- **Local agent installation.** Includes skill frontmatter (`name`,
  `description`, `metadata`, `mcp-server`) plus tool/workflow guidance
  (`start_session`, `remember`, `recall`).

The frontmatter `version` field is bumped in lockstep with the main
package on every release; the CI publish step also overrides via
`--version "$RELEASE_VERSION"`, so the registry is always at the latest
release tag even if a local bump is missed.

## Maintenance

When ShieldCortex positioning, safety wording, install guidance, or scope
rules change, update `skills/shieldcortex/SKILL.md` and bump its
frontmatter `version` to match `package.json`. CI handles the publish.

## History

A second directory `skills/shieldcortex-skill/` lived here until v4.14.11
and was described as a separate "marketplace artifact". In practice the CI
workflow only ever published `skills/shieldcortex/`, the second directory
froze at v4.4.1, and nothing else in the repo referenced it. Removed in
v4.14.11 cleanup; see commit history.
