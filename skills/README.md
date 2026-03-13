# Skills Directory

This repo intentionally keeps two ShieldCortex skill files because they serve different targets.

## `skills/shieldcortex-skill/SKILL.md`

This is the marketplace/published skill artifact.

- Used for ClawHub publishing
- Referenced by the release flow in [`CLAUDE.md`](../CLAUDE.md)
- Written as product-facing skill documentation for external installation and distribution

Publish command:

```bash
clawhub publish ./skills/shieldcortex-skill ...
```

## `skills/shieldcortex/SKILL.md`

This is the local agent-skill variant.

- Includes skill frontmatter (`name`, `description`, `metadata`, `mcp-server`)
- Includes tool/workflow guidance such as `start_session`, `remember`, and `recall`
- Intended for local skill installation/use in agent environments rather than ClawHub publishing

## Maintenance rule

When ShieldCortex positioning, safety wording, install guidance, or scope rules change:

1. Update `skills/shieldcortex-skill/SKILL.md` for the published marketplace skill
2. Mirror the equivalent guidance into `skills/shieldcortex/SKILL.md` for the local agent-skill format

They are related, but they are not interchangeable files.
