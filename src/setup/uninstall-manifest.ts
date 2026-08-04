/**
 * Uninstall parity manifest (#197).
 *
 * Field origin, 3 Aug: the operator asked whether uninstall needed updating —
 * the same instinct that caught `update` skipping install's permission
 * hardening (#171). Audit confirmed the same disease: install had grown a new
 * artifact (the ClawHub skill, #179/#187) and uninstall never learned about
 * it, so an "uninstalled" box kept a stale skill copy that would age silently.
 *
 * This manifest is the fix for the CLASS, not just the instance: every
 * artifact any install surface creates is listed here with exactly one fate —
 * a named removal function, or a written reason it is deliberately kept. A
 * parity test asserts both the exclusive-fate rule and that each removal
 * function is actually called from the uninstall path, so the next new
 * artifact cannot ship without declaring its uninstall story.
 */

export interface UninstallArtifact {
  /** Stable identifier for the artifact. */
  id: string;
  /** What the artifact is, in operator English. */
  description: string;
  /** Which command creates it. */
  createdBy: string;
  /** Exported function that removes it — exclusive with `keepReason`. */
  removedBy?: string;
  /** Why uninstall deliberately leaves it — exclusive with `removedBy`. */
  keepReason?: string;
  /** Where the kept artifact lives, for the closing summary. */
  keptAt?: string;
}

export const UNINSTALL_MANIFEST: UninstallArtifact[] = [
  {
    id: 'claude-settings-hooks',
    description: 'ShieldCortex hooks in ~/.claude/settings.json',
    createdBy: 'shieldcortex install',
    removedBy: 'removeHooks',
  },
  {
    id: 'claude-md-block',
    description: 'Memory-system block in ~/.claude/CLAUDE.md',
    createdBy: 'shieldcortex install',
    removedBy: 'removeClaudeMdBlock',
  },
  {
    id: 'mcp-entry',
    description: 'MCP server entry in ~/.claude.json',
    createdBy: 'shieldcortex install',
    removedBy: 'removeMcpEntry',
  },
  {
    id: 'background-service',
    description: 'Brain-worker background service',
    createdBy: 'shieldcortex install',
    removedBy: 'uninstallService',
  },
  {
    id: 'openclaw-hook',
    description: 'cortex-memory hook in OpenClaw hooks directories',
    createdBy: 'shieldcortex openclaw install',
    removedBy: 'uninstallOpenClawHook',
  },
  {
    id: 'openclaw-plugin',
    description: 'shieldcortex-realtime OpenClaw plugin (files + config refs)',
    createdBy: 'shieldcortex openclaw install',
    removedBy: 'uninstallPlugin',
  },
  {
    id: 'clawhub-skill',
    description: 'ShieldCortex skill copies (ClawHub / workspace locations)',
    createdBy: 'shieldcortex openclaw skill install',
    removedBy: 'uninstallOpenClawSkill',
  },
  {
    id: 'memories-db',
    description: 'Memory database',
    createdBy: 'shieldcortex install (first run)',
    keepReason: 'your memories are your data, not ours to delete — remove ~/.shieldcortex yourself if you want them gone',
    keptAt: '~/.shieldcortex/memories.db',
  },
  {
    id: 'audit-trail',
    description: 'Enforcement audit log',
    createdBy: 'guard activity',
    keepReason: 'the audit trail outlives the tool so past enforcement decisions stay reviewable',
    keptAt: '~/.shieldcortex/audit/',
  },
  {
    id: 'config-backups',
    description: 'Backups taken before ShieldCortex ever mutated your config files',
    createdBy: 'shieldcortex install / update / uninstall',
    keepReason: 'they are your rollback if any removal above went wrong',
    keptAt: '~/.shieldcortex/backups/',
  },
  {
    id: 'state-permissions',
    description: 'Owner-only permissions hardened onto ~/.shieldcortex',
    createdBy: 'shieldcortex install / update',
    keepReason: 'an attribute of the kept state above — tighter-than-default permissions are safe to leave',
    keptAt: '~/.shieldcortex/',
  },
  {
    id: 'npm-package',
    description: 'The global npm package itself',
    createdBy: 'npm i -g shieldcortex',
    keepReason: 'npm owns it: npm uninstall -g shieldcortex',
  },
];

/**
 * The closing lines of every uninstall: what was deliberately kept, and why.
 * Silence about a kept artifact reads as coverage — so it is never silent.
 */
export function formatKeptSummary(): string {
  const kept = UNINSTALL_MANIFEST.filter((a) => a.keepReason);
  const lines = ['Kept on purpose:'];
  for (const a of kept) {
    lines.push(`  - ${a.keptAt ? `${a.keptAt} — ` : ''}${a.description}: ${a.keepReason}`);
  }
  return lines.join('\n');
}
