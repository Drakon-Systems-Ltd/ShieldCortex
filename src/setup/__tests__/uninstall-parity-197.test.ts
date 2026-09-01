/**
 * #197 — uninstall parity: every artifact install creates has a declared fate.
 *
 * Field origin, 3 Aug: the operator asked whether uninstall needed updating —
 * the same instinct that caught `update` skipping install's hardening (#171).
 * It did: install had grown the ClawHub skill (#179/#187) and uninstall never
 * learned about it, so an "uninstalled" box kept a stale skill copy. Same
 * disease as everything that week — a second call site the fix never reached.
 *
 * The manifest turns that from an audit finding into a failing test: an
 * artifact must name its removal function (which must actually be CALLED from
 * the uninstall path) or carry a written keep-reason that the operator sees.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { UNINSTALL_MANIFEST, formatKeptSummary } from '../uninstall-manifest.js';
import { uninstallOpenClawSkill, skillDirLooksShieldcortex } from '../openclaw.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const uninstallPathSource =
  fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'uninstall.ts'), 'utf-8') +
  fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw.ts'), 'utf-8');

function skillHome(frontmatterName?: string): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-197-'));
  const dir = path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex');
  fs.mkdirSync(dir, { recursive: true });
  if (frontmatterName !== undefined) {
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      `---\nname: ${frontmatterName}\nmetadata:\n  version: 4.47.29\n---\nbody\n`,
    );
  }
  return home;
}

describe('#197 — the manifest rule: exactly one fate per artifact', () => {
  it('every artifact is removed XOR kept, never both, never neither', () => {
    for (const a of UNINSTALL_MANIFEST) {
      const fates = [a.removedBy, a.keepReason].filter(Boolean).length;
      expect(`${a.id}: ${fates} fate(s)`).toBe(`${a.id}: 1 fate(s)`);
    }
  });

  it('every removal function is actually called from the uninstall path', () => {
    // A manifest entry naming a function nobody calls is the #171 disease
    // with better paperwork. Definitions ("function foo(") do not count.
    for (const a of UNINSTALL_MANIFEST) {
      if (!a.removedBy) continue;
      const callSite = new RegExp(`(?<!function )\\b${a.removedBy}\\(`);
      expect(`${a.id} call-site: ${callSite.test(uninstallPathSource)}`).toBe(`${a.id} call-site: true`);
    }
  });

  it('the skill artifact is in the manifest — the gap that opened #197 stays closed', () => {
    const skill = UNINSTALL_MANIFEST.find((a) => a.id === 'clawhub-skill');
    expect(skill?.removedBy).toBe('uninstallOpenClawSkill');
  });

  it('the full uninstall path itself removes the skill — the standalone verb alone is not parity', () => {
    // A `skill uninstall` verb someone can type is not the same as
    // `shieldcortex uninstall` leaving no skill behind. Pin the call inside
    // uninstallOpenClawHook's own body.
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw.ts'), 'utf-8');
    const start = src.indexOf('export async function uninstallOpenClawHook');
    const end = src.indexOf('export', start + 1);
    expect(start).toBeGreaterThan(-1);
    expect(src.slice(start, end)).toContain('uninstallOpenClawSkill();');
  });

  it('the Codex MCP artifact is in the manifest — the gap that opened #452 stays closed', () => {
    const codex = UNINSTALL_MANIFEST.find((a) => a.id === 'codex-mcp');
    expect(codex?.removedBy).toBe('uninstallCodex');
  });

  it('the full uninstall path itself removes the Codex MCP block — the standalone verb alone is not parity', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'uninstall.ts'), 'utf-8');
    const start = src.indexOf('export async function uninstallAll');
    expect(start).toBeGreaterThan(-1);
    expect(src.slice(start)).toContain('await uninstallCodex();');
  });
});

describe('#197 — skill removal is fail-closed on ownership', () => {
  it('removes a ShieldCortex-owned skill copy', () => {
    const home = skillHome('shieldcortex');
    try {
      const r = uninstallOpenClawSkill(home);
      expect(r.removed).toHaveLength(1);
      expect(r.skipped).toHaveLength(0);
      expect(fs.existsSync(path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex'))).toBe(false);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it("leaves a foreign directory that merely shares the name — a user's own 'shieldcortex' folder must survive our uninstall", () => {
    const home = skillHome('someones-notes');
    try {
      const r = uninstallOpenClawSkill(home);
      expect(r.removed).toHaveLength(0);
      expect(r.skipped).toHaveLength(1);
      expect(fs.existsSync(path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex'))).toBe(true);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('an unreadable SKILL.md fails closed: kept, not deleted', () => {
    const home = skillHome(undefined); // dir exists, no SKILL.md at all
    try {
      expect(skillDirLooksShieldcortex(path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex'))).toBe(false);
      const r = uninstallOpenClawSkill(home);
      expect(r.removed).toHaveLength(0);
      expect(r.skipped).toHaveLength(1);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe('#197 — the operator sees what was kept, and why', () => {
  it('the kept summary names every intentional keep with its reason', () => {
    const summary = formatKeptSummary();
    for (const a of UNINSTALL_MANIFEST) {
      if (!a.keepReason) continue;
      expect(summary).toContain(a.keepReason);
      if (a.keptAt) expect(summary).toContain(a.keptAt);
    }
  });

  it('uninstall actually prints it — the summary is wired, not decorative', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'uninstall.ts'), 'utf-8');
    expect(src).toMatch(/formatKeptSummary\(\)/);
  });

  it('the memory database keep still tells the operator how to delete it themselves', () => {
    expect(formatKeptSummary()).toContain('~/.shieldcortex/memories.db');
  });
});
