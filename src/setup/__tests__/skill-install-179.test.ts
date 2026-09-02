/**
 * #179 — the skill has one install path, and drift cannot hide.
 *
 * Field report, 1 Aug: an operator typed `shieldcortex openclaw skill install`
 * — the obvious command — and got a usage screen. Behind it, four stacked
 * failures had let the installed skill silently age 21 releases: the npm
 * tarball does not ship the skill, the CLI offered no install path, `update`
 * refreshed only an existing copy via a bare `openclaw` spawn (invisible to
 * non-interactive PATH on two of five fleet hosts) without the acknowledge
 * flag ClawHub now requires, and nothing anywhere compared the skill version
 * to the CLI version.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  resolveOpenClawBinary,
  resolveSkillInstallArgs,
  findInstalledSkillDirs,
  readInstalledSkillVersion,
  LEGACY_CLAWHUB_ACK_FLAG,
  INSTALL_POLICY_ACK_FLAG,
} from '../openclaw.js';
import { checkOpenClawSkillVersion } from '../../cli/doctor.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

function fakeHome(skillVersion?: string): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-179-'));
  if (skillVersion) {
    const dir = path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'SKILL.md'),
      `---\nname: shieldcortex\nmetadata:\n  version: ${skillVersion}\n---\nbody\n`,
    );
  }
  return home;
}

describe('#179 — binary resolution does not bet on PATH', () => {
  it('falls back to well-known locations when `which` finds nothing', () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-179bin-'));
    try {
      const binDir = path.join(home, '.npm-global', 'bin');
      fs.mkdirSync(binDir, { recursive: true });
      fs.writeFileSync(path.join(binDir, 'openclaw'), '#!/bin/sh\n');
      // `which` may or may not resolve on this host; the contract is that a
      // known-location copy is found EVEN IF it does not.
      const found = resolveOpenClawBinary(home);
      expect(found).not.toBeNull();
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe('#179 — skill discovery and version parsing', () => {
  it('finds the workspace copy and reads its frontmatter version', () => {
    const home = fakeHome('4.47.6');
    try {
      const dirs = findInstalledSkillDirs(home);
      expect(dirs).toHaveLength(1);
      expect(readInstalledSkillVersion(dirs[0])).toBe('4.47.6');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('returns null rather than throwing on a missing or mangled SKILL.md', () => {
    const home = fakeHome();
    try {
      expect(findInstalledSkillDirs(home)).toHaveLength(0);
      expect(readInstalledSkillVersion('/nonexistent')).toBeNull();
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe('#179 — doctor makes drift visible', () => {
  it('the aiquant state: skill 21 releases behind → WARN naming the fix command', async () => {
    const home = fakeHome('4.47.6');
    try {
      const r = await checkOpenClawSkillVersion(home, '4.47.27');
      expect(r.status).toBe('warn');
      expect(r.message).toContain('4.47.6');
      expect(r.fix).toContain('shieldcortex openclaw skill install');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('matching versions → pass', async () => {
    const home = fakeHome('4.47.27');
    try {
      const r = await checkOpenClawSkillVersion(home, '4.47.27');
      expect(r.status).toBe('pass');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('absent skill → info, never a failure (Claude-Code-only boxes)', async () => {
    const home = fakeHome();
    try {
      const r = await checkOpenClawSkillVersion(home, '4.47.27');
      expect(r.status).toBe('info');
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});

describe('#179 — the command the operator typed now exists', () => {
  it('the openclaw subcommand router carries a skill case and the usage names it', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw.ts'), 'utf-8');
    expect(src).toMatch(/case 'skill':/);
    expect(src).toMatch(/openclaw <install\|uninstall\|status\|repair\|inspect-runtime\|skill install>/);
  });

  it('update wires the resolved binary + feature-detected args, and its skip names the install command', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'update.ts'), 'utf-8');
    expect(src).toMatch(/resolveOpenClawBinary/);
    expect(src).toMatch(/resolveSkillInstallArgs/);
    expect(src).toMatch(/shieldcortex openclaw skill install/);
    // The dead OpenClaw 1 flag must never be hardcoded as an argument again
    // (#456) — prose/comments may still name it, a string literal may not.
    expect(src).not.toMatch(/'--acknowledge-clawhub-risk'/);
  });
});

describe('#456 — skills install args are feature-detected, never a bet on a version', () => {
  // OpenClaw 2026.8.1 removed --acknowledge-clawhub-risk; passing it fails
  // every install. The helper probes the installed binary's own help.
  const BASE = ['skills', 'install', 'shieldcortex', '--force'];
  const args = (help: string | null): string[] =>
    resolveSkillInstallArgs('/fake/openclaw', { home: '/fake/home', probe: () => help });

  it('legacy help (lists the clawhub ack) → legacy args, current behaviour', () => {
    expect(args(`Options:\n  --force\n  ${LEGACY_CLAWHUB_ACK_FLAG}  acknowledge\n`)).toEqual([
      ...BASE,
      LEGACY_CLAWHUB_ACK_FLAG,
    ]);
  });

  it('2026.8.1 help (policy ack, no clawhub ack) → new args with the policy ack', () => {
    const help = `Options:\n  ${INSTALL_POLICY_ACK_FLAG}\n  --force\n  --force-install\n  --global\n`;
    expect(args(help)).toEqual([...BASE, INSTALL_POLICY_ACK_FLAG]);
  });

  it('help listing neither ack flag → bare --force', () => {
    expect(args('Options:\n  --force\n  --global\n')).toEqual(BASE);
  });

  it('a PROSE mention of the removed flag must not resurrect it', () => {
    // 2026.8.1-style help that only names the legacy flag in a sentence.
    const help = `Options:\n  ${INSTALL_POLICY_ACK_FLAG}  Acknowledge warnings\n  --force\nNote: ${LEGACY_CLAWHUB_ACK_FLAG} was removed; use ${INSTALL_POLICY_ACK_FLAG}.\n`;
    expect(args(help)).toEqual([...BASE, INSTALL_POLICY_ACK_FLAG]);
  });

  it('a transitional help offering BOTH acks prefers the new one', () => {
    const help = `Options:\n  ${LEGACY_CLAWHUB_ACK_FLAG}  deprecated\n  ${INSTALL_POLICY_ACK_FLAG}  acknowledge\n`;
    expect(args(help)).toEqual([...BASE, INSTALL_POLICY_ACK_FLAG]);
  });

  it('probe failure → the 2026.8.1 args, never the dead legacy flag', () => {
    const resolved = args(null);
    expect(resolved).toEqual([...BASE, INSTALL_POLICY_ACK_FLAG]);
    expect(resolved).not.toContain(LEGACY_CLAWHUB_ACK_FLAG);
  });

  it('a real spawn probe against a missing binary falls back rather than throwing', () => {
    const resolved = resolveSkillInstallArgs('/nonexistent/openclaw-bin', { home: os.tmpdir() });
    expect(resolved).toEqual([...BASE, INSTALL_POLICY_ACK_FLAG]);
  });
});
