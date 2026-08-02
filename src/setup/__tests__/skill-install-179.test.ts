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
  findInstalledSkillDirs,
  readInstalledSkillVersion,
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
    expect(src).toMatch(/openclaw <install\|uninstall\|status\|repair\|skill install>/);
  });

  it('update wires the resolved binary + acknowledge flag, and its skip names the install command', () => {
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'update.ts'), 'utf-8');
    expect(src).toMatch(/resolveOpenClawBinary/);
    expect(src).toMatch(/--acknowledge-clawhub-risk/);
    expect(src).toMatch(/shieldcortex openclaw skill install/);
  });
});
