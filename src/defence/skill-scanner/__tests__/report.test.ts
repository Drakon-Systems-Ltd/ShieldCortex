/**
 * Workspace Warning Report Tests (issue #121)
 *
 * scan-skills regenerates SHIELDCORTEX_WARNINGS.md so it always matches the
 * live scanner: written when there are flags, removed when there are none.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  generateWarningsMarkdown,
  writeWarningsFile,
  WARNINGS_FILENAME,
  type FlaggedSkill,
} from '../report.js';

const flag = (over: Partial<FlaggedSkill> = {}): FlaggedSkill => ({
  skillName: 'evil',
  path: '/skills/evil/SKILL.md',
  riskLevel: 'high',
  summary: 'evil: 2 finding(s) (2 high) — unsafe',
  ...over,
});

describe('report', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'sc-report-'));
  });
  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  describe('generateWarningsMarkdown', () => {
    it('lists each flagged skill with name, path and risk', () => {
      const md = generateWarningsMarkdown([flag(), flag({ skillName: 'other', path: '/x/HOOK.md', riskLevel: 'critical' })]);
      expect(md).toContain('# ShieldCortex Security Warning');
      expect(md).toContain('**evil** (`/skills/evil/SKILL.md`) — high');
      expect(md).toContain('**other** (`/x/HOOK.md`) — critical');
      expect(md).toContain('scan-skill <path> --accept');
    });
  });

  describe('writeWarningsFile', () => {
    it('writes the file when there are flagged skills', () => {
      const action = writeWarningsFile(tmp, [flag()]);
      expect(action).toBe('written');
      const file = join(tmp, WARNINGS_FILENAME);
      expect(existsSync(file)).toBe(true);
      expect(readFileSync(file, 'utf-8')).toContain('evil');
    });

    it('removes a stale file when nothing is flagged', () => {
      const file = join(tmp, WARNINGS_FILENAME);
      writeFileSync(file, 'stale content');
      const action = writeWarningsFile(tmp, []);
      expect(action).toBe('removed');
      expect(existsSync(file)).toBe(false);
    });

    it('reports absent when nothing is flagged and no file exists', () => {
      expect(writeWarningsFile(tmp, [])).toBe('absent');
      expect(existsSync(join(tmp, WARNINGS_FILENAME))).toBe(false);
    });

    it('overwrites an existing report with the current set', () => {
      const file = join(tmp, WARNINGS_FILENAME);
      writeWarningsFile(tmp, [flag({ skillName: 'first' })]);
      writeWarningsFile(tmp, [flag({ skillName: 'second' })]);
      const content = readFileSync(file, 'utf-8');
      expect(content).toContain('second');
      expect(content).not.toContain('first');
    });
  });
});
