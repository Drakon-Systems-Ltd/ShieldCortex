/**
 * Scan Verdict Store Tests (issue #121)
 *
 * Verdicts are keyed by content hash and persisted under
 * SHIELDCORTEX_CONFIG_DIR. Each test points that env var at a throwaway temp
 * dir so the real ~/.shieldcortex store is never touched.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  contentHash,
  loadVerdicts,
  getVerdict,
  recordVerdict,
  removeVerdict,
  getFileVerdict,
} from '../verdict-store.js';

describe('verdict-store', () => {
  let tmp: string;
  let prevEnv: string | undefined;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'sc-verdicts-'));
    prevEnv = process.env.SHIELDCORTEX_CONFIG_DIR;
    process.env.SHIELDCORTEX_CONFIG_DIR = tmp;
  });

  afterEach(() => {
    if (prevEnv === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = prevEnv;
    rmSync(tmp, { recursive: true, force: true });
  });

  const sampleVerdict = (over: Partial<Parameters<typeof recordVerdict>[1]> = {}) => ({
    path: '/some/SKILL.md',
    skillName: 'sample',
    riskLevel: 'high',
    acceptedAt: '2026-07-24T00:00:00.000Z',
    ...over,
  });

  it('hashes content deterministically and distinctly', () => {
    expect(contentHash('abc')).toBe(contentHash('abc'));
    expect(contentHash('abc')).not.toBe(contentHash('abd'));
  });

  it('starts empty', () => {
    expect(loadVerdicts().verdicts).toEqual({});
    expect(getVerdict(contentHash('nope'))).toBeUndefined();
  });

  it('records and retrieves a verdict by content hash', () => {
    const hash = contentHash('payload');
    recordVerdict(hash, sampleVerdict());
    const got = getVerdict(hash);
    expect(got).toBeDefined();
    expect(got?.skillName).toBe('sample');
    expect(got?.riskLevel).toBe('high');
  });

  it('removes a verdict', () => {
    const hash = contentHash('payload');
    recordVerdict(hash, sampleVerdict());
    expect(removeVerdict(hash)).toBe(true);
    expect(getVerdict(hash)).toBeUndefined();
    // Removing again is a no-op.
    expect(removeVerdict(hash)).toBe(false);
  });

  it('resolves a file verdict by current content and invalidates on change', () => {
    const file = join(tmp, 'SKILL.md');
    writeFileSync(file, 'original content');
    recordVerdict(contentHash('original content'), sampleVerdict({ path: file }));

    const first = getFileVerdict(file);
    expect(first).not.toBeNull();
    expect(first?.verdict.skillName).toBe('sample');

    // Content changes → hash changes → previous acceptance no longer applies.
    writeFileSync(file, 'tampered content');
    expect(getFileVerdict(file)).toBeNull();
  });

  it('returns null file verdict for unreadable path', () => {
    expect(getFileVerdict(join(tmp, 'does-not-exist.md'))).toBeNull();
  });

  it('tolerates a corrupt store file', () => {
    writeFileSync(join(tmp, 'scan-verdicts.json'), '{ not valid json');
    expect(loadVerdicts().verdicts).toEqual({});
  });
});
