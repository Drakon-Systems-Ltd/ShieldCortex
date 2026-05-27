import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * v4.25.1: recall ring buffer.
 *
 * `~/.shieldcortex/recall-log/{0..9}.json` — index 0 is newest, rotated on
 * every recall hook run. Operators read it via
 * `shieldcortex inspect last-recall` when diagnosing why a memory surfaced
 * (or didn't) for a particular prompt.
 *
 * Structure mirrors precompact-ring-buffer.test.ts exactly — same 8 cases,
 * adapted for the recall payload shape (prompt + candidates with FTS rank
 * and effective salience instead of extracted-segment candidates).
 */
describe('recall ring buffer', () => {
  let tempHome: string;
  let origHome: string | undefined;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-recall-log-'));
    origHome = process.env.HOME;
    process.env.HOME = tempHome;
    jest.resetModules();
  });

  afterEach(() => {
    if (origHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = origHome;
    }
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function logPathFor(index: number) {
    return path.join(tempHome, '.shieldcortex', 'recall-log', `${index}.json`);
  }

  it('writes a new entry to slot 0', async () => {
    const { writeRecallLog } = await import('../../scripts/lib/recall-log.mjs');
    writeRecallLog({
      prompt: 'how is shieldcortex working',
      promptHash: 'sha256:abc',
      sessionId: 'sess-1',
      project: 'shieldcortex',
      minSalience: 0.2,
      candidates: [
        {
          id: 891,
          title: 'Architecture: SC v4.x defence pipeline',
          source: 'fts',
          ftsRank: -8.32,
          effectiveSalience: 0.41,
          injected: true,
          dropReason: null,
        },
      ],
      injectedCount: 1,
      finalContextChars: 120,
    });
    const raw = fs.readFileSync(logPathFor(0), 'utf8');
    const parsed = JSON.parse(raw);
    expect(parsed.prompt).toBe('how is shieldcortex working');
    expect(parsed.candidates).toHaveLength(1);
    expect(parsed.candidates[0].source).toBe('fts');
    expect(parsed.ranAt).toBeDefined();
  });

  it('rotates older entries up by one slot on each write', async () => {
    const { writeRecallLog } = await import('../../scripts/lib/recall-log.mjs');
    writeRecallLog({ prompt: 'first', candidates: [] });
    writeRecallLog({ prompt: 'second', candidates: [] });
    writeRecallLog({ prompt: 'third', candidates: [] });
    expect(JSON.parse(fs.readFileSync(logPathFor(0), 'utf8')).prompt).toBe('third');
    expect(JSON.parse(fs.readFileSync(logPathFor(1), 'utf8')).prompt).toBe('second');
    expect(JSON.parse(fs.readFileSync(logPathFor(2), 'utf8')).prompt).toBe('first');
  });

  it('drops entries past index 9 (ring buffer size)', async () => {
    const { writeRecallLog } = await import('../../scripts/lib/recall-log.mjs');
    for (let i = 0; i < 12; i++) {
      writeRecallLog({ prompt: `p-${i}`, candidates: [] });
    }
    // After 12 writes, slot 0 holds the newest (p-11) and slot 9 holds the
    // 10th-most-recent (p-2). The first two writes are gone.
    expect(JSON.parse(fs.readFileSync(logPathFor(0), 'utf8')).prompt).toBe('p-11');
    expect(JSON.parse(fs.readFileSync(logPathFor(9), 'utf8')).prompt).toBe('p-2');
    expect(fs.existsSync(logPathFor(10))).toBe(false);
  });

  it('creates ~/.shieldcortex/recall-log/ on first write', async () => {
    const { writeRecallLog } = await import('../../scripts/lib/recall-log.mjs');
    expect(fs.existsSync(path.join(tempHome, '.shieldcortex', 'recall-log'))).toBe(false);
    writeRecallLog({ candidates: [] });
    expect(fs.existsSync(path.join(tempHome, '.shieldcortex', 'recall-log'))).toBe(true);
  });

  it('readRecallLog returns null for missing slots (no throw)', async () => {
    const { readRecallLog } = await import('../../scripts/lib/recall-log.mjs');
    expect(readRecallLog(0)).toBeNull();
    expect(readRecallLog(5)).toBeNull();
  });

  it('listRecallLogs returns entries newest-first, skipping missing slots', async () => {
    const { writeRecallLog, listRecallLogs } = await import(
      '../../scripts/lib/recall-log.mjs'
    );
    writeRecallLog({ prompt: 'first', candidates: [] });
    writeRecallLog({ prompt: 'second', candidates: [] });
    const all = listRecallLogs();
    expect(all).toHaveLength(2);
    expect(all[0].index).toBe(0);
    expect(all[0].entry.prompt).toBe('second');
    expect(all[1].index).toBe(1);
    expect(all[1].entry.prompt).toBe('first');
  });

  it('atomic write: leaves no .tmp file behind on success', async () => {
    const { writeRecallLog } = await import('../../scripts/lib/recall-log.mjs');
    writeRecallLog({ candidates: [] });
    const dir = path.join(tempHome, '.shieldcortex', 'recall-log');
    const entries = fs.readdirSync(dir);
    expect(entries.filter((e) => e.endsWith('.tmp'))).toHaveLength(0);
    expect(entries).toContain('0.json');
  });

  it('preserves all candidate fields (dropReason, source, effectiveSalience, ftsRank)', async () => {
    const { writeRecallLog, readRecallLog } = await import(
      '../../scripts/lib/recall-log.mjs'
    );
    writeRecallLog({
      prompt: 'how does shieldcortex defence work',
      candidates: [
        {
          id: 891,
          title: 'Architecture: defence pipeline',
          category: 'architecture',
          memoryPurpose: 'project',
          salience: 0.55,
          ftsRank: -8.32,
          source: 'fts',
          effectiveSalience: 0.41,
          injected: true,
          dropReason: null,
        },
        {
          id: 412,
          title: 'Preference: use black rgb(0,0,0) as shape fill',
          category: 'preference',
          memoryPurpose: 'feedback',
          salience: 0.3,
          ftsRank: -2.1,
          source: 'fts',
          effectiveSalience: 0.18,
          injected: false,
          dropReason: 'below_min_salience',
        },
      ],
      injectedCount: 1,
      finalContextChars: 120,
    });
    const entry = readRecallLog(0)!;
    expect(entry.candidates).toHaveLength(2);
    expect(entry.candidates[0].source).toBe('fts');
    expect(entry.candidates[0].effectiveSalience).toBe(0.41);
    expect(entry.candidates[0].injected).toBe(true);
    expect(entry.candidates[1].dropReason).toBe('below_min_salience');
    expect(entry.candidates[1].ftsRank).toBe(-2.1);
    expect(entry.injectedCount).toBe(1);
    expect(entry.finalContextChars).toBe(120);
  });
});
