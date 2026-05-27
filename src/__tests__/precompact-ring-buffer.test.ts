import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * v4.25.0: precompact ring buffer.
 *
 * `~/.shieldcortex/precompact-log/{0..9}.json` — index 0 is newest, rotated
 * on every precompact run. Operators read it via
 * `shieldcortex inspect last-precompact` when diagnosing extraction.
 *
 * The module reads HOME from os.homedir() at module load time, so each
 * test must isolate HOME via a temp dir AND re-import the module fresh
 * (jest.resetModules() + dynamic import) so the LOG_DIR constant points
 * at the tmpdir.
 */
describe('precompact ring buffer', () => {
  let tempHome: string;
  let origHome: string | undefined;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-precompact-log-'));
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
    return path.join(tempHome, '.shieldcortex', 'precompact-log', `${index}.json`);
  }

  it('writes a new entry to slot 0', async () => {
    const { writePrecompactLog } = await import('../../scripts/lib/precompact-log.mjs');
    writePrecompactLog({
      thresholdUsed: 0.42,
      contextFullnessPct: 60,
      totalMemories: 100,
      candidates: [
        { extractorType: 'decision', title: 'Decision: ship 4.25', salience: 0.55, saved: true, memoryId: 1 },
      ],
    });
    const raw = fs.readFileSync(logPathFor(0), 'utf8');
    const parsed = JSON.parse(raw);
    expect(parsed.thresholdUsed).toBe(0.42);
    expect(parsed.candidates).toHaveLength(1);
    expect(parsed.candidates[0].extractorType).toBe('decision');
    expect(parsed.ranAt).toBeDefined();
  });

  it('rotates older entries up by one slot on each write', async () => {
    const { writePrecompactLog } = await import('../../scripts/lib/precompact-log.mjs');
    writePrecompactLog({ thresholdUsed: 0.1, candidates: [{ title: 'first' }] });
    writePrecompactLog({ thresholdUsed: 0.2, candidates: [{ title: 'second' }] });
    writePrecompactLog({ thresholdUsed: 0.3, candidates: [{ title: 'third' }] });
    expect(JSON.parse(fs.readFileSync(logPathFor(0), 'utf8')).thresholdUsed).toBe(0.3);
    expect(JSON.parse(fs.readFileSync(logPathFor(1), 'utf8')).thresholdUsed).toBe(0.2);
    expect(JSON.parse(fs.readFileSync(logPathFor(2), 'utf8')).thresholdUsed).toBe(0.1);
  });

  it('drops entries past index 9 (ring buffer size)', async () => {
    const { writePrecompactLog } = await import('../../scripts/lib/precompact-log.mjs');
    for (let i = 0; i < 12; i++) {
      writePrecompactLog({ thresholdUsed: i / 10, candidates: [] });
    }
    // After 12 writes, slot 9 holds the 10th-most-recent (threshold=0.2),
    // slot 0 holds the newest (threshold=1.1). The first two writes are gone.
    expect(JSON.parse(fs.readFileSync(logPathFor(0), 'utf8')).thresholdUsed).toBeCloseTo(1.1, 2);
    expect(JSON.parse(fs.readFileSync(logPathFor(9), 'utf8')).thresholdUsed).toBeCloseTo(0.2, 2);
    expect(fs.existsSync(logPathFor(10))).toBe(false);
  });

  it('creates ~/.shieldcortex/precompact-log/ on first write', async () => {
    const { writePrecompactLog } = await import('../../scripts/lib/precompact-log.mjs');
    expect(fs.existsSync(path.join(tempHome, '.shieldcortex', 'precompact-log'))).toBe(false);
    writePrecompactLog({ candidates: [] });
    expect(fs.existsSync(path.join(tempHome, '.shieldcortex', 'precompact-log'))).toBe(true);
  });

  it('readPrecompactLog returns null for missing slots (no throw)', async () => {
    const { readPrecompactLog } = await import('../../scripts/lib/precompact-log.mjs');
    expect(readPrecompactLog(0)).toBeNull();
    expect(readPrecompactLog(5)).toBeNull();
  });

  it('listPrecompactLogs returns entries newest-first, skipping missing slots', async () => {
    const { writePrecompactLog, listPrecompactLogs } = await import(
      '../../scripts/lib/precompact-log.mjs'
    );
    writePrecompactLog({ thresholdUsed: 0.1, candidates: [] });
    writePrecompactLog({ thresholdUsed: 0.2, candidates: [] });
    const all = listPrecompactLogs();
    expect(all).toHaveLength(2);
    expect(all[0].index).toBe(0);
    expect(all[0].entry.thresholdUsed).toBe(0.2);
    expect(all[1].index).toBe(1);
    expect(all[1].entry.thresholdUsed).toBe(0.1);
  });

  it('atomic write: leaves no .tmp file behind on success', async () => {
    const { writePrecompactLog } = await import('../../scripts/lib/precompact-log.mjs');
    writePrecompactLog({ candidates: [] });
    const dir = path.join(tempHome, '.shieldcortex', 'precompact-log');
    const entries = fs.readdirSync(dir);
    expect(entries.filter((e) => e.endsWith('.tmp'))).toHaveLength(0);
    expect(entries).toContain('0.json');
  });

  it('preserves all candidate fields including frequencyBoost and error', async () => {
    const { writePrecompactLog, readPrecompactLog } = await import(
      '../../scripts/lib/precompact-log.mjs'
    );
    writePrecompactLog({
      candidates: [
        { extractorType: 'preference', category: 'preference', memoryPurpose: 'feedback', title: 'P', salience: 0.5, frequencyBoost: 0.1, saved: true, error: null },
        { extractorType: 'decision', title: 'D', salience: 0.2, saved: false, error: 'pipeline error' },
      ],
    });
    const entry = readPrecompactLog(0)!;
    expect(entry.candidates[0].memoryPurpose).toBe('feedback');
    expect(entry.candidates[0].frequencyBoost).toBe(0.1);
    expect(entry.candidates[1].saved).toBe(false);
    expect(entry.candidates[1].error).toBe('pipeline error');
  });
});
