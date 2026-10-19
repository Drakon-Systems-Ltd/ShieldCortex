/**
 * 5.x compat (#859, design 3.7(d)6 / (e)5 / (e)9 / (e)12) — what the library
 * writes and reads internally keeps PERSONAL, while only the public functions
 * project it to CONFIDENTIAL, and the projection never mutates what it copies.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../../../database/init.js';
import { classifySensitivity, classifySensitivityPrecise } from '../index.js';
import { toPublicSensitivity } from '../tier.js';
import { runDefencePipelinePrecise, toPublicPipelineResult } from '../../pipeline.js';
import { addMemory, getMemoryById } from '../../../memory/store.js';
import { reclassifyMemories, type ReclassifyOptions } from '../../../cli/reclassify.js';

const FAMILY_TITLE = 'Surprise family trip';
const FAMILY_CONTENT = 'Booked a surprise trip to the coast for Sam\'s birthday with the kids in May; do not tell her before the weekend.';
const KEYS = ['level', 'confidence', 'detectedPatterns', 'redactionRequired'];
const user = { type: 'user' as const, identifier: 'sensitivity-compat-5x' };

describe('5.x compat: writer to reader keeps PERSONAL', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
  });
  afterEach(() => closeDatabase());

  it('a written row stores PERSONAL and reads back PERSONAL; the public classifier says CONFIDENTIAL', () => {
    const created = addMemory({ title: FAMILY_TITLE, content: FAMILY_CONTENT }, undefined, user);
    const row = getDatabase().prepare('SELECT sensitivity_level FROM memories WHERE id = ?').get(created.id) as { sensitivity_level: string };
    expect(row.sensitivity_level).toBe('PERSONAL');
    expect(getMemoryById(created.id)?.sensitivityLevel).toBe('PERSONAL');
    expect(classifySensitivity(FAMILY_CONTENT, FAMILY_TITLE).level).toBe('CONFIDENTIAL');
    // Reading through the public classifier did not rewrite the row.
    const after = getDatabase().prepare('SELECT sensitivity_level FROM memories WHERE id = ?').get(created.id) as { sensitivity_level: string };
    expect(after.sensitivity_level).toBe('PERSONAL');
  });
});

describe('5.x compat: the public projection copies and never mutates', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
  });
  afterEach(() => closeDatabase());

  it('toPublicSensitivity returns a new object and leaves the precise one PERSONAL', () => {
    const precise = classifySensitivityPrecise(FAMILY_CONTENT, FAMILY_TITLE);
    const snapshot = structuredClone(precise);
    const project = jest.fn(toPublicSensitivity);
    const pub = project(precise);
    expect(project).toHaveBeenCalledTimes(1);
    expect(project).toHaveBeenCalledWith(precise);
    expect(pub).not.toBe(precise);
    expect(pub.detectedPatterns).not.toBe(precise.detectedPatterns);
    expect(pub.level).toBe('CONFIDENTIAL');
    expect(Object.keys(pub)).toEqual(KEYS);
    expect(precise).toEqual(snapshot);
    expect(precise.level).toBe('PERSONAL');
  });

  it('toPublicPipelineResult copies sensitivity; the internal result and its audit row stay PERSONAL', () => {
    const precise = runDefencePipelinePrecise(FAMILY_CONTENT, FAMILY_TITLE, user);
    const snapshot = structuredClone(precise);
    const pub = toPublicPipelineResult(precise);
    expect(pub.sensitivity).not.toBe(precise.sensitivity);
    expect(pub.sensitivity.level).toBe('CONFIDENTIAL');
    expect(precise).toEqual(snapshot);
    expect(precise.sensitivity.level).toBe('PERSONAL');
    const row = getDatabase().prepare('SELECT sensitivity_level FROM defence_audit WHERE id = ?').get(precise.auditId) as { sensitivity_level: string };
    expect(row.sensitivity_level).toBe('PERSONAL');
  });
});

describe('5.x compat: reclassify uses the precise seam by default', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
  });
  afterEach(() => closeDatabase());

  function seedPublicFamilyRow(): number {
    const info = getDatabase().prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience, sensitivity_level)
       VALUES (lower(hex(randomblob(16))), 'long_term', 'context', ?, ?, 'compat859', 0.9, 'PUBLIC')`,
    ).run(FAMILY_TITLE, FAMILY_CONTENT);
    return Number(info.lastInsertRowid);
  }

  it('dry run with the DEFAULT classifier plans PUBLIC→PERSONAL (not →CONFIDENTIAL) and writes nothing', async () => {
    const id = seedPublicFamilyRow();
    const dry = await reclassifyMemories({ db: getDatabase(), project: 'compat859' });
    expect(dry.dryRun).toBe(true);
    expect(dry.changes).toEqual([{ id, from: 'PUBLIC', to: 'PERSONAL' }]);
    expect(dry.transitions).toEqual({ 'PUBLIC→PERSONAL': 1 });
    const row = getDatabase().prepare('SELECT sensitivity_level FROM memories WHERE id = ?').get(id) as { sensitivity_level: string };
    expect(row.sensitivity_level).toBe('PUBLIC');
  });

  it('an injected classify returning PERSONAL still fits ReclassifyOptions', async () => {
    const id = seedPublicFamilyRow();
    const options: ReclassifyOptions = { db: getDatabase(), project: 'compat859', classify: () => ({ level: 'PERSONAL' }) };
    const dry = await reclassifyMemories(options);
    expect(dry.changes).toEqual([{ id, from: 'PUBLIC', to: 'PERSONAL' }]);
  });
});

describe('5.x compat: CLI scan --json keeps PERSONAL (unmocked pipeline)', () => {
  let root: string;
  let saved: NodeJS.ProcessEnv;
  let logs: string[];

  beforeEach(() => {
    closeDatabase();
    saved = { ...process.env };
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-859-scan-')));
    process.env.HOME = root;
    process.env.CLAUDE_MEMORY_DB = path.join(root, 'memories.db');
    logs = [];
    jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
    try { closeDatabase(); } catch { /* already closed */ }
    process.env = saved;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('emits "sensitivity":"PERSONAL" and keeps the allowed exit code', async () => {
    const { runScanArgv } = await import('../../../cli/scan-command.js');
    expect(await runScanArgv(['--json', FAMILY_CONTENT])).toBe(0);
    expect(logs).toHaveLength(1);
    const body = JSON.parse(logs[0]) as { sensitivity: string };
    expect(body.sensitivity).toBe('PERSONAL');
    expect(logs[0]).not.toContain('"tier"');
  });

  it('text output says Sensitivity: PERSONAL', async () => {
    const { runScanArgv } = await import('../../../cli/scan-command.js');
    await runScanArgv([FAMILY_CONTENT]);
    expect(logs.join('\n')).toContain('Sensitivity: PERSONAL');
  });
});
