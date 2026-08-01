import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { runMemoryCaptureDistCheck, runMemoryCaptureDropsCheck } from '../doctor.js';
import { closeDatabase, initDatabase } from '../../database/init.js';
import Database from 'better-sqlite3';

/**
 * Issue #137 — memory capture fails SILENTLY when dist/ is stale or partial.
 *
 * `scripts/lib/save-memory.mjs:loadDefenceModules()` returns null (and the
 * hook fail-closes, dropping the write with only a discarded stderr line and
 * a synthetic `defence_audit` row) when any of runDefencePipeline,
 * initDatabase, or resolveDisposition is missing from dist/. Fail-closed
 * there is correct and untouched by this fix — these tests exist to pin the
 * OBSERVABILITY doctor must now provide: a hard FAIL that names the missing
 * piece and the fix command, plus a separate check that surfaces PAST drops
 * recorded in defence_audit even after the dist build has been repaired.
 */
describe('doctor: memory-capture dist completeness (#137)', () => {
  let pkgRoot: string;

  beforeEach(() => {
    pkgRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-dist-'));
    // Real dist output is ESM ("type": "module" at the package root) — mirror
    // that so dynamic import() resolves these .js files the same way it
    // would resolve the real build, not as CommonJS.
    fs.writeFileSync(path.join(pkgRoot, 'package.json'), JSON.stringify({ type: 'module' }));
  });

  afterEach(() => {
    fs.rmSync(pkgRoot, { recursive: true, force: true });
  });

  function writeDistFile(rel: string, content: string): void {
    const full = path.join(pkgRoot, 'dist', rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }

  function writeCompleteDist(): void {
    writeDistFile(path.join('defence', 'pipeline.js'), 'export function runDefencePipeline() { return null; }\n');
    writeDistFile(path.join('database', 'init.js'), 'export function initDatabase() { return null; }\n');
    writeDistFile(path.join('defence', 'disposition.js'), 'export function resolveDisposition() { return null; }\n');
  }

  it('FAILs when dist/ does not exist at all (fresh checkout, no build yet)', async () => {
    const result = await runMemoryCaptureDistCheck(pkgRoot);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/pipeline\.js/);
    expect(result.message).toMatch(/init\.js/);
    expect(result.message).toMatch(/disposition\.js/);
    expect(result.message).toMatch(/silently drop/i);
    expect(result.fix).toMatch(/build:ts|repair/);
  });

  it('FAILs when dist/ is PARTIAL — only some of the three required modules exist', async () => {
    // Reproduces the exact #137 repro: dist carried an 11 Jul build missing
    // dist/defence/disposition.js. 100% of saves were silently dropped.
    writeDistFile(path.join('defence', 'pipeline.js'), 'export function runDefencePipeline() { return null; }\n');
    writeDistFile(path.join('database', 'init.js'), 'export function initDatabase() { return null; }\n');
    // defence/disposition.js deliberately missing.

    const result = await runMemoryCaptureDistCheck(pkgRoot);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/disposition\.js/);
    expect(result.message).not.toMatch(/pipeline\.js is missing|init\.js is missing/);
  });

  it('FAILs when a required module exists but does not export the expected symbol (corrupt/partial build)', async () => {
    writeDistFile(path.join('defence', 'pipeline.js'), 'export function runDefencePipeline() { return null; }\n');
    writeDistFile(path.join('database', 'init.js'), 'export function initDatabase() { return null; }\n');
    // Present on disk, but the named export doctor (and the real hook) needs
    // is missing — same effective failure as the file being absent.
    writeDistFile(path.join('defence', 'disposition.js'), 'export function somethingElse() { return null; }\n');

    const result = await runMemoryCaptureDistCheck(pkgRoot);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/resolveDisposition/);
    expect(result.fix).toBeTruthy();
  });

  it('PASSes when all three modules are present and export the right functions', async () => {
    writeCompleteDist();
    const result = await runMemoryCaptureDistCheck(pkgRoot);
    expect(result.status).toBe('pass');
  });
});

describe('doctor: memory-capture recent drops (#137)', () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-drops-'));
    dbPath = path.join(tmpDir, 'memories.db');
  });

  afterEach(() => {
    try { closeDatabase(); } catch { /* ignore */ }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function insertFallbackAudit(reason: string, timestamp: string): void {
    const db = new Database(dbPath);
    try {
      db.prepare(`
        INSERT INTO defence_audit (
          memory_id, project, timestamp, source_type, source_identifier,
          trust_score, sensitivity_level, firewall_result,
          anomaly_score, threat_indicators, blocked_patterns, reason
        ) VALUES (NULL, NULL, ?, 'hook', 'stop-hook', 0, 'INTERNAL', 'BLOCK', 0, '[]', '[]', ?)
      `).run(timestamp, reason);
    } finally {
      db.close();
    }
  }

  it('skips (info) when the database does not exist yet', () => {
    const result = runMemoryCaptureDropsCheck(dbPath);
    expect(result.status).toBe('info');
    expect(result.skipped).toBe('db-uninitialised');
  });

  it('PASSes on a healthy database with no fallback-audit rows', () => {
    initDatabase(dbPath);
    closeDatabase();
    const result = runMemoryCaptureDropsCheck(dbPath);
    expect(result.status).toBe('pass');
  });

  it('FAILs when a defence_pipeline_unavailable row landed in the last 24h — this is the #137 silent-drop signal', () => {
    initDatabase(dbPath);
    closeDatabase();
    insertFallbackAudit('defence_pipeline_unavailable: dist build missing', new Date().toISOString());

    const result = runMemoryCaptureDropsCheck(dbPath);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/1 memory capture/);
    expect(result.message).toMatch(/DROPPED/);
  });

  it('does NOT count drops older than 24h (surfaces the live problem, not ancient history)', () => {
    initDatabase(dbPath);
    closeDatabase();
    const twoDaysAgo = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();
    insertFallbackAudit('defence_pipeline_unavailable: dist build missing', twoDaysAgo);

    const result = runMemoryCaptureDropsCheck(dbPath);
    expect(result.status).toBe('pass');
  });

  it('does NOT count unrelated defence_audit rows (e.g. real QUARANTINE holds)', () => {
    initDatabase(dbPath);
    closeDatabase();
    insertFallbackAudit('injection pattern matched', new Date().toISOString());

    const result = runMemoryCaptureDropsCheck(dbPath);
    expect(result.status).toBe('pass');
  });
});
