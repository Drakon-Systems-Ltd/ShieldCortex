/**
 * #647 round-2 review B1-R2 — the re-sign's audit sink must be a database that
 * outlives the command.
 *
 * `CLAUDE_MEMORY_DB=:memory:` is a supported override. Before this fix
 * `openRecoveryAuditSink` opened it, the insert returned a real row id, the
 * re-sign reported "recorded", and `close()` destroyed the only copy of the row.
 * A row id is not a receipt. These cases pin, against the real database layer
 * (nothing mocked but the OpenClaw plugin guard sync):
 *
 *   - an in-memory database is refused, whether the sink opens it (and then
 *     closes it again) or the caller already had it open (and keeps it, usable);
 *   - `resignTamperedConfig` on a caller-owned in-memory database refuses before
 *     the backup and the signature: bytes unchanged, no backup, still tampered;
 *   - a file-backed database still records a row that is there after close,
 *     and `location` is the handle's own file name;
 *   - ordinary best-effort Iron Dome audit rows still go to an in-memory
 *     database exactly as before — no Guard decision depends on durable storage.
 *
 * The fresh-process, built-CLI form of the refusal is in
 * config-resign-audit-dist-647.
 *
 * Isolation: per-test SHIELDCORTEX_CONFIG_DIR, SHIELDCORTEX_PROTECTED_ROOT,
 * OPENCLAW_HOME and CLAUDE_MEMORY_DB under os.tmpdir().
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHash, createHmac, randomBytes } from 'crypto';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

jest.unstable_mockModule('../setup/openclaw-plugin-guard-sync.js', () => ({
  syncOpenClawPluginActionGuard: jest.fn(() => ({ status: 'skipped' as const, reason: 'no-entry' as const })),
}));

const { closeDatabase, getDatabase, initDatabase, isDatabaseInitialized } = await import('../database/init.js');
const { openRecoveryAuditSink } = await import('../cloud/recovery-audit.js');
const { logIronDomeAudit } = await import('../defence/iron-dome/audit.js');
const { inspectConfigIntegrity, resignTamperedConfig } = await import('../cloud/config.js');

const ENV_KEYS = ['SHIELDCORTEX_CONFIG_DIR', 'SHIELDCORTEX_PROTECTED_ROOT', 'OPENCLAW_HOME', 'CLAUDE_MEMORY_DB'] as const;
const EVENT = { outcome: 'config_resigned' as const, path: '/test/config.json', reason: 'tampered', detail: 'persistence probe' };

let root: string;
let configDir: string;
let saved: Record<string, string | undefined>;

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-647-sink-'));
  configDir = path.join(root, 'config');
  for (const dir of [configDir, path.join(root, 'protected'), path.join(root, 'openclaw')]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  process.env.SHIELDCORTEX_PROTECTED_ROOT = path.join(root, 'protected');
  process.env.OPENCLAW_HOME = path.join(root, 'openclaw');
  process.env.CLAUDE_MEMORY_DB = path.join(root, 'db', 'memories.db');
});

afterEach(() => {
  if (isDatabaseInitialized()) closeDatabase();
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  fs.rmSync(root, { recursive: true, force: true });
});

const configFile = () => path.join(configDir, 'config.json');
const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex');
const backups = () => fs.readdirSync(configDir).filter((n) => n.includes('.bak-resign-'));
const auditRows = () =>
  (getDatabase().prepare("SELECT COUNT(*) AS n FROM defence_audit WHERE reason LIKE '[iron-dome:%'").get() as { n: number }).n;

/** Signed as config.ts signs it, then hand-edited on keys no lock or Guard floor holds. */
function tamperedConfig(): Buffer {
  const key = randomBytes(32).toString('hex');
  fs.writeFileSync(path.join(configDir, '.integrity-key'), key, { mode: 0o600 });
  const body = { actionGuard: { enabled: true, enforce: true }, defenceMode: 'strict', proactiveRecall: false };
  const sig = createHmac('sha256', key).update(JSON.stringify(body, null, 2), 'utf-8').digest('hex');
  fs.writeFileSync(configFile(), `${JSON.stringify({ ...body, proactiveRecall: true, _sig: sig }, null, 2)}\n`, { mode: 0o600 });
  return fs.readFileSync(configFile());
}

describe('#647 recovery audit sink: an in-memory database is not a receipt', () => {
  it('refuses a :memory: database it opened itself, and closes it again', async () => {
    process.env.CLAUDE_MEMORY_DB = ':memory:';
    expect(isDatabaseInitialized()).toBe(false);

    await expect(openRecoveryAuditSink()).rejects.toThrow(/":memory:" is in-memory or temporary/);
    expect(isDatabaseInitialized()).toBe(false);
  });

  it('refuses a caller-owned :memory: database and leaves it open and usable', async () => {
    const callerDb = initDatabase(':memory:');
    logIronDomeAudit({ action: 'kill_switch', allowed: true, reason: 'before the sink' });
    const rowsBefore = auditRows();
    expect(rowsBefore).toBeGreaterThan(0);

    await expect(openRecoveryAuditSink()).rejects.toThrow(/is in-memory or temporary/);

    // Same handle, still open, its rows intact, and the ordinary best-effort
    // audit still writes to it exactly as before.
    expect(isDatabaseInitialized()).toBe(true);
    expect(getDatabase()).toBe(callerDb);
    expect(auditRows()).toBe(rowsBefore);
    logIronDomeAudit({ action: 'kill_switch', allowed: true, reason: 'after the sink' });
    expect(auditRows()).toBe(rowsBefore + 1);
  });

  it('resignTamperedConfig on a caller-owned :memory: database refuses before backup and signing', async () => {
    const before = tamperedConfig();
    expect(inspectConfigIntegrity().verdict).toBe('tampered');
    initDatabase(':memory:');

    await expect(resignTamperedConfig(sha256(before))).rejects.toThrow(
      /audit log that must record a re-sign could not be opened[\s\S]*in-memory or temporary[\s\S]*Nothing was written/,
    );

    expect(fs.readFileSync(configFile()).equals(before)).toBe(true);
    expect(backups()).toEqual([]);
    expect(inspectConfigIntegrity().verdict).toBe('tampered');
    expect(
      (getDatabase().prepare("SELECT COUNT(*) AS n FROM defence_audit WHERE reason LIKE '%config_resigned%'").get() as { n: number }).n,
    ).toBe(0);
    // The caller's database was not closed by the refusal.
    expect(isDatabaseInitialized()).toBe(true);
    expect(getDatabase().prepare('SELECT 1 AS one').get()).toEqual({ one: 1 });
  });
});

describe('#647 recovery audit sink: a file-backed database still records', () => {
  it('opened here: records a row that survives close, at the handle\'s own file', async () => {
    const file = process.env.CLAUDE_MEMORY_DB!;
    const sink = await openRecoveryAuditSink();
    expect(sink.location).toBe(getDatabase().name);
    expect(sink.location).toBe(file);
    const id = sink.record(EVENT);
    expect(id).toBeGreaterThan(0);
    sink.close();
    expect(isDatabaseInitialized()).toBe(false);

    const db = new Database(file, { readonly: true, fileMustExist: true });
    try {
      const row = db.prepare('SELECT reason FROM defence_audit WHERE id = ?').get(id) as { reason: string } | undefined;
      expect(row?.reason).toContain('config_resigned');
      expect(row?.reason).toContain('persistence probe');
    } finally {
      db.close();
    }
  });

  it('caller-owned: records, and close() leaves the caller\'s database open', async () => {
    const file = path.join(root, 'caller', 'memories.db');
    const callerDb = initDatabase(file);
    const sink = await openRecoveryAuditSink();
    expect(sink.location).toBe(file);
    const id = sink.record(EVENT);
    expect(id).toBeGreaterThan(0);
    sink.close();

    expect(isDatabaseInitialized()).toBe(true);
    expect(getDatabase()).toBe(callerDb);
    expect(getDatabase().prepare('SELECT id FROM defence_audit WHERE id = ?').get(id)).toEqual({ id });
  });
});
