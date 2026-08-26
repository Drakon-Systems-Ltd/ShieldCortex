/**
 * Track A harden + T1 doctor checks (#348 / #393 / #394).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('checkMemoryPlaneDrift + checkMemoryHostContract', () => {
  let tmpHome: string;
  let scDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-348-home-'));
    scDir = path.join(tmpHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true, mode: 0o700 });
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeConfig(cfg: Record<string, unknown>): void {
    fs.writeFileSync(path.join(scDir, 'config.json'), `${JSON.stringify(cfg, null, 2)}\n`);
  }

  function openDb(): Database.Database {
    const dbPath = path.join(scDir, 'memories.db');
    const db = new Database(dbPath);
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY,
        title TEXT, content TEXT, status TEXT, sensitivity_level TEXT,
        created_at TEXT
      );
      CREATE TABLE session_events (
        id INTEGER PRIMARY KEY,
        created_at TEXT
      );
    `);
    return db;
  }

  async function runDrift() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkMemoryPlaneDrift();
  }

  async function runHost() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkMemoryHostContract();
  }

  it('fails illegal plane value', async () => {
    writeConfig({ memory: { plane: 'multi_master' } });
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/illegal memory\.plane/i);
    expect(r.fix).toMatch(/--memory-plane/);
  });

  it('warns dual_legacy when activity and zero durable admits', async () => {
    writeConfig({
      openclawAutoMemory: true,
      memory: { plane: 'dual_legacy', inject: { mode: 'start', nativeContract: 'sc_only' } },
    });
    const db = openDb();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    // old admitted row outside window doesn't count as 7d durable admit
    db.prepare(
      `INSERT INTO memories (title, content, status, sensitivity_level, created_at)
       VALUES ('old', 'x', 'active', 'INTERNAL', datetime('now', '-30 days'))`,
    ).run();
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/dual_legacy/i);
  });

  it('fails import_only when native touched and zero durable admits', async () => {
    writeConfig({
      memory: {
        plane: 'import_only',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 't', agentId: 'a' },
      },
    });
    const db = openDb();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# brain\n'.repeat(20));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/drift|import_only/i);
  });

  it('host contract fails when OC memorySearch still enabled under sc_only', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(ocDir, { recursive: true });
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: true } } }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/memorySearch|contract/i);
  });

  it('host contract passes when inject off', async () => {
    writeConfig({ memory: { plane: 'dual_legacy' } });
    const r = await runHost();
    expect(r.status).toBe('info');
  });

  it('host contract fails when memorySearch key absent (OC default-on)', async () => {
    writeConfig({
      openclawAutoMemory: true,
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(ocDir, { recursive: true });
    fs.writeFileSync(path.join(ocDir, 'openclaw.json'), JSON.stringify({ agents: { defaults: {} } }, null, 2));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/default-on|not proven off|Memory Search/i);
  });

  it('host contract needs memorySearch.enabled === false AND the SC pack wired — the switch alone is half a contract', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(ocDir, { recursive: true });
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    // H1: native-off with no SC delivery proof used to be the certified green.
    const half = await runHost();
    expect(half.status).toBe('fail');
    expect(half.message).toMatch(/not proven delivered/);
    expect(half.fix).toMatch(/shieldcortex install/);

    fs.mkdirSync(path.join(ocDir, 'hooks', 'cortex-memory'), { recursive: true });
    const full = await runHost();
    expect(full.status).toBe('pass');
  });

  // ── T1 host runtime matrix (#393) ──
  // The live TARS shape: Hermes primary, no OpenClaw binary, contract sc_only.
  // The pre-#393 check reported PASS here ("no paper-contract signals on disk")
  // and, when it did fail, prescribed an OpenClaw edit the box cannot act on.

  function writeHermes(opts: { memoryEnabled?: boolean; userProfile?: boolean; plugin?: boolean } = {}): void {
    const hermesDir = path.join(tmpHome, '.hermes');
    fs.mkdirSync(hermesDir, { recursive: true });
    fs.writeFileSync(
      path.join(hermesDir, 'config.yaml'),
      [
        'context:',
        '  engine: compressor',
        'memory:',
        `  memory_enabled: ${opts.memoryEnabled ?? true}`,
        `  user_profile_enabled: ${opts.userProfile ?? true}`,
        '  write_approval: false',
        'delegation:',
        '  model: claude-sonnet-5',
        '',
      ].join('\n'),
    );
    if (opts.plugin !== false) {
      fs.mkdirSync(path.join(hermesDir, 'plugins', 'shieldcortex'), { recursive: true });
    }
  }

  const busContract = (plane = 'dual_legacy'): Record<string, unknown> => ({
    memory: {
      plane,
      inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'hermes-primary' },
    },
  });

  it('host contract fails a Hermes-primary paper contract and remediates on Hermes, not OpenClaw', async () => {
    writeConfig(busContract());
    writeHermes({ memoryEnabled: true, userProfile: true });
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/paper contract/);
    expect(r.message).toMatch(/Hermes: native ON/);
    expect(r.fix).toMatch(/memory_enabled=false/);
    expect(r.fix).not.toMatch(/memorySearch/);
  });

  it('host contract fails when a Hermes native MEMORY.md was written this week, even with switches off', async () => {
    writeConfig(busContract());
    writeHermes({ memoryEnabled: false, userProfile: false });
    const memDir = path.join(tmpHome, '.hermes', 'memories');
    fs.mkdirSync(memDir, { recursive: true });
    fs.writeFileSync(path.join(memDir, 'MEMORY.md'), '# hermes brain\n'.repeat(20));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/written within 7d/);
  });

  it('host contract cannot determine when no host runtime is on the box — warn on dual_legacy, fail on import_only', async () => {
    writeConfig(busContract());
    const warned = await runHost();
    expect(warned.status).toBe('warn');
    expect(warned.message).toMatch(/no bound host runtime found/);

    writeConfig(busContract('import_only'));
    const failed = await runHost();
    expect(failed.status).toBe('fail');
    expect(failed.message).toMatch(/cannot determine/);
  });

  it('host contract never passes on an unreadable openclaw.json', async () => {
    writeConfig(busContract());
    // A directory at the config path is present-but-unreadable, deterministically
    // (chmod 000 proves nothing when the test runner is root).
    fs.mkdirSync(path.join(tmpHome, '.openclaw', 'openclaw.json'), { recursive: true });
    // Pack wired, so the verdict isolates the unreadable native evidence.
    fs.mkdirSync(path.join(tmpHome, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    const r = await runHost();
    expect(r.status).not.toBe('pass');
    expect(r.message).toMatch(/cannot determine/);
    expect(r.fix).toMatch(/readable/);
  });

  it('host contract passes when every bound runtime proves native off and carries the SC pack', async () => {
    writeConfig(busContract());
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(path.join(ocDir, 'hooks', 'cortex-memory'), { recursive: true });
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/sc_only enforced/);
  });

  it('host contract fails sc_only on a Hermes-bound box even with the native switches off — sidecar is the honest posture', async () => {
    // The TARS shape after flipping Hermes' own switches: native proven off,
    // OpenClaw proven off and wired — still FAIL, because nothing delivers the
    // SC pack on the Hermes bus (no SC inject surface until Phase-2 ships).
    writeConfig(busContract());
    writeHermes({ memoryEnabled: false, userProfile: false });
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.mkdirSync(path.join(ocDir, 'hooks', 'cortex-memory'), { recursive: true });
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/not proven delivered/);
    expect(r.message).toMatch(/no automatic inject surface/);
    expect(r.fix).toMatch(/mcp_sidecar_no_inject/);
  });

  it('host contract passes an honest sidecar and rejects sidecar-plus-contract', async () => {
    writeHermes({ memoryEnabled: true, userProfile: true });
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject', runtimes: ['hermes'] },
        inject: { mode: 'off', hostId: 'tars', agentId: 'hermes-primary' },
      },
    });
    const sidecar = await runHost();
    expect(sidecar.status).toBe('pass');
    expect(sidecar.message).toMatch(/honest sidecar/);

    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject' },
        inject: { mode: 'start', nativeContract: 'sc_only' },
      },
    });
    const both = await runHost();
    expect(both.status).toBe('fail');
    expect(both.message).toMatch(/mutually exclusive/);
  });

  it('host contract rejects a junk posture instead of ignoring it', async () => {
    writeConfig({
      memory: { plane: 'dual_legacy', hostContract: { posture: 'coexist_dedup' }, inject: { mode: 'off' } },
    });
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/illegal memory\.hostContract\.posture/);
  });

  it('host contract fails when a declared runtime cannot be proven (intent is not enforcement)', async () => {
    writeConfig({
      memory: {
        plane: 'sc_canonical',
        hostContract: { runtimes: ['hermes'] },
        inject: { mode: 'start', nativeContract: 'sc_only' },
      },
    });
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/Hermes/);
  });

  it('import_only fails on native touch even when SC has 7d admits', async () => {
    writeConfig({
      memory: {
        plane: 'import_only',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 't', agentId: 'a' },
      },
    });
    const db = openDb();
    db.prepare(
      `INSERT INTO memories (title, content, status, sensitivity_level, created_at)
       VALUES ('fresh', 'fact', 'active', 'INTERNAL', datetime('now'))`,
    ).run();
    db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# still the brain\n'.repeat(10));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/native memory artifact touched|drift/i);
  });
});

