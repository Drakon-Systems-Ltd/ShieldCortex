/**
 * #394 T2 residual — dual-plane drift doctor teeth.
 *
 * Three laws under test, none of which the #397 partial landing enforced:
 *
 *  1. REAL injectable counting. The drift check must count injectables with the
 *     SAME predicate the session-start hook injects with (`isInjectEligible` in
 *     scripts/lib/inject-pack.mjs), not a coarse SQL approximation — and that
 *     count must be teeth, not decoration. A store full of rows the real gate
 *     rejects (unverified legacy, directive form, unscoped) delivers NOTHING on
 *     the SC bus, which is exactly the green-wash the residual plan names.
 *  2. FP law. Only native artifacts that actually feed the bound agent's SoT
 *     count as drift. An operator scratchpad — `~/MEMORY.md`, `~/notes/…`, a
 *     stray `.md` in a workspace, a project `CLAUDE.md` preamble — must not.
 *  3. Scope law. `requireScope` is deny-by-default CONFIG. Unscoped/scratch
 *     data can never trick the doctor into PASS, and can never turn the gate off.
 *
 * Plus: telemetry gaps say "cannot determine" instead of PASSing, and illegal
 * plane × contract combos fail.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  INJECT_CANDIDATE_FIELDS,
  buildStartPack,
  isInjectEligible,
  selectInjectCandidates,
} from '../../../scripts/lib/inject-pack.mjs';

describe('checkMemoryPlaneDrift — #394 T2 teeth', () => {
  let tmpHome: string;
  let scDir: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-394-home-'));
    scDir = path.join(tmpHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true, mode: 0o700 });
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    delete process.env.OPENCLAW_STATE_DIR;
    delete process.env.OPENCLAW_CONFIG_PATH;
    delete process.env.OPENCLAW_PROFILE;
    delete process.env.OPENCLAW_HOME;
    delete process.env.CLAWDBOT_STATE_DIR;
    delete process.env.CLAWDBOT_CONFIG_PATH;
    // Signed config writers resolve their destination before runDrift installs
    // the os.homedir spy. Pin them to the same sandbox as doctor's live read so
    // these tests prove signature semantics without touching the real host.
    process.env.SHIELDCORTEX_CONFIG_DIR = scDir;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeConfig(cfg: Record<string, unknown>): void {
    fs.writeFileSync(path.join(scDir, 'config.json'), `${JSON.stringify(cfg, null, 2)}\n`);
  }

  /** Plane config with the inject bus on and a legal contract. */
  function planeConfig(plane: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      memory: {
        plane,
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'hermes-primary' },
        ...extra,
      },
    };
  }

  /**
   * Superset of the columns the REAL inject predicate reads. A doctor that only
   * knows status/sensitivity/trust cannot answer "would this row be injected".
   */
  function openDb(): Database.Database {
    const db = new Database(path.join(scDir, 'memories.db'));
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY,
        title TEXT, content TEXT, status TEXT, sensitivity_level TEXT,
        content_form TEXT, trust_score REAL, defence_verdict TEXT,
        source_attested INTEGER, pinned INTEGER, quarantined INTEGER, in_quarantine INTEGER,
        host_id TEXT, agent_id TEXT, project TEXT, transferable INTEGER,
        salience REAL, created_at TEXT
      );
      CREATE TABLE session_events (id INTEGER PRIMARY KEY, created_at TEXT);
    `);
    return db;
  }

  interface RowSpec {
    title?: string;
    content?: string;
    status?: string;
    sensitivity_level?: string;
    content_form?: string | null;
    trust_score?: number | null;
    defence_verdict?: string | null;
    source_attested?: number;
    pinned?: number;
    quarantined?: number;
    in_quarantine?: number;
    host_id?: string | null;
    agent_id?: string | null;
    project?: string | null;
    transferable?: number;
    salience?: number;
    ageDays?: number;
  }

  /** A row the REAL predicate accepts, unless a field is overridden. */
  function insertRow(db: Database.Database, spec: RowSpec = {}): void {
    db.prepare(
      `INSERT INTO memories
        (title, content, status, sensitivity_level, content_form, trust_score,
         defence_verdict, source_attested, pinned, quarantined, in_quarantine,
         host_id, agent_id, project, transferable, salience, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', ?))`,
    ).run(
      spec.title ?? 'deploy note',
      spec.content ?? 'The staging deploy runs from the release branch.',
      spec.status ?? 'active',
      spec.sensitivity_level ?? 'INTERNAL',
      spec.content_form === undefined ? 'fact' : spec.content_form,
      spec.trust_score === undefined ? 0.9 : spec.trust_score,
      spec.defence_verdict === undefined ? 'allow' : spec.defence_verdict,
      spec.source_attested ?? 0,
      spec.pinned ?? 0,
      spec.quarantined ?? 0,
      spec.in_quarantine ?? 0,
      spec.host_id === undefined ? 'tars' : spec.host_id,
      spec.agent_id === undefined ? 'hermes-primary' : spec.agent_id,
      spec.project === undefined ? null : spec.project,
      spec.transferable ?? 0,
      spec.salience ?? 0.5,
      `-${spec.ageDays ?? 0} days`,
    );
  }

  function addActivity(db: Database.Database, n = 3): void {
    for (let i = 0; i < n; i++) {
      db.prepare(`INSERT INTO session_events (created_at) VALUES (datetime('now'))`).run();
    }
  }

  async function runDrift() {
    jest.spyOn(os, 'homedir').mockReturnValue(tmpHome);
    const mod = await import('../doctor.js');
    return mod.checkMemoryPlaneDrift();
  }

  // ── 1. Real injectable counting ────────────────────────────────

  it('counts injectables with the real inject predicate, not an approximation', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    insertRow(db, { title: 'second' });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('pass');
    // An honest count, not a "≈" hedge over a weaker SQL predicate.
    expect(r.message).toMatch(/injectable=2\b/);
    expect(r.message).not.toMatch(/injectable≈/);
  });

  it('fails import_only when the store holds durable rows the real gate rejects as unverified legacy', async () => {
    // Coarse SQL (status + sensitivity + trust_score >= 0.5) counts these as
    // injectable. The real predicate never injects an unverified row (Opus B1),
    // so the SC bus delivers nothing while the plane claims canonicity.
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { defence_verdict: 'unverified' });
    insertRow(db, { defence_verdict: 'unverified', title: 'second' });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/injectable=0\b/);
    expect(r.message).toMatch(/inject eligibility|delivers nothing/i);
  });

  it('fails import_only when every durable row is directive-form — the form key is part of real eligibility', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { content_form: 'directive', pinned: 1 });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/injectable=0\b/);
  });

  it('warns rather than fails on the same zero-injectable store under dual_legacy', async () => {
    writeConfig(planeConfig('dual_legacy'));
    const db = openDb();
    insertRow(db, { defence_verdict: 'unverified' });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/injectable=0\b/);
  });

  it('honours the attestation-is-not-trust escape exactly as the injector does', async () => {
    // source_attested + pinned + no numeric trust + allow verdict is the ONE
    // sanctioned pin escape; a coarse COALESCE(trust_score, 0) >= 0.5 filter
    // would undercount it to zero and manufacture drift.
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { trust_score: null, source_attested: 1, pinned: 1, defence_verdict: 'allow' });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/injectable=1\b/);
  });

  it('does not let attestation alone carry a row under the trust floor', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { trust_score: 0.3, source_attested: 1, pinned: 1 });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/injectable=0\b/);
  });

  it('counts durable admits inside the configured host/agent scope, not another hosts rows in a shared DB', async () => {
    // A shared/legacy DB where the last week of admits all belong to a
    // DIFFERENT host must not read as "this box captured into SC".
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { host_id: 'other-box', agent_id: 'other-agent' });
    insertRow(db, { host_id: 'other-box', agent_id: 'other-agent', title: 'second' });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/sc_durable_admits_7d=0\b/);
    expect(r.message).toMatch(/injectable=0\b/);
  });

  it('uses one candidate row shape/window for doctor and both start consumers', () => {
    for (const sourcePath of [
      'scripts/session-start-hook.mjs',
      'hooks/openclaw/cortex-memory/handler.ts',
    ]) {
      const source = fs.readFileSync(path.join(process.cwd(), sourcePath), 'utf-8');
      expect(source).toMatch(/selectInjectCandidates\(db/);
      expect(source).not.toMatch(/LIMIT 64/);
    }
    const db = openDb();
    insertRow(db, { title: 'fact', source_attested: 1, pinned: 1 });
    insertRow(db, { title: 'directive', content_form: 'directive', pinned: 1 });
    const rows = selectInjectCandidates(db) as Array<Record<string, unknown>>;
    db.close();
    expect(Object.keys(rows[0]).sort()).toEqual([...INJECT_CANDIDATE_FIELDS].sort());
    expect(rows.map((r) => r.id)).toEqual([1, 2]);
    const runtimeScope = { hostId: 'tars', agentId: 'hermes-primary', requireScope: true };
    const eligibleIds = rows.filter((r) => isInjectEligible(r, runtimeScope)).map((r) => r.id);
    const sessionPack = buildStartPack(rows, {
      mode: 'start', nativeContract: 'sc_only', scope: runtimeScope,
    });
    const openClawPack = buildStartPack(rows, {
      mode: 'start', nativeContract: 'sc_only', scope: runtimeScope,
    });
    expect(eligibleIds).toEqual([1]);
    expect(sessionPack.items.map((r: { id: unknown }) => r.id)).toEqual(eligibleIds);
    expect(openClawPack.items.map((r: { id: unknown }) => r.id)).toEqual(eligibleIds);
  });

  it('grades the real top-64 window — an eligible row at rank 65 is not on the bus', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    for (let i = 0; i < 64; i++) {
      insertRow(db, { title: `directive-${i}`, content_form: 'directive', salience: 1 });
    }
    insertRow(db, { title: 'eligible-rank-65', content_form: 'fact', salience: 0 });
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/injectable=0\b/);
    expect(r.message).toMatch(/delivers nothing/);
  });

  it('treats SQLite quarantine booleans as true for integer 1', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { quarantined: 1 });
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/injectable=0\b/);
  });

  it('reports eligibility unknown when a session project is required but doctor has none', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { project: 'project-a', transferable: 0 });
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/real inject eligibility cannot be evaluated/);
    expect(r.message).toMatch(/injectable=unknown/);
  });

  // ── 2. Scope law: deny-by-default is config, never data-derived ──

  it('reports unscoped rows as excluded and refuses to PASS an unscoped shared DB', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { host_id: null, agent_id: null });
    insertRow(db, { host_id: null, agent_id: null, title: 'second' });
    insertRow(db, { host_id: 'tars', agent_id: null, title: 'half-scoped' });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/injectable=0\b/);
    expect(r.message).toMatch(/unscoped_excluded=3\b/);
    expect(r.message).toMatch(/requireScope=true/);
  });

  it('keeps requireScope deny-by-default when the whole store is unscoped — a gate that self-disables is not a gate', async () => {
    // Every row unscoped: the data-derived off-switch the residual plan bans
    // would flip requireScope off here and mint a green PASS.
    writeConfig(planeConfig('dual_legacy'));
    const db = openDb();
    for (let i = 0; i < 5; i++) insertRow(db, { host_id: null, agent_id: null, title: `row-${i}` });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).not.toBe('pass');
    expect(r.message).toMatch(/requireScope=true/);
    expect(r.message).toMatch(/injectable=0\b/);
  });

  it('refuses to PASS a quiet all-unscoped store without relying on activity rows', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db, { host_id: null, agent_id: null });
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/scope gate excluded 1 unscoped row/);
    expect(r.message).toMatch(/activity_7d=0/);
  });

  it('turns the scope gate off only on explicit config, and then counts what the injector would really inject', async () => {
    writeConfig({
      memory: {
        plane: 'import_only',
        inject: {
          mode: 'start', nativeContract: 'sc_only',
          hostId: 'tars', agentId: 'hermes-primary',
          requireScope: false,
        },
      },
    });
    const db = openDb();
    insertRow(db, { host_id: null, agent_id: null });
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/requireScope=false/);
    expect(r.message).toMatch(/injectable=1\b/);
  });

  // ── 3. FP fixtures: operator scratchpad is not agent SoT ─────────

  it('does not treat an operator scratchpad as agent SoT drift', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    // Home-dir notes, a personal memory folder, and a stray file inside an
    // OpenClaw workspace. None of these is a file any host loads as its brain.
    fs.writeFileSync(path.join(tmpHome, 'MEMORY.md'), '# my own notes\n'.repeat(40));
    fs.mkdirSync(path.join(tmpHome, 'notes'), { recursive: true });
    fs.writeFileSync(path.join(tmpHome, 'notes', 'MEMORY.md'), '# scratch\n'.repeat(40));
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'scratchpad.md'), '# todo\n'.repeat(40));
    const r = await runDrift();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/native_sot_touched_7d=false/);
  });

  it('does not treat a project CLAUDE.md preamble as memory-plane drift', async () => {
    // A project instructions file is host-contract evidence (#393), not native
    // memory growth. Developers edit it constantly; drift must not fire.
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    fs.mkdirSync(path.join(tmpHome, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(tmpHome, '.claude', 'CLAUDE.md'), '# project rules\n'.repeat(40));
    const r = await runDrift();
    expect(r.status).toBe('pass');
  });

  // ── 4. Native SoT true positives, per plane ──────────────────────

  it('fails import_only on a touched OpenClaw workspace memory directory', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const memDir = path.join(tmpHome, '.openclaw', 'workspace', 'memory');
    fs.mkdirSync(memDir, { recursive: true });
    fs.writeFileSync(path.join(memDir, 'notes.md'), '# still the brain\n'.repeat(20));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/native/i);
    expect(r.message).toMatch(/native_sot_touched_7d=true/);
  });

  it('ignores a fresh zero-byte native bootstrap file', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '');
    const r = await runDrift();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/native_sot_touched_7d=false/);
  });

  it('detects nested native memory growth recursively', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const nested = path.join(tmpHome, '.openclaw', 'workspace', 'memory', 'year', 'month');
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, 'notes.md'), '# nested native brain\n');
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/year.*month.*notes\.md/);
  });

  it('warns cannot-determine when native recursion exceeds the depth cap', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    db.close();
    let nested = path.join(tmpHome, '.openclaw', 'workspace', 'memory');
    for (let i = 0; i < 10; i++) nested = path.join(nested, `level-${i}`);
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(nested, 'notes.md'), '# beyond bounded scan\n');
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/);
    expect(r.message).toMatch(/exceeds native store recursion depth/);
  });

  it('fails import_only on a touched IMPLICIT per-agent OpenClaw workspace brain', async () => {
    // Reuses the host contract's workspace enumeration: a workspace-<agentId>
    // brain must not hide behind the stock workspace being clean.
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    fs.mkdirSync(path.join(tmpHome, '.openclaw'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({ agents: { list: [{ id: 'main', default: true }, { id: 'case' }] } }, null, 2),
    );
    const implicitWs = path.join(tmpHome, '.openclaw', 'workspace-case');
    fs.mkdirSync(implicitWs, { recursive: true });
    fs.writeFileSync(path.join(implicitWs, 'MEMORY.md'), '# implicit brain\n'.repeat(10));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/workspace-case/);
  });

  it('fails sc_canonical on a touched Claude Code native memory store', async () => {
    writeConfig(planeConfig('sc_canonical'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const store = path.join(tmpHome, '.claude', 'memory');
    fs.mkdirSync(store, { recursive: true });
    fs.writeFileSync(path.join(store, 'MEMORY.md'), '# native brain\n'.repeat(20));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/native_sot_touched_7d=true/);
  });

  it('fails import_only on a touched Hermes native memory store', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const store = path.join(tmpHome, '.hermes', 'memories');
    fs.mkdirSync(store, { recursive: true });
    fs.writeFileSync(path.join(store, 'MEMORY.md'), '# hermes brain\n'.repeat(20));
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/native_sot_touched_7d=true/);
  });

  it('detects a Hermes profile re-enabling default-on native memory', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    fs.mkdirSync(path.join(tmpHome, '.hermes'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.hermes', 'config.yaml'),
      'memory:\n  memory_enabled: false\n  user_profile_enabled: false\n',
    );
    const profile = path.join(tmpHome, '.hermes', 'profiles', 'research');
    fs.mkdirSync(profile, { recursive: true });
    fs.writeFileSync(path.join(profile, 'config.yaml'), 'memory:\n  memory_enabled: true\n');
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/Hermes profile research.*memory_enabled=true/);
  });

  it('cannot determine drift when a Hermes profile config is unreadable', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    fs.mkdirSync(path.join(tmpHome, '.hermes'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.hermes', 'config.yaml'),
      'memory:\n  memory_enabled: false\n  user_profile_enabled: false\n',
    );
    fs.mkdirSync(path.join(tmpHome, '.hermes', 'profiles', 'mystery', 'config.yaml'), { recursive: true });
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/);
    expect(r.message).toMatch(/Hermes profile mystery config\.yaml cannot be read/);
  });

  it('warns — never fails — on the same native SoT growth under dual_legacy', async () => {
    writeConfig(planeConfig('dual_legacy'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# dual brain\n'.repeat(20));
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/dual_legacy/);
  });

  it('ignores native SoT files last written before the window', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    const stale = path.join(ws, 'MEMORY.md');
    fs.writeFileSync(stale, '# archived brain\n'.repeat(20));
    const old = Date.now() - 60 * 24 * 60 * 60 * 1000;
    fs.utimesSync(stale, old / 1000, old / 1000);
    const r = await runDrift();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/native_sot_touched_7d=false/);
  });

  it('fails import_only when the native memory bus is provably still switched on', async () => {
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    fs.mkdirSync(path.join(tmpHome, '.openclaw'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: true } } } }, null, 2),
    );
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/native (memory )?bus/i);
  });

  // ── 5. Telemetry gaps never PASS silently ────────────────────────

  it('cannot determine drift when there is no activity telemetry at all', async () => {
    writeConfig(planeConfig('import_only'));
    const db = new Database(path.join(scDir, 'memories.db'));
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY,
        title TEXT, content TEXT, status TEXT, sensitivity_level TEXT,
        content_form TEXT, trust_score REAL, defence_verdict TEXT,
        source_attested INTEGER, pinned INTEGER, quarantined INTEGER, in_quarantine INTEGER,
        host_id TEXT, agent_id TEXT, project TEXT, transferable INTEGER,
        salience REAL, created_at TEXT
      );
    `);
    insertRow(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/i);
    expect(r.message).toMatch(/activity_7d=unknown/);
  });

  it('cannot determine drift when the memories table is unreadable', async () => {
    writeConfig(planeConfig('dual_legacy'));
    const db = new Database(path.join(scDir, 'memories.db'));
    db.exec(`CREATE TABLE session_events (id INTEGER PRIMARY KEY, created_at TEXT);`);
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/i);
  });

  it('cannot determine drift when the native SoT tree is unprobeable', async () => {
    // A relative OPENCLAW_STATE_DIR resolves against the OpenClaw process cwd,
    // so doctor cannot know where the native brain lives. It used to skip the
    // candidates and certify green off the SC side alone.
    process.env.OPENCLAW_STATE_DIR = './somewhere-relative';
    writeConfig(planeConfig('import_only'));
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/i);
  });

  // ── 6. Illegal plane × contract combos ───────────────────────────

  it('fails sc_canonical with no inject bus configured at all', async () => {
    writeConfig({ memory: { plane: 'sc_canonical' } });
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/sc_canonical/);
  });

  it('fails sc_canonical with inject explicitly off — canonicity without a bus', async () => {
    writeConfig({
      memory: { plane: 'sc_canonical', inject: { mode: 'off', nativeContract: 'sc_only' } },
    });
    const db = openDb();
    insertRow(db);
    addActivity(db);
    db.close();
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/sc_canonical/);
  });

  it('fails sc_canonical with turn-only inject — turn is not an automatic start bus', async () => {
    writeConfig({
      memory: { plane: 'sc_canonical', inject: { mode: 'turn', nativeContract: 'sc_only' } },
    });
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/without an automatic start bus/);
  });

  it('passes a signed honest sidecar even when native memory is live', async () => {
    const cloud = await import('../../cloud/config.js');
    cloud.setMemoryHostPosture('mcp_sidecar_no_inject');
    fs.mkdirSync(path.join(tmpHome, '.hermes'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.hermes', 'config.yaml'),
      'memory:\n  memory_enabled: true\n  user_profile_enabled: true\n',
    );
    const r = await runDrift();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/honest sidecar/);
    expect(r.message).toMatch(/native_bus_active=true/);
  });

  it('fails signed sidecar posture combined with import ownership', async () => {
    const cloud = await import('../../cloud/config.js');
    cloud.setMemoryPlane('import_only');
    cloud.setMemoryHostPosture('mcp_sidecar_no_inject');
    const r = await runDrift();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/contradicts posture/);
  });

  it('does not exempt an unsigned handcrafted sidecar posture', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject' },
        inject: { mode: 'off' },
      },
    });
    const db = openDb();
    insertRow(db);
    db.close();
    const store = path.join(tmpHome, '.hermes', 'memories');
    fs.mkdirSync(store, { recursive: true });
    fs.writeFileSync(path.join(store, 'MEMORY.md'), '# native remains live\n');
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).not.toMatch(/honest sidecar/);
  });

  it('does not exempt a posture carrying a forged embedded signature', async () => {
    writeConfig({
      _sig: 'forged',
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject' },
        inject: { mode: 'off' },
      },
    });
    const db = openDb();
    insertRow(db);
    db.close();
    const store = path.join(tmpHome, '.hermes', 'memories');
    fs.mkdirSync(store, { recursive: true });
    fs.writeFileSync(path.join(store, 'MEMORY.md'), '# native remains live\n');
    const r = await runDrift();
    expect(r.status).toBe('warn');
    expect(r.message).not.toMatch(/honest sidecar/);
  });
});
