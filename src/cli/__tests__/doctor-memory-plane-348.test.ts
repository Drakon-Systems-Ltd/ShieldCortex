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

  let trustedBinDir: string;

  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-348-home-'));
    scDir = path.join(tmpHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true, mode: 0o700 });
    // hookCommandTrust treats /tmp as a world-writable staging root, so a
    // wired-Claude fixture needs its binary OUTSIDE tmpHome — the repo tree
    // qualifies and is cleaned up below.
    trustedBinDir = fs.mkdtempSync(path.join(process.cwd(), '.jest-scbin-'));
    originalEnv = { ...process.env };
    process.env.HOME = tmpHome;
    process.env.USERPROFILE = tmpHome;
    // Hermeticity: a developer box with these set would silently relocate
    // every fixture's evidence root.
    delete process.env.OPENCLAW_STATE_DIR;
    delete process.env.OPENCLAW_CONFIG_PATH;
    jest.resetModules();
  });

  afterEach(() => {
    process.env = originalEnv;
    try { fs.rmSync(tmpHome, { recursive: true, force: true }); } catch { /* ignore */ }
    try { fs.rmSync(trustedBinDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /** A real executable at a non-staging path, so trust classification is deterministic. */
  function trustedShieldcortexCommand(): string {
    const bin = path.join(trustedBinDir, 'shieldcortex');
    fs.writeFileSync(bin, '#!/bin/sh\nexit 0\n');
    fs.chmodSync(bin, 0o755);
    return `${bin} hook session-start`;
  }

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

  // The installer's own artifact set (src/setup/openclaw.ts HOOK_FILES),
  // copied byte-identical from the packaged source so hookFilesStale agrees.
  // Jest runs from the repo root, so cwd-relative reaches the packaged source.
  const HOOK_SOURCE_DIR = path.resolve('hooks', 'openclaw', 'cortex-memory');
  function installRealHookArtifacts(): void {
    const dest = path.join(tmpHome, '.openclaw', 'hooks', 'cortex-memory');
    fs.mkdirSync(dest, { recursive: true });
    for (const f of ['HOOK.md', 'handler.ts', 'runtime.mjs']) {
      fs.copyFileSync(path.join(HOOK_SOURCE_DIR, f), path.join(dest, f));
    }
  }

  it('host contract needs memorySearch.enabled === false AND the real SC artifact set — a switch or a bare directory is half a contract', async () => {
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

    // SOL H1: an EMPTY hook directory is not wiring either — this exact shape
    // used to certify PASS.
    fs.mkdirSync(path.join(ocDir, 'hooks', 'cortex-memory'), { recursive: true });
    const bareDir = await runHost();
    expect(bareDir.status).toBe('fail');
    expect(bareDir.message).toMatch(/not proven delivered/);

    // SOL r3 B1: byte-current artifacts WITHOUT hooks.internal.enabled was the
    // r2 "legitimate PASS" fixture — but OpenClaw loads zero internal hooks
    // behind the closed global gate, so the pack never runs.
    installRealHookArtifacts();
    const gateClosed = await runHost();
    expect(gateClosed.status).toBe('fail');
    expect(gateClosed.message).toMatch(/not proven delivered/);
    expect(gateClosed.fix).toMatch(/hooks\.internal\.enabled=true/);

    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const full = await runHost();
    expect(full.status).toBe('pass');
    // Static proof only — the pass message must never read as a delivered receipt.
    expect(full.message).toMatch(/runtime delivery not attested/);
  });

  it('host contract fails when the host config disables the installed hook (hooks.internal.entries)', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true, entries: { 'cortex-memory': { enabled: false } } } },
      }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/not proven delivered/);
  });

  it('host contract treats a stale hook copy as unknown delivery, never wired (SOL H1)', async () => {
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars', agentId: 'h' },
      },
    });
    installRealHookArtifacts();
    fs.appendFileSync(path.join(tmpHome, '.openclaw', 'hooks', 'cortex-memory', 'handler.ts'), '\n// drift\n');
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/SC pack delivery unknown/);
  });

  it('hook artifacts are unverifiable when the packaged source is missing — never byte-current by default (SOL r2 B6)', async () => {
    installRealHookArtifacts();
    const mod = await import('../doctor.js');
    const dir = path.join(tmpHome, '.openclaw', 'hooks', 'cortex-memory');
    const files = ['HOOK.md', 'handler.ts', 'runtime.mjs'];
    expect(mod.probeOpenClawScHookArtifacts(dir, files, () => false, true)).toBe('complete');
    expect(mod.probeOpenClawScHookArtifacts(dir, files, () => false, false)).toBe('unverifiable');
    // With no source, the stale comparator must not even be consulted.
    expect(mod.probeOpenClawScHookArtifacts(dir, files, () => { throw new Error('never'); }, false)).toBe('unverifiable');
  });

  it('host contract honours OPENCLAW_STATE_DIR for config, hook, and workspace evidence (SOL r2 B6)', async () => {
    writeConfig(busContract());
    // Old, fully green artifacts under the DEFAULT root...
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    // ...must not certify a runtime that actually lives under a custom root
    // with no hook artifacts of its own.
    const customRoot = path.join(tmpHome, 'oc-state');
    fs.mkdirSync(customRoot, { recursive: true });
    fs.writeFileSync(
      path.join(customRoot, 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    process.env.OPENCLAW_STATE_DIR = customRoot;
    const unwired = await runHost();
    expect(unwired.status).toBe('fail');
    expect(unwired.message).toMatch(/not proven delivered/);

    // Workspace evidence is read from the custom root too.
    const ws = path.join(customRoot, 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'memory.md'), '# custom-root brain\n'.repeat(10));
    const brainy = await runHost();
    expect(brainy.status).toBe('fail');
    expect(brainy.message).toMatch(/memory\.md written within 7d/);
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
    // Real artifact set on disk, so the verdict isolates the unreadable config
    // (which blocks BOTH the native proof and the hook-enabled proof).
    installRealHookArtifacts();
    const r = await runHost();
    expect(r.status).not.toBe('pass');
    expect(r.message).toMatch(/cannot determine/);
    expect(r.fix).toMatch(/readable/);
  });

  it('host contract passes when every bound runtime proves native off and carries the SC pack', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/sc_only enforced/);
  });

  it('host contract fails an illegal inject mode instead of green-washing it (SOL H5)', async () => {
    // 'bogus' with disable_native_inject used to dodge the start-bus delivery
    // requirement while the runtime normalized it to start and injected.
    writeConfig({
      memory: { plane: 'dual_legacy', inject: { mode: 'bogus', nativeContract: 'disable_native_inject' } },
    });
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/illegal memory\.inject\.mode "bogus"/);
  });

  it('host contract treats a bare nativeContract as the start bus, never as "inject off" (emitter parity)', async () => {
    // The emitter reads memory.nativeInjectContract and defaults mode=start —
    // the old reading reported this exact shape as info "inject off".
    writeConfig({ memory: { plane: 'dual_legacy', nativeInjectContract: 'sc_only' } });
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/no bound host runtime found/);
  });

  it('host contract: a live Claude native store binds Claude even with no settings.json (SOL H2)', async () => {
    writeConfig(busContract());
    const memDir = path.join(tmpHome, '.claude', 'projects', 'proj', 'memory');
    fs.mkdirSync(memDir, { recursive: true });
    fs.writeFileSync(path.join(memDir, 'MEMORY.md'), '# claude brain\n'.repeat(30));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/paper contract/);
    expect(r.message).toMatch(/Claude Code: native ON/);
  });

  it('host contract: a live ~/.claude/CLAUDE.md preamble is native ON — the automatic brain must stop under a bus contract (SOL r2 B5)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    // Wired cleanly, so the verdict isolates the preamble evidence rather
    // than tripping the pack-delivery gate.
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    fs.writeFileSync(path.join(claudeDir, 'CLAUDE.md'), '# global preamble\n'.repeat(20));
    const live = await runHost();
    expect(live.status).toBe('fail');
    expect(live.message).toMatch(/Claude Code: native ON/);
    expect(live.message).toMatch(/CLAUDE\.md/);

    // Stale preamble: present but quiet is unknown, never off_proven.
    const old = (Date.now() - 40 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(path.join(claudeDir, 'CLAUDE.md'), old, old);
    const stale = await runHost();
    expect(stale.status).toBe('warn');
    expect(stale.message).toMatch(/cannot determine/);
  });

  it('host contract: a live per-project CLAUDE.md within the bounded projects scan is native ON (SOL r2 B5)', async () => {
    writeConfig(busContract());
    const projDir = path.join(tmpHome, '.claude', 'projects', 'proj');
    fs.mkdirSync(projDir, { recursive: true });
    fs.writeFileSync(path.join(projDir, 'CLAUDE.md'), '# project preamble\n'.repeat(20));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/Claude Code: native ON/);
    expect(r.message).toMatch(/proj\/CLAUDE\.md/);
  });

  it('host contract: a truncated Claude store scan can never prove off (SOL H2)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(path.join(claudeDir, 'memory'), { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    // 55 entries exceed the 50-file scan cap; pre-fix the slice left
    // scanComplete=true and this box proved off from a partial look.
    for (let i = 0; i < 55; i++) {
      fs.writeFileSync(path.join(claudeDir, 'memory', `note-${i}.txt`), 'x');
    }
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/scan could not complete/);
  });

  it('host contract: SessionStart ownership needs a resolvable, trustable executable (SOL r2 B3)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    // A command whose binary does not exist owned session-start before r2
    // while every hook died silently (#146 worn as a PASS).
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: `${path.join(tmpHome, 'ghost', 'shieldcortex')} hook session-start` }] }] },
      }),
    );
    const dead = await runHost();
    expect(dead.status).toBe('fail');
    expect(dead.message).toMatch(/not proven delivered/);

    // An executable planted under /tmp (tmpHome lives there) is at best
    // unknown — doctor cannot attest it is the ShieldCortex binary.
    const plantedBin = path.join(tmpHome, 'bin', 'shieldcortex');
    fs.mkdirSync(path.dirname(plantedBin), { recursive: true });
    fs.writeFileSync(plantedBin, '#!/bin/sh\nexit 0\n');
    fs.chmodSync(plantedBin, 0o755);
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: `${plantedBin} hook session-start` }] }] },
      }),
    );
    const planted = await runHost();
    expect(planted.status).toBe('warn');
    expect(planted.message).toMatch(/cannot determine/);
    expect(planted.message).toMatch(/SC pack delivery unknown/);

    // The same box with a clean, resolvable binary is the legitimate PASS.
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    const clean = await runHost();
    expect(clean.status).toBe('pass');
    expect(clean.message).toMatch(/executable resolves/);
  });

  it('host contract: a SessionStart matcher that skips startup is not wiring — compact-only hooks feed the wrong bus (SOL r3 B5)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    // The r3 false PASS: a resolving SC command whose matcher only covers
    // compaction owned session-start while every normal startup got no pack.
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ matcher: 'compact', hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    const restricted = await runHost();
    expect(restricted.status).toBe('fail');
    expect(restricted.message).toMatch(/not proven delivered/);

    // The same command under a startup-covering matcher is the legitimate PASS.
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ matcher: 'startup|resume', hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    const covering = await runHost();
    expect(covering.status).toBe('pass');
    expect(covering.message).toMatch(/matcher covers startup/);
  });

  it('host contract inspects configured custom/per-agent OpenClaw workspaces (SOL H4)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    const wsB = path.join(tmpHome, 'agents', 'case-ws');
    fs.mkdirSync(wsB, { recursive: true });
    fs.writeFileSync(path.join(wsB, 'AGENTS.md'), 'Read MEMORY.md at the start of every session.');
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: {
          defaults: { memorySearch: { enabled: false } },
          list: [{ name: 'case', workspace: wsB }],
        },
      }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/case-ws\/AGENTS\.md/);
  });

  it('host contract demotes unreadable workspace evidence to cannot determine (SOL H4)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    // A directory at the AGENTS.md path reads as present-but-unreadable.
    fs.mkdirSync(path.join(tmpHome, '.openclaw', 'workspace', 'AGENTS.md'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/workspace evidence unreadable/);
  });

  it('host contract: a Hermes profile with native memory on defeats root false/false (SOL H6)', async () => {
    writeConfig(busContract());
    writeHermes({ memoryEnabled: false, userProfile: false });
    const profDir = path.join(tmpHome, '.hermes', 'profiles', 'research');
    fs.mkdirSync(profDir, { recursive: true });
    fs.writeFileSync(
      path.join(profDir, 'config.yaml'),
      'memory:\n  memory_enabled: true\n  user_profile_enabled: false\n',
    );
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/research: memory_enabled=true/);
  });

  it('host contract: a Hermes profile without a readable config.yaml can never prove off (SOL H6)', async () => {
    // disable_native_inject on the turn bus needs no delivery proof, and a
    // wired OpenClaw supplies the inject surface — so the verdict isolates the
    // Hermes profile-switch gap.
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        inject: { mode: 'turn', nativeContract: 'disable_native_inject', hostId: 'tars', agentId: 'h' },
      },
    });
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    writeHermes({ memoryEnabled: false, userProfile: false });
    fs.mkdirSync(path.join(tmpHome, '.hermes', 'profiles', 'mystery'), { recursive: true });
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/cannot determine/);
    expect(r.message).toMatch(/mystery \(no config\.yaml/);
  });

  it('host contract fails a live lowercase memory.md under dual_legacy — bootstrap files defeat sc_only on every plane (SOL r2 B1)', async () => {
    // The exact r2 false PASS: dual_legacy + sc_only + memorySearch off +
    // wired hook + live native workspace memory file certified green.
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'memory.md'), '# lowercase brain\n'.repeat(10));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/memory\.md written within 7d/);
    expect(r.message).toMatch(/bootstraps workspace memory files/);
  });

  it('host contract fails a stale workspace bootstrap file — OpenClaw loads it on presence, so age proves nothing (SOL r3 B2)', async () => {
    // The r3 false PASS: an otherwise fully green box (memorySearch off, gate
    // open, byte-current hook) with an 8-day-old MEMORY.md certified PASS
    // while OpenClaw bootstrapped that file into every normal session.
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const ws = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# quiet brain\n');
    const old = (Date.now() - 8 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(path.join(ws, 'MEMORY.md'), old, old);
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/present but not written in 7d/);
    expect(r.message).toMatch(/PRESENCE/);
    expect(r.fix).toMatch(/archive\/remove/);
  });

  it('host contract: a profile-only Hermes tree binds and is judged — it cannot ride another runtime to PASS (SOL r2 B2)', async () => {
    // Green OpenClaw everywhere; the ONLY Hermes evidence is a live profile
    // config. Root config.yaml, SC plugin, and declaration all absent.
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({ agents: { defaults: { memorySearch: { enabled: false } } } }, null, 2),
    );
    const profDir = path.join(tmpHome, '.hermes', 'profiles', 'research');
    fs.mkdirSync(profDir, { recursive: true });
    fs.writeFileSync(path.join(profDir, 'config.yaml'), 'memory:\n  memory_enabled: true\n');
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/research: memory_enabled=true/);
    expect(r.fix).toMatch(/mcp_sidecar_no_inject/);
  });

  it('host contract fails sc_only on a Hermes-bound box even with the native switches off — sidecar is the honest posture', async () => {
    // The TARS shape after flipping Hermes' own switches: native proven off,
    // OpenClaw proven off and wired — still FAIL, because nothing delivers the
    // SC pack on the Hermes bus (no SC inject surface until Phase-2 ships).
    writeConfig(busContract());
    writeHermes({ memoryEnabled: false, userProfile: false });
    installRealHookArtifacts();
    const ocDir = path.join(tmpHome, '.openclaw');
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
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

  it('host contract fails a hand-crafted posture-only blob — sidecar needs inject.mode explicitly off (SOL r2 B4)', async () => {
    writeHermes({ memoryEnabled: true, userProfile: true });
    // No memory.inject at all: the emitter would default to start and emit
    // legacy sidecar recall while doctor certified "SC inject off".
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject', runtimes: ['hermes'] },
      },
    });
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/not explicitly off/);
    expect(r.fix).toMatch(/--memory-host-posture mcp_sidecar_no_inject/);
  });

  it('host contract rejects a junk posture instead of ignoring it', async () => {
    writeConfig({
      memory: { plane: 'dual_legacy', hostContract: { posture: 'coexist_dedup' }, inject: { mode: 'off' } },
    });
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/illegal memory\.hostContract\.posture/);
  });

  it('host contract fails junk hostContract.runtimes entries instead of silently filtering them (SOL r2 nit)', async () => {
    // 'grok' used to vanish, leaving 'hermes' as the only declared runtime —
    // an unsupported declaration must be a loud failure, not a smaller net.
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { runtimes: ['hermes', 'grok'] },
        inject: { mode: 'start', nativeContract: 'sc_only' },
      },
    });
    const junkEntry = await runHost();
    expect(junkEntry.status).toBe('fail');
    expect(junkEntry.message).toMatch(/illegal memory\.hostContract\.runtimes entry "grok"/);
    expect(junkEntry.fix).toMatch(/--memory-host-runtime/);

    // A non-array value for the whole key is the same class of junk.
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { runtimes: 'hermes' },
        inject: { mode: 'start', nativeContract: 'sc_only' },
      },
    });
    const nonArray = await runHost();
    expect(nonArray.status).toBe('fail');
    expect(nonArray.message).toMatch(/illegal memory\.hostContract\.runtimes/);
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

