/**
 * Track A harden + T1 doctor checks (#348 / #393 / #394).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac } from 'crypto';
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
    // cloud/config imports homedir as a stable binding while doctor probes via
    // os.homedir(); pin the product-supported override so both rows and signed
    // setters grade the same sandboxed bytes.
    process.env.SHIELDCORTEX_CONFIG_DIR = scDir;
    // Hermeticity: a developer box with these set would silently relocate
    // every fixture's evidence root.
    delete process.env.OPENCLAW_STATE_DIR;
    delete process.env.OPENCLAW_CONFIG_PATH;
    delete process.env.OPENCLAW_PROFILE;
    delete process.env.OPENCLAW_HOME;
    delete process.env.CLAWDBOT_STATE_DIR;
    delete process.env.CLAWDBOT_CONFIG_PATH;
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

  function writeSignedConfig(cfg: Record<string, unknown>): void {
    const key = fs.readFileSync(path.join(scDir, '.integrity-key'), 'utf-8').trim();
    const body = JSON.stringify(cfg, null, 2);
    const sig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
    writeConfig({ ...cfg, _sig: sig });
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
  function installRealHookArtifacts(stateRoot = path.join(tmpHome, '.openclaw')): void {
    const dest = path.join(stateRoot, 'hooks', 'cortex-memory');
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

  it('host contract expands ~ in OPENCLAW_STATE_DIR / OPENCLAW_CONFIG_PATH the way resolveUserPath does (SOL r3 B6)', async () => {
    // The r3 defect: "~/oc-alt" was probed as a LITERAL relative path, so the
    // real tree under $HOME/oc-alt vanished and its readings with it.
    writeConfig(busContract());
    const altRoot = path.join(tmpHome, 'oc-alt');
    installRealHookArtifacts(altRoot);
    fs.writeFileSync(
      path.join(altRoot, 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    process.env.OPENCLAW_STATE_DIR = '~/oc-alt';
    const viaTilde = await runHost();
    expect(viaTilde.status).toBe('pass');
    expect(viaTilde.message).toMatch(/sc_only enforced/);

    // A live brain under the tilde root must equally be found.
    const ws = path.join(altRoot, 'workspace');
    fs.mkdirSync(ws, { recursive: true });
    fs.writeFileSync(path.join(ws, 'MEMORY.md'), '# alt brain\n'.repeat(5));
    const brainy = await runHost();
    expect(brainy.status).toBe('fail');
    expect(brainy.message).toMatch(/MEMORY\.md written within 7d/);

    // OPENCLAW_CONFIG_PATH expands the same way — a tilde config that leaves
    // Memory Search default-ON must be read and failed.
    delete process.env.OPENCLAW_STATE_DIR;
    fs.writeFileSync(path.join(tmpHome, 'oc.json'), JSON.stringify({ agents: { defaults: {} } }, null, 2));
    process.env.OPENCLAW_CONFIG_PATH = '~/oc.json';
    const viaConfig = await runHost();
    expect(viaConfig.status).toBe('fail');
    expect(viaConfig.message).toMatch(/default-ON/);
  });

  it('host contract treats relative or ~user path overrides as unresolvable — OpenClaw cannot vanish while another runtime carries the PASS (SOL r3 B6)', async () => {
    // Fully green Claude Code, so the old behavior (relative override probed
    // against the DOCTOR cwd, found nothing, OpenClaw unbound) certified an
    // overall PASS on the back of the other runtime.
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    process.env.OPENCLAW_STATE_DIR = 'oc-state';
    const relative = await runHost();
    expect(relative.status).toBe('warn');
    expect(relative.message).toMatch(/cannot determine/);
    expect(relative.message).toMatch(/OPENCLAW_STATE_DIR/);
    expect(relative.message).toMatch(/cannot know/);
    expect(relative.fix).toMatch(/absolute path/);

    // ~user is NOT expanded by the host (expandHomePrefix rewrites only the
    // bare ~ prefix) — it resolves against OpenClaw's cwd and is equally
    // unresolvable for doctor.
    process.env.OPENCLAW_STATE_DIR = '~ubuntu/.openclaw';
    const tildeUser = await runHost();
    expect(tildeUser.status).toBe('warn');
    expect(tildeUser.message).toMatch(/~user/);

    // Same law for the config-path override.
    delete process.env.OPENCLAW_STATE_DIR;
    process.env.OPENCLAW_CONFIG_PATH = 'configs/openclaw.json';
    const relConfig = await runHost();
    expect(relConfig.status).toBe('warn');
    expect(relConfig.message).toMatch(/OPENCLAW_CONFIG_PATH/);
  });

  it('host contract marks an explicit relative agent workspace as an incomplete enumeration, never probing the doctor cwd (SOL r3 B6)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: {
          defaults: { memorySearch: { enabled: false } },
          list: [{ id: 'main', default: true }, { id: 'case', workspace: 'agents/case-ws' }],
        },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/could not all be enumerated/);
  });

  it('host contract: a relative OPENCLAW_HOME is unresolvable — never probed against the doctor cwd (SOL r4 B2)', async () => {
    // The r4 defect: OPENCLAW_HOME was path.resolve()d against the DOCTOR cwd,
    // while the host resolves it against the OPENCLAW process cwd
    // (openclaw/src/infra/home-dir.ts). Different working directories meant
    // doctor could certify green artifacts from one tree while OpenClaw ran
    // unwired from another. Fully green fixtures under the default root make
    // the old behavior reach PASS, so any regression trips this test.
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    process.env.OPENCLAW_HOME = 'oc-home';
    const relative = await runHost();
    expect(relative.status).toBe('warn');
    expect(relative.message).toMatch(/OPENCLAW_HOME/);
    expect(relative.message).toMatch(/cannot know/);
    expect(relative.fix).toMatch(/absolute path/);

    // ~user never expands in the host either — it rides the same cwd fallback.
    process.env.OPENCLAW_HOME = '~ubuntu/oc';
    const tildeUser = await runHost();
    expect(tildeUser.status).toBe('warn');
    expect(tildeUser.message).toMatch(/OPENCLAW_HOME/);

    // An ABSOLUTE OPENCLAW_HOME relocates the whole effective-home tree; the
    // evidence must be read from there, not from $HOME.
    const ocHomeDir = path.join(tmpHome, 'oc-home');
    installRealHookArtifacts(path.join(ocHomeDir, '.openclaw'));
    fs.writeFileSync(
      path.join(ocHomeDir, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    process.env.OPENCLAW_HOME = ocHomeDir;
    const absolute = await runHost();
    expect(absolute.status).toBe('pass');
    expect(absolute.message).toMatch(/sc_only enforced/);
  });

  it('host contract: byte-current artifacts cannot wire the bus when npx is missing — runtime eligibility is part of the proof (SOL r4 B4)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    // Sanity: with npx resolvable (any dev/CI PATH) this is the r3 green.
    const wired = await runHost();
    expect(wired.status).toBe('pass');

    // PATH scrubbed to an empty dir: HOOK.md requires npx and OpenClaw drops
    // runtime-ineligible hooks at load, so the same artifact set caps at
    // unknown — doctor cannot attest the hook would ever register.
    const emptyBin = path.join(tmpHome, 'empty-bin');
    fs.mkdirSync(emptyBin, { recursive: true });
    process.env.PATH = emptyBin;
    const scrubbed = await runHost();
    expect(scrubbed.status).toBe('warn');
    expect(scrubbed.message).toMatch(/SC pack delivery unknown/);
    expect(scrubbed.fix).toMatch(/required binaries/);
  });

  it("doctor's required-bins pin matches the packaged HOOK.md requires (SOL r4 B4 drift guard)", async () => {
    const mod = await import('../doctor.js');
    const raw = fs.readFileSync(path.join(HOOK_SOURCE_DIR, 'HOOK.md'), 'utf-8');
    const meta = raw.match(/^metadata:\s*\n\s*(\{.*\})\s*$/m);
    expect(meta).not.toBeNull();
    const parsed = JSON.parse(meta![1]) as {
      openclaw?: { os?: unknown; always?: unknown; requires?: Record<string, unknown> };
    };
    // The whole requires block is pinned — a new bins/anyBins/env/config
    // requirement (or an os restriction) added to the hook without teaching
    // doctor must fail here, not green-wash at runtime.
    expect(parsed.openclaw?.requires).toEqual({ bins: [...mod.OPENCLAW_HOOK_REQUIRED_BINS] });
    expect(parsed.openclaw?.os).toBeUndefined();
    expect(parsed.openclaw?.always).toBeUndefined();
  });

  it('host contract: a default-workspace hook that shadows cortex-memory defeats pristine managed artifacts (SOL r4 B3)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const wsHooks = path.join(tmpHome, '.openclaw', 'workspace', 'hooks');

    // The r4 false PASS: managed artifacts pristine, gate open — but the
    // default workspace shadows cortex-memory with a drifted handler, and
    // OpenClaw loads THAT one (workspace hooks win by name at merge).
    const shadow = path.join(wsHooks, 'cortex-memory');
    fs.mkdirSync(shadow, { recursive: true });
    for (const f of ['HOOK.md', 'handler.ts', 'runtime.mjs']) {
      fs.copyFileSync(path.join(HOOK_SOURCE_DIR, f), path.join(shadow, f));
    }
    fs.appendFileSync(path.join(shadow, 'handler.ts'), '\n// drifted shadow\n');
    const shadowed = await runHost();
    expect(shadowed.status).toBe('warn');
    expect(shadowed.message).toMatch(/SC pack delivery unknown/);
    expect(shadowed.fix).toMatch(/default-workspace cortex-memory hook/);

    // A byte-identical shadow delivers the same pack — still statically wired.
    fs.copyFileSync(path.join(HOOK_SOURCE_DIR, 'handler.ts'), path.join(shadow, 'handler.ts'));
    const identical = await runHost();
    expect(identical.status).toBe('pass');
    expect(identical.message).toMatch(/runtime delivery not attested/);

    // frontmatter `name:` rebrands ANY dir — a differently-named workspace
    // hook that declares cortex-memory cannot be cleared.
    fs.rmSync(shadow, { recursive: true, force: true });
    const rebrand = path.join(wsHooks, 'innocent-hook');
    fs.mkdirSync(rebrand, { recursive: true });
    fs.writeFileSync(path.join(rebrand, 'HOOK.md'), '---\nname: cortex-memory\n---\n# not the pack\n');
    fs.writeFileSync(path.join(rebrand, 'handler.ts'), 'export default async () => {};\n');
    const rebranded = await runHost();
    expect(rebranded.status).toBe('warn');
    expect(rebranded.message).toMatch(/SC pack delivery unknown/);

    // An unrelated workspace hook with a plainly different name is cleared —
    // custom hooks must not tax the verdict.
    fs.rmSync(rebrand, { recursive: true, force: true });
    const other = path.join(wsHooks, 'other-hook');
    fs.mkdirSync(other, { recursive: true });
    fs.writeFileSync(path.join(other, 'HOOK.md'), '---\nname: other-hook\ndescription: unrelated\n---\n# other\n');
    fs.writeFileSync(path.join(other, 'handler.ts'), 'export default async () => {};\n');
    const cleared = await runHost();
    expect(cleared.status).toBe('pass');
  });

  it('host contract: the shadow probe follows the CONFIGURED default workspace — exactly where the gateway loads hooks (SOL r4 B3)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    const customWs = path.join(tmpHome, 'custom-ws');
    fs.mkdirSync(path.join(customWs, 'hooks', 'cortex-memory'), { recursive: true });
    fs.writeFileSync(path.join(customWs, 'hooks', 'cortex-memory', 'HOOK.md'), '---\nname: cortex-memory\n---\nnot the pack\n');
    fs.writeFileSync(path.join(customWs, 'hooks', 'cortex-memory', 'handler.ts'), 'export default async () => {};\n');
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false }, workspace: '~/custom-ws' } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const shadowed = await runHost();
    expect(shadowed.status).toBe('warn');
    expect(shadowed.message).toMatch(/SC pack delivery unknown/);

    // A stray cortex-memory dir in the STOCK workspace is inert once the
    // default workspace lives elsewhere — the gateway loads hooks from ONE
    // workspace, so precision here keeps honest installs green.
    fs.rmSync(path.join(customWs, 'hooks'), { recursive: true, force: true });
    const strayDir = path.join(tmpHome, '.openclaw', 'workspace', 'hooks', 'cortex-memory');
    fs.mkdirSync(strayDir, { recursive: true });
    fs.writeFileSync(path.join(strayDir, 'HOOK.md'), '---\nname: cortex-memory\n---\nstray\n');
    fs.writeFileSync(path.join(strayDir, 'handler.ts'), 'export default async () => {};\n');
    const inert = await runHost();
    expect(inert.status).toBe('pass');
  });

  it('host contract: $include in openclaw.json defeats pristine artifacts — doctor cannot attest the merged config (SOL r5 B1)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    const ocDir = path.join(tmpHome, '.openclaw');
    // The exact r5 shape: raw root reads gate-open + memorySearch-off (the r3
    // green), but OpenClaw deep-merges the included file BEFORE evaluating —
    // and that file disables the cortex-memory entry.
    fs.writeFileSync(
      path.join(ocDir, 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true, entries: { $include: './entries.json5' } } },
      }, null, 2),
    );
    fs.writeFileSync(
      path.join(ocDir, 'entries.json5'),
      JSON.stringify({ 'cortex-memory': { enabled: false } }, null, 2),
    );
    const verdict = await runHost();
    expect(verdict.status).toBe('warn');
    expect(verdict.message).toMatch(/cannot determine host contract/);
    expect(verdict.fix).toMatch(/\$include/);
  });

  it('openClawBoundConfigCandidate mirrors resolveDefaultConfigCandidates precedence (SOL r6 B1)', async () => {
    const mod = await import('../doctor.js');
    const defaultRoot = path.join(tmpHome, '.openclaw');
    // Nothing anywhere: no candidate binds.
    expect(mod.openClawBoundConfigCandidate(tmpHome, defaultRoot, false)).toEqual({ kind: 'none' });
    // A legacy filename in a legacy state dir binds (clawdbot era).
    fs.mkdirSync(path.join(tmpHome, '.clawdbot'), { recursive: true });
    fs.writeFileSync(path.join(tmpHome, '.clawdbot', 'clawdbot.json'), '{}');
    expect(mod.openClawBoundConfigCandidate(tmpHome, defaultRoot, false)).toEqual({
      kind: 'ungraded',
      path: path.join(tmpHome, '.clawdbot', 'clawdbot.json'),
    });
    // A legacy filename in the CURRENT state dir outranks it (dir-major order,
    // exactly resolveDefaultConfigCandidates).
    fs.mkdirSync(defaultRoot, { recursive: true });
    fs.writeFileSync(path.join(defaultRoot, 'moltbot.json'), '{}');
    expect(mod.openClawBoundConfigCandidate(tmpHome, defaultRoot, false)).toEqual({
      kind: 'ungraded',
      path: path.join(defaultRoot, 'moltbot.json'),
    });
    // The graded openclaw.json is candidate #1 and wins outright.
    fs.writeFileSync(path.join(defaultRoot, 'openclaw.json'), '{}');
    expect(mod.openClawBoundConfigCandidate(tmpHome, defaultRoot, false)).toEqual({ kind: 'graded' });
    // With OPENCLAW_STATE_DIR, the override dir's candidates come first — but
    // the HOME default dirs are still on OpenClaw's list, so a config there
    // binds even when the override dir is empty.
    const custom = path.join(tmpHome, 'oc-state');
    fs.mkdirSync(custom, { recursive: true });
    expect(mod.openClawBoundConfigCandidate(tmpHome, custom, true)).toEqual({
      kind: 'ungraded',
      path: path.join(defaultRoot, 'openclaw.json'),
    });
    fs.writeFileSync(path.join(custom, 'clawdbot.json'), '{}');
    expect(mod.openClawBoundConfigCandidate(tmpHome, custom, true)).toEqual({
      kind: 'ungraded',
      path: path.join(custom, 'clawdbot.json'),
    });
    fs.writeFileSync(path.join(custom, 'openclaw.json'), '{}');
    expect(mod.openClawBoundConfigCandidate(tmpHome, custom, true)).toEqual({ kind: 'graded' });
  });

  it('host contract: a clawdbot-era config plus a live workspace MEMORY.md binds OpenClaw — never PASS on the back of a clean runtime (SOL r6 B1)', async () => {
    // Fully green Claude Code: before the fix, OpenClaw saw no binding signal
    // (graded openclaw.json absent, no hook, nothing declared) and dropped
    // from the verdict while Claude carried the box to PASS — despite
    // OpenClaw loading clawdbot.json and bootstrapping the memory file.
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    fs.mkdirSync(path.join(tmpHome, '.clawdbot'), { recursive: true });
    fs.writeFileSync(path.join(tmpHome, '.clawdbot', 'clawdbot.json'), '{}');
    const wsDir = path.join(tmpHome, '.openclaw', 'workspace');
    fs.mkdirSync(wsDir, { recursive: true });
    fs.writeFileSync(path.join(wsDir, 'MEMORY.md'), '# session brain\n'.repeat(8));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/OpenClaw/);
    expect(r.message).toMatch(/native automatic memory still owns the bus|native ON/);

    // Even without the memory file, the legacy candidate alone binds — with
    // no SC hook the pack is not delivered on a bound runtime: fail, never
    // the old PASS.
    fs.rmSync(path.join(wsDir, 'MEMORY.md'), { force: true });
    const legacyOnly = await runHost();
    expect(legacyOnly.status).toBe('fail');
    expect(legacyOnly.message).toMatch(/not proven delivered/);
    expect(legacyOnly.message).toMatch(/OpenClaw/);

    // Byte-current artifacts do not rescue it either: the hooks.internal gate
    // lives in a config doctor does not grade, so delivery caps at unknown.
    installRealHookArtifacts();
    const withArtifacts = await runHost();
    expect(withArtifacts.status).toBe('warn');
    expect(withArtifacts.message).toMatch(/legacy OpenClaw config/);
    expect(withArtifacts.message).toMatch(/grades only openclaw\.json/);
  });

  it('probeOpenClawHooksDirClaim: the exact r6 manifest-redirect shape in the MANAGED dir is never cleared (SOL r6 B2)', async () => {
    const mod = await import('../doctor.js');
    const files = ['HOOK.md', 'handler.ts', 'runtime.mjs'];
    installRealHookArtifacts();
    const managed = path.join(tmpHome, '.openclaw', 'hooks');
    // Byte-current artifacts alone: the managed dir provably serves the pack.
    expect(mod.probeOpenClawHooksDirClaim(managed, files, () => false, true)).toEqual({ kind: 'identical' });
    // {"openclaw":{"hooks":["nested"]}}: OpenClaw loads nested/HOOK.md and
    // SKIPS the root HOOK.md (hooks/workspace.ts loadHooksFromDir) — the
    // byte-current root set never runs.
    const dest = path.join(managed, 'cortex-memory');
    fs.mkdirSync(path.join(dest, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(dest, 'nested', 'HOOK.md'), '---\nname: cortex-memory\n---\nnot the pack\n');
    fs.writeFileSync(path.join(dest, 'nested', 'handler.ts'), 'export default async () => {};\n');
    fs.writeFileSync(path.join(dest, 'package.json'), JSON.stringify({ openclaw: { hooks: ['nested'] } }));
    const redirected = mod.probeOpenClawHooksDirClaim(managed, files, () => false, true);
    expect(redirected.kind).toBe('unproven');
    expect((redirected as { detail: string }).detail).toMatch(/package\.json/);
  });

  it('host contract: a manifest in the managed cortex-memory dir, or a sibling claiming the name, defeats byte-current artifacts (SOL r6 B2)', async () => {
    // The full r3 green: gate open, memorySearch off, byte-current artifacts.
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    expect((await runHost()).status).toBe('pass');

    // Exact r6 shape: a valid package.json under the byte-current managed
    // cortex-memory dir redirects hook definitions — the root HOOK.md is
    // skipped, so the SC bootstrap hook never loads. Used to certify PASS.
    const dest = path.join(tmpHome, '.openclaw', 'hooks', 'cortex-memory');
    fs.writeFileSync(path.join(dest, 'package.json'), JSON.stringify({ openclaw: { hooks: ['nested'] } }));
    const redirected = await runHost();
    expect(redirected.status).toBe('warn');
    expect(redirected.message).toMatch(/SC pack delivery unknown/);
    expect(redirected.fix).toMatch(/managed hooks dir/);
    fs.rmSync(path.join(dest, 'package.json'), { force: true });

    // A SIBLING managed hook dir that could claim the cortex-memory name via
    // frontmatter is equally unproven — same-source name collisions leave
    // what-runs unattested.
    const sibling = path.join(tmpHome, '.openclaw', 'hooks', 'sneaky');
    fs.mkdirSync(sibling, { recursive: true });
    fs.writeFileSync(path.join(sibling, 'HOOK.md'), '---\nname: cortex-memory\n---\nnot the pack\n');
    fs.writeFileSync(path.join(sibling, 'handler.ts'), 'export default async () => {};\n');
    const claimed = await runHost();
    expect(claimed.status).toBe('warn');
    expect(claimed.message).toMatch(/SC pack delivery unknown/);
    fs.rmSync(sibling, { recursive: true, force: true });

    // A benign sibling managed hook (plain frontmatter, no manifest, never
    // names cortex-memory) must not break the honest green.
    const benign = path.join(tmpHome, '.openclaw', 'hooks', 'other-hook');
    fs.mkdirSync(benign, { recursive: true });
    fs.writeFileSync(path.join(benign, 'HOOK.md'), '---\nname: other-hook\ndescription: fine\n---\nok\n');
    fs.writeFileSync(path.join(benign, 'handler.ts'), 'export default async () => {};\n');
    expect((await runHost()).status).toBe('pass');
  });

  it('$include makes workspace enumeration and the default workspace unattestable (SOL r5 B1)', async () => {
    const mod = await import('../doctor.js');
    const cfg = (value: Record<string, unknown>) => ({ kind: 'present' as const, value });
    const inc = cfg({ agents: { $include: './agents.json5' } });
    // Included content can add defaults/per-agent workspaces doctor never
    // enumerates — the scan must refuse to claim completeness…
    expect(mod.openClawWorkspacePaths(tmpHome, path.join(tmpHome, '.openclaw'), inc).complete).toBe(false);
    // …and can redirect the ONE workspace the gateway loads hooks from.
    expect('unresolvable' in mod.openClawDefaultWorkspace(tmpHome, inc)).toBe(true);
    // Without the directive both readings stand as before.
    const plain = cfg({ agents: { defaults: {} } });
    expect(mod.openClawWorkspacePaths(tmpHome, path.join(tmpHome, '.openclaw'), plain).complete).toBe(true);
    expect(mod.openClawDefaultWorkspace(tmpHome, plain)).toEqual({ path: path.join(tmpHome, '.openclaw', 'workspace') });
  });

  it('openClawDefaultWorkspace mirrors resolveAgentWorkspaceDir for the default agent (SOL r4 B3)', async () => {
    const mod = await import('../doctor.js');
    const home = tmpHome;
    const cfg = (value: Record<string, unknown>) => ({ kind: 'present' as const, value });
    // No config: the stock home workspace.
    expect(mod.openClawDefaultWorkspace(home, { kind: 'absent' })).toEqual({ path: path.join(home, '.openclaw', 'workspace') });
    // agents.defaults.workspace wins for the default agent…
    expect(mod.openClawDefaultWorkspace(home, cfg({ agents: { defaults: { workspace: '~/ws-a' } } })))
      .toEqual({ path: path.join(home, 'ws-a') });
    // …but the default agent's own entry outranks it (ids normalize).
    expect(mod.openClawDefaultWorkspace(home, cfg({
      agents: { defaults: { workspace: '~/ws-a' }, list: [{ id: 'Main', workspace: '~/ws-b' }] },
    }))).toEqual({ path: path.join(home, 'ws-b') });
    // The default flag elects the entry.
    expect(mod.openClawDefaultWorkspace(home, cfg({
      agents: { list: [{ id: 'a' }, { id: 'B', default: true, workspace: '~/ws-c' }] },
    }))).toEqual({ path: path.join(home, 'ws-c') });
    // A relative configured workspace resolves against the OpenClaw process
    // cwd — unresolvable for doctor, never guessed.
    expect('unresolvable' in mod.openClawDefaultWorkspace(home, cfg({
      agents: { defaults: { workspace: 'rel/ws' } },
    }))).toBe(true);
    // OPENCLAW_PROFILE suffixes the stock default, exactly like
    // resolveDefaultAgentWorkspaceDir.
    process.env.OPENCLAW_PROFILE = 'work';
    expect(mod.openClawDefaultWorkspace(home, { kind: 'absent' })).toEqual({ path: path.join(home, '.openclaw', 'workspace-work') });
    delete process.env.OPENCLAW_PROFILE;
  });

  it('probeOpenClawWorkspaceHookShadow: manifests, unevaluable names, and cap overflow can never be cleared (SOL r4 B3)', async () => {
    const mod = await import('../doctor.js');
    const files = ['HOOK.md', 'handler.ts', 'runtime.mjs'];
    const ws = path.join(tmpHome, 'shadow-ws');
    const mk = (rel: string, content = ''): void => {
      const p = path.join(ws, rel);
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, content);
    };
    // No hooks dir at all → nothing can shadow.
    fs.mkdirSync(ws, { recursive: true });
    expect(mod.probeOpenClawWorkspaceHookShadow(ws, files, () => false, true)).toEqual({ kind: 'none' });
    // A dir with no HOOK.md and no manifest loads nothing (loadHookFromDir
    // returns null without HOOK.md).
    fs.mkdirSync(path.join(ws, 'hooks', 'empty-dir'), { recursive: true });
    expect(mod.probeOpenClawWorkspaceHookShadow(ws, files, () => false, true)).toEqual({ kind: 'none' });
    // package.json redirects hook definitions — unprovable without the loader.
    mk('hooks/pkg-hook/package.json', '{}');
    const viaManifest = mod.probeOpenClawWorkspaceHookShadow(ws, files, () => false, true);
    expect(viaManifest.kind).toBe('unproven');
    expect((viaManifest as { detail: string }).detail).toMatch(/package\.json/);
    fs.rmSync(path.join(ws, 'hooks', 'pkg-hook'), { recursive: true, force: true });
    // A `name:` doctor cannot evaluate plainly (YAML escapes could spell
    // cortex-memory without the literal appearing) is never cleared.
    mk('hooks/sneaky/HOOK.md', '---\nname: "cortex-memor\\x79"\n---\nhi\n');
    mk('hooks/sneaky/handler.ts', 'export default 1;\n');
    const sneaky = mod.probeOpenClawWorkspaceHookShadow(ws, files, () => false, true);
    expect(sneaky.kind).toBe('unproven');
    fs.rmSync(path.join(ws, 'hooks', 'sneaky'), { recursive: true, force: true });
    // More hook dirs than the scan bounds — incomplete, never silently cleared.
    for (let i = 0; i < 51; i++) fs.mkdirSync(path.join(ws, 'hooks', `h-${i}`), { recursive: true });
    const overflow = mod.probeOpenClawWorkspaceHookShadow(ws, files, () => false, true);
    expect(overflow.kind).toBe('unproven');
    expect((overflow as { detail: string }).detail).toMatch(/incomplete/);
  });

  it('workspace shadow scan clears only frontmatter proven benign by strict literal parse — escaped YAML rebrands never clear (SOL r5 B2)', async () => {
    const mod = await import('../doctor.js');
    const files = ['HOOK.md', 'handler.ts', 'runtime.mjs'];
    const ws = path.join(tmpHome, 'esc-ws');
    const probeWith = (hookMd: string): { kind: string } => {
      fs.rmSync(path.join(ws, 'hooks'), { recursive: true, force: true });
      const dir = path.join(ws, 'hooks', 'candidate');
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'HOOK.md'), hookMd);
      fs.writeFileSync(path.join(dir, 'handler.ts'), 'export default async () => {};\n');
      return mod.probeOpenClawWorkspaceHookShadow(ws, files, () => false, true);
    };
    // The exact r5 shape: the host YAML parser (openclaw/src/markdown/
    // frontmatter.ts YAML.parse) decodes "\u006eame": "\u0063ortex-memory"
    // to name: cortex-memory — no literal cortex-memory, no plain `name:`
    // line, and the workspace hook wins the merge by name.
    expect(probeWith('---\n"\\u006eame": "\\u0063ortex-memory"\n---\nhi\n').kind).toBe('unproven');
    // Quoted values decode under the host parser too — never cleared.
    expect(probeWith('---\nname: "innocent"\n---\nhi\n').kind).toBe('unproven');
    // Flow maps restructure the whole block.
    expect(probeWith('---\n{ name: innocent }\n---\nhi\n').kind).toBe('unproven');
    // A name with no inline value takes a nested/folded value doctor cannot
    // evaluate plainly.
    expect(probeWith('---\nname:\n  innocent\n---\nhi\n').kind).toBe('unproven');
    // An indented FIRST entry re-anchors the YAML root mapping off column 0,
    // so "indented lines are nested" no longer holds.
    expect(probeWith('---\n  name: innocent\n---\nhi\n').kind).toBe('unproven');
    // A line that is no plain `key: value` entry is unparseable evidence.
    expect(probeWith('---\nname innocent\n---\nhi\n').kind).toBe('unproven');
    // ANY unprovable sibling entry taints the block — a quoted value can open
    // a context that swallows later lines.
    expect(probeWith('---\nname: innocent\nextra: "q"\n---\nhi\n').kind).toBe('unproven');
    // Plain unquoted ASCII frontmatter — nested blocks under a column-0 key
    // included — still clears: custom hooks must not tax the verdict.
    expect(probeWith('---\nname: my-hook\ndescription: does something useful\nmetadata:\n  openclaw:\n    emoji: brain\n---\nbody\n').kind).toBe('none');
    // No frontmatter block at all: the hook keeps its dir name.
    expect(probeWith('# just a readme\n').kind).toBe('none');
  });

  it('host contract: escaped YAML frontmatter in a workspace hook defeats pristine artifacts (SOL r5 B2)', async () => {
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: { defaults: { memorySearch: { enabled: false } } },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const dir = path.join(tmpHome, '.openclaw', 'workspace', 'hooks', 'helper');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'HOOK.md'), '---\n"\\u006eame": "\\u0063ortex-memory"\n---\nnot the pack\n');
    fs.writeFileSync(path.join(dir, 'handler.ts'), 'export default async () => {};\n');
    const verdict = await runHost();
    expect(verdict.status).toBe('warn');
    expect(verdict.message).toMatch(/SC pack delivery unknown/);
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

  /** Claude Code's project-key encoding: cwd with non-alphanumerics as '-'. */
  function claudeProjectKey(projectRoot: string): string {
    return projectRoot.replace(/[^A-Za-z0-9]/g, '-');
  }

  it('host contract: a live CLAUDE.md at the REAL project root is native ON — decoded from the projects key (SOL r3 B4)', async () => {
    // The r3 false PASS: doctor probed ~/.claude/projects/<key>/CLAUDE.md — a
    // location Claude never loads — found nothing, and certified off_proven
    // while the real <root>/CLAUDE.md rode into every session.
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    const projectRoot = path.join(tmpHome, 'proj');
    fs.mkdirSync(projectRoot, { recursive: true });
    fs.mkdirSync(path.join(claudeDir, 'projects', claudeProjectKey(projectRoot)), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, 'CLAUDE.md'), '# project preamble\n'.repeat(20));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/Claude Code: native ON/);
    expect(r.message).toMatch(/proj\/CLAUDE\.md/);

    // <root>/.claude/CLAUDE.md is the same automatic surface.
    fs.rmSync(path.join(projectRoot, 'CLAUDE.md'));
    fs.mkdirSync(path.join(projectRoot, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(projectRoot, '.claude', 'CLAUDE.md'), '# nested preamble\n'.repeat(20));
    const nested = await runHost();
    expect(nested.status).toBe('fail');
    expect(nested.message).toMatch(/Claude Code: native ON/);
  });

  it('host contract: a CLAUDE.md inside the key dir itself is inert, and an undecodable key is an attestation gap, never off_proven (SOL r3 B4)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    // The old (wrong) location: projects/<key>/CLAUDE.md. Claude never loads
    // it, so it is transcript-dir clutter, not native evidence — the box still
    // PASSes on a real off-proof.
    const projectRoot = path.join(tmpHome, 'proj');
    fs.mkdirSync(projectRoot, { recursive: true });
    const keyDir = path.join(claudeDir, 'projects', claudeProjectKey(projectRoot));
    fs.mkdirSync(keyDir, { recursive: true });
    fs.writeFileSync(path.join(keyDir, 'CLAUDE.md'), '# clutter, not a preamble\n');
    const inert = await runHost();
    expect(inert.status).toBe('pass');

    // A key doctor cannot decode back to a real root caps the proof at
    // unknown with honest wording — never silence, never off_proven.
    fs.mkdirSync(path.join(claudeDir, 'projects', 'proj'), { recursive: true });
    const gap = await runHost();
    expect(gap.status).toBe('warn');
    expect(gap.message).toMatch(/cannot determine/);
    expect(gap.message).toMatch(/cannot be fully decoded/);

    // A key whose project was deleted decodes to zero roots on a complete
    // walk: nothing exists for Claude to load, so it does not block the proof.
    fs.rmSync(path.join(claudeDir, 'projects', 'proj'), { recursive: true, force: true });
    fs.mkdirSync(path.join(claudeDir, 'projects', claudeProjectKey(path.join(tmpHome, 'gone'))), { recursive: true });
    const gone = await runHost();
    expect(gone.status).toBe('pass');
  });

  it('decodeClaudeProjectKey walks the real tree: hyphenated names decode, ambiguity yields every candidate root (SOL r3 B4)', async () => {
    const mod = await import('../doctor.js');
    // Hyphens in real directory names survive the lossy encoding.
    const hyphenated = path.join(tmpHome, 'worktrees', 'sc-393-host');
    fs.mkdirSync(hyphenated, { recursive: true });
    const decoded = mod.decodeClaudeProjectKey(claudeProjectKey(hyphenated));
    expect(decoded.complete).toBe(true);
    expect(decoded.roots).toContain(hyphenated);
    // Ambiguity: /base/my-app and /base/my/app encode identically — both are
    // candidate roots and both get probed.
    fs.mkdirSync(path.join(tmpHome, 'my-app'), { recursive: true });
    fs.mkdirSync(path.join(tmpHome, 'my', 'app'), { recursive: true });
    const ambiguous = mod.decodeClaudeProjectKey(claudeProjectKey(path.join(tmpHome, 'my-app')));
    expect(ambiguous.complete).toBe(true);
    expect(ambiguous.roots).toEqual(expect.arrayContaining([
      path.join(tmpHome, 'my-app'),
      path.join(tmpHome, 'my', 'app'),
    ]));
    // A key that is not an absolute-path encoding cannot be attested.
    expect(mod.decodeClaudeProjectKey('proj')).toEqual({ roots: [], complete: false });
  });

  it('host contract: a live ANCESTOR CLAUDE.md defeats a clean nested project (SOL r4 B1)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    // The r4 false PASS: the recorded project is a NESTED directory with
    // clean leaf files, while an ancestor CLAUDE.md still rides into every
    // session Claude starts there.
    const nested = path.join(tmpHome, 'repos', 'app', 'packages', 'web');
    fs.mkdirSync(nested, { recursive: true });
    fs.mkdirSync(path.join(claudeDir, 'projects', claudeProjectKey(nested)), { recursive: true });
    fs.writeFileSync(path.join(tmpHome, 'repos', 'app', 'CLAUDE.md'), '# monorepo preamble\n'.repeat(10));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/Claude Code: native ON/);
    expect(r.message).toMatch(/app\/CLAUDE\.md/);

    // Ancestor evidence doctor cannot read caps at unknown, never off_proven
    // (a FILE where .claude should be a directory probes as ENOTDIR).
    fs.rmSync(path.join(tmpHome, 'repos', 'app', 'CLAUDE.md'));
    fs.writeFileSync(path.join(tmpHome, 'repos', '.claude'), 'not a dir');
    const unreadable = await runHost();
    expect(unreadable.status).toBe('warn');
    expect(unreadable.message).toMatch(/unreadable/);
  });

  it('host contract: an ancestor walk the cap truncates is an incomplete scan, never off_proven (SOL r4 B1)', async () => {
    writeConfig(busContract());
    const claudeDir = path.join(tmpHome, '.claude');
    fs.mkdirSync(claudeDir, { recursive: true });
    fs.writeFileSync(
      path.join(claudeDir, 'settings.json'),
      JSON.stringify({
        hooks: { SessionStart: [{ hooks: [{ type: 'command', command: trustedShieldcortexCommand() }] }] },
      }),
    );
    // 12 nesting levels: the bounded walk stops before reaching $HOME, so a
    // preamble could sit above the truncation point — that is an attestation
    // gap, not silence.
    const deep = path.join(tmpHome, ...Array.from({ length: 12 }, (_, i) => `d${i}`));
    fs.mkdirSync(deep, { recursive: true });
    fs.mkdirSync(path.join(claudeDir, 'projects', claudeProjectKey(deep)), { recursive: true });
    const r = await runHost();
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/scan could not complete/);
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

  it('host contract probes IMPLICIT per-agent workspaces — a workspace-<agentId> brain cannot ride defaults-off to PASS (SOL r3 B3)', async () => {
    // The r3 false PASS: agent "case" has no explicit workspace, so OpenClaw
    // resolves <stateDir>/workspace-case (agent-scope.ts) and bootstraps a
    // live MEMORY.md there — while doctor only probed the stock and explicit
    // workspaces and certified green.
    writeConfig(busContract());
    installRealHookArtifacts();
    fs.writeFileSync(
      path.join(tmpHome, '.openclaw', 'openclaw.json'),
      JSON.stringify({
        agents: {
          defaults: { memorySearch: { enabled: false } },
          list: [{ id: 'main', default: true }, { id: 'case' }],
        },
        hooks: { internal: { enabled: true } },
      }, null, 2),
    );
    const implicitWs = path.join(tmpHome, '.openclaw', 'workspace-case');
    fs.mkdirSync(implicitWs, { recursive: true });
    fs.writeFileSync(path.join(implicitWs, 'MEMORY.md'), '# implicit brain\n'.repeat(5));
    const r = await runHost();
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/workspace-case\/MEMORY\.md/);
  });

  it('host contract follows the legacy state-dir fallback — a .clawdbot workspace-<agentId> brain cannot hide behind an absent ~/.openclaw (SOL r7)', async () => {
    // The exact r7 false PASS: absolute OPENCLAW_CONFIG_PATH with
    // memorySearch off, disable_native_inject + turn mode (no start-pack
    // proof required), ~/.openclaw ABSENT, and a live
    // ~/.clawdbot/workspace-case/MEMORY.md. OpenClaw's resolveStateDir falls
    // back to .clawdbot when .openclaw is missing (config/paths.ts), resolves
    // agent "case" to <stateDir>/workspace-case (agent-scope.ts), and
    // bootstraps that brain — while a doctor pinned to ~/.openclaw scanned an
    // empty universe and certified native off.
    writeConfig({
      ...busContract(),
      memory: {
        ...(busContract().memory as Record<string, unknown>),
        inject: { mode: 'turn', nativeContract: 'disable_native_inject' },
      },
    });
    const cfgPath = path.join(tmpHome, 'oc-config', 'openclaw.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    fs.writeFileSync(cfgPath, JSON.stringify({
      agents: {
        defaults: { memorySearch: { enabled: false } },
        list: [{ id: 'main', default: true }, { id: 'case' }],
      },
    }, null, 2));
    process.env.OPENCLAW_CONFIG_PATH = cfgPath;
    // No ~/.openclaw at all — only the legacy state dir exists.
    fs.rmSync(path.join(tmpHome, '.openclaw'), { recursive: true, force: true });
    const legacyWs = path.join(tmpHome, '.clawdbot', 'workspace-case');
    fs.mkdirSync(legacyWs, { recursive: true });
    fs.writeFileSync(path.join(legacyWs, 'MEMORY.md'), '# legacy implicit brain\n'.repeat(5));
    const r = await runHost();
    expect(r.status).not.toBe('pass');
    expect(`${r.message} ${r.fix ?? ''}`).toMatch(/workspace-case\/MEMORY\.md|clawdbot/);
  });

  it('OPENCLAW_TEST_FAST=1 skips the legacy fallback exactly like the host — a decoy .clawdbot hook tree cannot be attested (SOL r8)', async () => {
    // The exact r8 false PASS: OPENCLAW_TEST_FAST=1 makes the host pin
    // ~/.openclaw (paths.ts resolveStateDir) even when it is absent; a doctor
    // still walking the legacy fallback would attest byte-current SC hook
    // artifacts in .clawdbot/hooks that the host never loads.
    writeConfig(busContract());
    const cfgPath = path.join(tmpHome, 'oc-config', 'openclaw.json');
    fs.mkdirSync(path.dirname(cfgPath), { recursive: true });
    fs.writeFileSync(cfgPath, JSON.stringify({
      agents: { defaults: { memorySearch: { enabled: false } } },
      hooks: { internal: { enabled: true } },
    }, null, 2));
    process.env.OPENCLAW_CONFIG_PATH = cfgPath;
    process.env.OPENCLAW_TEST_FAST = '1';
    try {
      fs.rmSync(path.join(tmpHome, '.openclaw'), { recursive: true, force: true });
      // Byte-current decoy artifacts live ONLY in the legacy tree.
      installRealHookArtifacts(path.join(tmpHome, '.clawdbot'));
      const r = await runHost();
      // Host uses absent ~/.openclaw: no SC hook exists there, so sc_only
      // must not PASS off the decoy legacy hook.
      expect(r.status).not.toBe('pass');
    } finally {
      delete process.env.OPENCLAW_TEST_FAST;
    }
  });

  it('openClawWorkspacePaths mirrors resolveAgentWorkspaceDir: default agent, id normalization, duplicates, explicit overrides (SOL r3 B3)', async () => {
    const mod = await import('../doctor.js');
    const cfg = (agents: Record<string, unknown>) =>
      ({ kind: 'present' as const, value: { agents } });
    const home = '/home/x';
    const root = '/srv/oc-state';

    // A single-entry list makes that agent the DEFAULT: its implicit
    // workspace is the home default, never workspace-<id>.
    const solo = mod.openClawWorkspacePaths(home, root, cfg({ list: [{ id: 'solo' }] }));
    expect(solo.paths).toContain('/home/x/.openclaw/workspace');
    expect(solo.paths).not.toContain('/srv/oc-state/workspace-solo');

    // Non-default agents without explicit workspaces resolve implicitly under
    // the state root, with host id normalization ("Case Agent!" -> case-agent).
    const multi = mod.openClawWorkspacePaths(home, root, cfg({
      list: [{ id: 'hermes', default: true }, { id: 'case' }, { id: 'Case Agent!' }],
    }));
    expect(multi.paths).toContain('/srv/oc-state/workspace-case');
    expect(multi.paths).toContain('/srv/oc-state/workspace-case-agent');
    expect(multi.paths).not.toContain('/srv/oc-state/workspace-hermes');

    // An explicit workspace suppresses the implicit one, and duplicate ids
    // resolve to the first entry (a second "case" with no workspace must not
    // resurrect workspace-case).
    const explicit = mod.openClawWorkspacePaths(home, root, cfg({
      list: [{ id: 'hermes', default: true }, { id: 'case', workspace: '/srv/agents/case-ws' }, { id: 'case' }],
    }));
    expect(explicit.paths).toContain('/srv/agents/case-ws');
    expect(explicit.paths).not.toContain('/srv/oc-state/workspace-case');

    // OPENCLAW_PROFILE relocates the home default (resolveDefaultAgentWorkspaceDir).
    process.env.OPENCLAW_PROFILE = 'tars';
    const profiled = mod.openClawWorkspacePaths(home, root, cfg({}));
    expect(profiled.paths).toContain('/home/x/.openclaw/workspace-tars');
    delete process.env.OPENCLAW_PROFILE;

    // The implicit set is bounded by the cap and overflow is never silent.
    const crowd = mod.openClawWorkspacePaths(home, root, cfg({
      list: [{ id: 'boss', default: true }, ...Array.from({ length: 30 }, (_, i) => ({ id: `agent-${i}` }))],
    }));
    expect(crowd.paths.length).toBeLessThanOrEqual(16);
    expect(crowd.complete).toBe(false);
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

  it('host contract passes a signed honest sidecar and rejects sidecar-plus-contract', async () => {
    writeHermes({ memoryEnabled: true, userProfile: true });
    const cloud = await import('../../cloud/config.js');
    cloud.setMemoryHostRuntimes(['hermes']);
    cloud.setMemoryHostPosture('mcp_sidecar_no_inject');
    const sidecar = await runHost();
    expect(sidecar.status).toBe('pass');
    expect(sidecar.message).toMatch(/honest sidecar/);

    writeSignedConfig({
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

  it('host contract rejects unsigned and forged sidecar posture declarations', async () => {
    writeHermes({ memoryEnabled: true, userProfile: true });
    const sidecar = {
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: 'mcp_sidecar_no_inject', runtimes: ['hermes'] },
        inject: { mode: 'off', hostId: 'tars', agentId: 'hermes-primary' },
      },
    };
    writeConfig(sidecar);
    const unsigned = await runHost();
    expect(unsigned.status).toBe('fail');
    expect(unsigned.message).toMatch(/untrusted/);
    expect(unsigned.message).not.toMatch(/honest sidecar/);

    writeConfig({ ...sidecar, _sig: 'forged' });
    const forged = await runHost();
    expect(forged.status).toBe('fail');
    expect(forged.message).toMatch(/untrusted/);
    expect(forged.message).not.toMatch(/honest sidecar/);
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

  it('host contract fails non-string posture values as illegal, mirroring runtime-declaration junk (SOL r3 nit)', async () => {
    // Before r3 these became posture=null and escaped the illegal-posture
    // failure entirely.
    for (const junk of [123, true, { posture: 'x' }, null]) {
      writeConfig({
        memory: { plane: 'dual_legacy', hostContract: { posture: junk }, inject: { mode: 'off' } },
      });
      const r = await runHost();
      expect(r.status).toBe('fail');
      expect(r.message).toMatch(/illegal memory\.hostContract\.posture/);
      expect(r.fix).toMatch(/--memory-host-posture/);
    }
    // The String()-coercion trap: a one-element array stringifies to the legal
    // posture and would otherwise mint an honest-sidecar PASS out of junk.
    writeHermes({ memoryEnabled: true, userProfile: true });
    writeConfig({
      memory: {
        plane: 'dual_legacy',
        hostContract: { posture: ['mcp_sidecar_no_inject'], runtimes: ['hermes'] },
        inject: { mode: 'off', hostId: 'tars', agentId: 'hermes-primary' },
      },
    });
    const arrayJunk = await runHost();
    expect(arrayJunk.status).toBe('fail');
    expect(arrayJunk.message).toMatch(/illegal memory\.hostContract\.posture/);
    expect(arrayJunk.message).not.toMatch(/honest sidecar/);
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

