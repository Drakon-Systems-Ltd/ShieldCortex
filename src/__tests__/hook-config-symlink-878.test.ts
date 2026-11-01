import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { copyFileSync, lstatSync, mkdtempSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

/**
 * #878 B1 — the two non-src readers of `config.json` that decide the Action
 * Guard's posture must hold a symlinked `config.json` whose target is unsigned
 * at the same strict posture `readRawConfigState` does in src. Before this,
 * src reported strict while the Claude Code hook and the OpenClaw runtime took
 * `enabled:false` / `enforce:false` straight from the link's target.
 *
 * The hook is driven the way Claude Code drives it: `/bin/sh -c "<node>
 * dist/index.js hook pre-tool"`, which runs `scripts/pre-tool-hook.mjs`.
 * A unit test of src/cloud/config.ts would stay green and miss the split.
 */

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ROOT = join(repoRoot, 'dist');
const INSTALLED_COMMAND = `${process.execPath} ${join(DIST_ROOT, 'index.js')} hook pre-tool`;
/** Denied by an enabled, enforcing guard; allowed with no decision when the guard is off. */
const GATED = { command: 'sudo modprobe softdog' };

const GUARD_OFF = { actionGuard: { enabled: false } };
const WATCH_ONLY = { actionGuard: { enabled: true, enforce: false } };
// #509 readinessGate: strict deletes it, so a strict posture enforces at once.
const READINESS_GATED = { actionGuard: { enabled: true, enforce: true, readinessGate: true } };
// The deprecated alias spelling must not leak a loosening past the strict view.
const ALIAS_OFF = { interceptor: { actionGuard: { enabled: false, enforce: false } } };

// A genuinely signed body: the HMAC src/cloud/config.ts verifies (canonical
// body = the object without `_sig`, `JSON.stringify(rest, null, 2)`), keyed by
// the `.integrity-key` written beside config.json. Since r5 the hook and
// runtime recompute that HMAC for a link, as src does.
const FIXTURE_KEY = 'a'.repeat(64);
function signedBody(body: Record<string, unknown>): Record<string, unknown> {
  return { ...body, _sig: createHmac('sha256', FIXTURE_KEY).update(JSON.stringify(body, null, 2)).digest('hex') };
}
function writeIntegrityKey(): void {
  writeFileSync(join(configDir, '.integrity-key'), FIXTURE_KEY, { mode: 0o600 });
}

let home: string;
let configDir: string;
let outside: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-878-hook-link-'));
  configDir = join(home, '.shieldcortex');
  mkdirSync(configDir, { recursive: true });
  outside = join(home, 'elsewhere');
  mkdirSync(outside, { recursive: true });
});

afterEach(() => {
  rmSync(home, { recursive: true, force: true });
});

type Shape = 'relative' | 'absolute' | 'nested';

function linkTo(shape: Shape, body: Record<string, unknown>): void {
  const link = join(configDir, 'config.json');
  if (shape === 'relative') {
    writeFileSync(join(configDir, 'target.json'), JSON.stringify(body));
    symlinkSync('target.json', link);
  } else if (shape === 'absolute') {
    writeFileSync(join(outside, 'target.json'), JSON.stringify(body));
    symlinkSync(join(outside, 'target.json'), link);
  } else {
    writeFileSync(join(outside, 'target.json'), JSON.stringify(body));
    symlinkSync(join(outside, 'target.json'), join(configDir, 'mid.json'));
    symlinkSync('mid.json', link);
  }
}

function runInstalledHook(command = INSTALLED_COMMAND): { decision?: string; reason?: string; code: number; signal: string | null; stderr: string; error?: Error } {
  const run = spawnSync('/bin/sh', ['-c', command], {
    input: JSON.stringify({
      session_id: 'sc-878-hook-link',
      cwd: home,
      hook_event_name: 'PreToolUse',
      permission_mode: 'bypassPermissions',
      tool_name: 'Bash',
      tool_input: GATED,
    }),
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      SHIELDCORTEX_CONFIG_DIR: configDir,
      SHIELDCORTEX_DIST_ROOT: DIST_ROOT,
    },
    encoding: 'utf-8',
    timeout: 60_000,
  });
  for (const line of (run.stdout ?? '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const out = JSON.parse(trimmed)?.hookSpecificOutput;
      if (out?.hookEventName === 'PreToolUse') {
        return {
          decision: out.permissionDecision, reason: out.permissionDecisionReason,
          code: run.status ?? -1, signal: run.signal, stderr: run.stderr ?? '', error: run.error,
        };
      }
    } catch { /* not the decision line */ }
  }
  return { code: run.status ?? -1, signal: run.signal, stderr: run.stderr ?? '', error: run.error };
}

/**
 * N3: an absent decision must mean "allowed", not "the process failed". The
 * hook launched, ran to completion and exited 0 on every path here.
 */
function runHookOk(command?: string): ReturnType<typeof runInstalledHook> {
  const run = runInstalledHook(command);
  expect(run.error).toBeUndefined();
  expect(run.signal).toBeNull();
  expect({ code: run.code, stderr: run.stderr }).toMatchObject({ code: 0 });
  return run;
}

describe('#878 B1 — installed Claude Code hook, symlinked unsigned config.json', () => {
  const fixtures: Array<[string, Record<string, unknown>]> = [
    ['Guard off', GUARD_OFF],
    ['watch-only', WATCH_ONLY],
    ['readiness-gated', READINESS_GATED],
    ['alias Guard off', ALIAS_OFF],
  ];
  for (const shape of ['relative', 'absolute', 'nested'] as const) {
    for (const [name, body] of fixtures) {
      it(`${shape} link to unsigned ${name}: denied (strict), not allowed as off`, () => {
        linkTo(shape, body);
        const run = runHookOk();
        expect(run.decision).toBe('deny');
      });
    }
  }

  it('control: a regular unsigned Guard-off file is still honoured (no decision)', () => {
    writeFileSync(join(configDir, 'config.json'), JSON.stringify(GUARD_OFF));
    expect(runHookOk().decision).toBeUndefined();
  });

  it('control: a regular unsigned enforcing file still denies', () => {
    writeFileSync(join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
    expect(runHookOk().decision).toBe('deny');
  });

  it('dangling link: nothing to read, the same {} src reads (src: unreadable → defaults)', () => {
    symlinkSync(join(outside, 'missing.json'), join(configDir, 'config.json'));
    expect(runHookOk().decision).toBeUndefined();
  });

  for (const shape of ['relative', 'absolute', 'nested'] as const) {
    it(`control (N3): ${shape} link to a SIGNED Guard-off target is honoured (no decision), not held strict`, () => {
      writeIntegrityKey();
      linkTo(shape, signedBody(GUARD_OFF));
      expect(runHookOk().decision).toBeUndefined();
    });
  }

  it('control (N3): link to a legacy-signed target (.config-sig beside the link) is honoured', () => {
    writeIntegrityKey();
    linkTo('relative', GUARD_OFF);
    const bytes = JSON.stringify(GUARD_OFF);
    writeFileSync(join(configDir, '.config-sig'), createHmac('sha256', FIXTURE_KEY).update(bytes).digest('hex'), { mode: 0o600 });
    expect(runHookOk().decision).toBeUndefined();
  });
});

type Runtime = { loadShieldConfig: () => Promise<Record<string, any>> };

async function runtimeFor(configPath: string): Promise<Runtime> {
  const mod = await import('../../hooks/openclaw/cortex-memory/runtime.mjs') as {
    createOpenClawRuntime: (opts?: { configPath?: string }) => Runtime;
  };
  return mod.createOpenClawRuntime({ configPath });
}

describe('#878 B1 — OpenClaw runtime loadShieldConfig, symlinked unsigned config.json', () => {
  for (const shape of ['relative', 'absolute', 'nested'] as const) {
    for (const [name, body] of [['Guard off', GUARD_OFF], ['watch-only', WATCH_ONLY], ['readiness-gated', READINESS_GATED]] as const) {
      it(`${shape} link to unsigned ${name}: strict posture, readinessGate dropped`, async () => {
        linkTo(shape, body as Record<string, unknown>);
        const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
        expect(cfg.actionGuard).toMatchObject({ enabled: true, enforce: true, autoApprove: [], reviewedScripts: [] });
        expect(cfg.actionGuard.broker).toEqual({ enabled: false });
        expect(cfg.actionGuard).not.toHaveProperty('readinessGate');
        expect(cfg.defenceMode).toBe('strict');
      });
    }
  }

  it('alias spelling: the covered keys are stripped from interceptor.actionGuard', async () => {
    linkTo('relative', ALIAS_OFF);
    const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
    expect(cfg.actionGuard).toMatchObject({ enabled: true, enforce: true });
    expect(cfg.interceptor.actionGuard).toEqual({});
  });

  it('identity is stable across calls (the plugin re-merges on identity change)', async () => {
    linkTo('relative', GUARD_OFF);
    const runtime = await runtimeFor(join(configDir, 'config.json'));
    const first = await runtime.loadShieldConfig();
    expect(await runtime.loadShieldConfig()).toBe(first);
  });

  it('control: a regular unsigned Guard-off file is the file\'s own value', async () => {
    writeFileSync(join(configDir, 'config.json'), JSON.stringify(GUARD_OFF));
    const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
    expect(cfg).toEqual(GUARD_OFF);
  });

  it('link to an empty file: {} — src reads empty bytes as absent', async () => {
    writeFileSync(join(configDir, 'target.json'), '');
    symlinkSync('target.json', join(configDir, 'config.json'));
    const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
    expect(cfg).toEqual({});
  });

  it('dangling link: {} — the same defaults src reads for an unreadable file', async () => {
    symlinkSync(join(outside, 'missing.json'), join(configDir, 'config.json'));
    const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
    expect(cfg).toEqual({});
  });

  it('control (N3): link to a SIGNED Guard-off target is the target\'s own value', async () => {
    writeIntegrityKey();
    linkTo('relative', signedBody(GUARD_OFF));
    const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
    expect(cfg.actionGuard).toEqual({ enabled: false });
    expect(cfg.defenceMode).toBeUndefined();
  });
});

/**
 * #878 r4 B1-R4 — a WARM runtime. The cache used to be keyed on the target's
 * mtime alone, so replacing config.json with an unsigned link whose target
 * carries the same mtime kept serving the old parsed object, and the
 * unsigned-link check judged the OLD bytes: Guard off while a fresh runtime
 * and src were strict. Every transition here pins the mtime equal by
 * assertion, so only the identity key can see the change.
 */
describe('#878 r4 — warm OpenClaw runtime: same-mtime swaps re-read before the link verdict', () => {
  const configPath = () => join(configDir, 'config.json');
  // Whole seconds: a utimes round trip is exact, so "same mtime" holds bit for
  // bit (a Date carries ms and loses the sub-ms part). Every fixture is pinned
  // BEFORE the warm runtime's first read, so the old mtime key cannot see a change.
  const PINNED = 1_767_225_600;
  const pin = (file: string): void => utimesSync(file, PINNED, PINNED);

  /** The unsigned Guard-off target the swap lands on, at the pinned mtime. */
  function unsignedTarget(name = 'unsigned-new.json'): string {
    const target = join(outside, name);
    writeFileSync(target, JSON.stringify(GUARD_OFF));
    pin(target);
    return target;
  }

  function expectStrict(cfg: Record<string, any>): void {
    expect(cfg.actionGuard).toMatchObject({ enabled: true, enforce: true, autoApprove: [], reviewedScripts: [] });
    expect(cfg.actionGuard.broker).toEqual({ enabled: false });
    expect(cfg.actionGuard).not.toHaveProperty('readinessGate');
    expect(cfg.defenceMode).toBe('strict');
  }

  /** Move the regular config.json aside and link an unsigned target in, same mtime. */
  async function swapRegularForUnsignedLink(runtime: Runtime): Promise<Record<string, any>> {
    expect(statSync(configPath()).mtimeMs).toBe(PINNED * 1000);
    renameSync(configPath(), join(configDir, 'config.json.aside'));
    symlinkSync(unsignedTarget(), configPath());
    expect(lstatSync(configPath()).isSymbolicLink()).toBe(true);
    expect(statSync(configPath()).mtimeMs).toBe(PINNED * 1000);
    return runtime.loadShieldConfig();
  }

  it('signed regular → unsigned link (same mtime): strict, and stays strict on the next warm read', async () => {
    writeIntegrityKey();
    writeFileSync(configPath(), JSON.stringify(signedBody(GUARD_OFF)));
    pin(configPath());
    const runtime = await runtimeFor(configPath());
    const first = await runtime.loadShieldConfig();
    expect(first.actionGuard).toEqual({ enabled: false });

    const after = await swapRegularForUnsignedLink(runtime);
    expect(after).not.toBe(first);
    expectStrict(after);
    // Fresh-runtime parity: the warm answer is the one a cold start gives.
    expect(after).toEqual(await (await runtimeFor(configPath())).loadShieldConfig());
    expect(await runtime.loadShieldConfig()).toBe(after);
  });

  for (const [name, bytes] of [['empty', ''], ['malformed', '{not json'], ['array', '[]']] as const) {
    it(`failed/non-object parse (${name} regular) → valid unsigned link (same mtime): strict`, async () => {
      writeFileSync(configPath(), bytes);
      pin(configPath());
      const runtime = await runtimeFor(configPath());
      const first = await runtime.loadShieldConfig();
      expect(first?.actionGuard).toBeUndefined();

      expectStrict(await swapRegularForUnsignedLink(runtime));
    });
  }

  it('already-linked retarget: signed link → unsigned target (same mtime): strict', async () => {
    writeIntegrityKey();
    writeFileSync(join(outside, 'signed.json'), JSON.stringify(signedBody(GUARD_OFF)));
    pin(join(outside, 'signed.json'));
    symlinkSync(join(outside, 'signed.json'), configPath());
    const runtime = await runtimeFor(configPath());
    const first = await runtime.loadShieldConfig();
    expect(first.actionGuard).toEqual({ enabled: false });

    const target = unsignedTarget();
    rmSync(configPath());
    symlinkSync(target, configPath());
    expect(statSync(configPath()).mtimeMs).toBe(PINNED * 1000);
    expectStrict(await runtime.loadShieldConfig());
  });

  it('control: unsigned link → retarget to a signed target (same mtime): honoured again, not stuck strict', async () => {
    writeIntegrityKey();
    symlinkSync(unsignedTarget('unsigned.json'), configPath());
    const runtime = await runtimeFor(configPath());
    expectStrict(await runtime.loadShieldConfig());

    const signedTarget = join(outside, 'signed.json');
    writeFileSync(signedTarget, JSON.stringify(signedBody(GUARD_OFF)));
    pin(signedTarget);
    rmSync(configPath());
    symlinkSync(signedTarget, configPath());
    const cfg = await runtime.loadShieldConfig();
    expect(cfg.actionGuard).toEqual({ enabled: false });
    expect(cfg.defenceMode).toBeUndefined();
  });

  it('in-place same-mtime rewrite of a linked target (signed → unsigned bytes): strict', async () => {
    writeIntegrityKey();
    const target = join(outside, 'target.json');
    writeFileSync(target, JSON.stringify(signedBody(GUARD_OFF)));
    pin(target);
    symlinkSync(target, configPath());
    const runtime = await runtimeFor(configPath());
    expect((await runtime.loadShieldConfig()).actionGuard).toEqual({ enabled: false });

    writeFileSync(target, JSON.stringify(GUARD_OFF));
    pin(target);
    expect(statSync(target).mtimeMs).toBe(PINNED * 1000);
    expectStrict(await runtime.loadShieldConfig());
  });
});

/**
 * #878 r4 N2 — the synthetic canary's interceptor config. Built with the
 * posture the runtime holds: an unsigned linked config.json is strict, a
 * signed linked one and a regular one are their own values.
 */
describe('#878 r4 N2 — resolveBoxInterceptorConfig, symlinked config.json', () => {
  const DEFAULTS = { enabled: true, actionGuard: { enabled: false, enforce: true, autoApprove: [] } };
  async function resolve(): Promise<Record<string, any>> {
    const { resolveBoxInterceptorConfig } = await import('../setup/openclaw-selfcheck.js');
    return resolveBoxInterceptorConfig(home, DEFAULTS) as Record<string, any>;
  }

  it('unsigned link with the alias set off: enabled + enforcing, no auto-approve', async () => {
    linkTo('relative', ALIAS_OFF);
    const cfg = await resolve();
    expect(cfg.actionGuard).toMatchObject({ enabled: true, enforce: true, autoApprove: [], reviewedScripts: [] });
    expect(cfg.actionGuard.broker).toEqual({ enabled: false });
  });

  it('unsigned link with no interceptor block at all: still strict, not the bare defaults', async () => {
    linkTo('absolute', GUARD_OFF);
    expect((await resolve()).actionGuard).toMatchObject({ enabled: true, enforce: true });
  });

  it('control: signed link with the alias set off is honoured', async () => {
    writeIntegrityKey();
    linkTo('relative', signedBody(ALIAS_OFF));
    expect((await resolve()).actionGuard).toMatchObject({ enabled: false, enforce: false });
  });

  it('control: a regular unsigned file with the alias set off is honoured', async () => {
    writeFileSync(join(configDir, 'config.json'), JSON.stringify(ALIAS_OFF));
    expect((await resolve()).actionGuard).toMatchObject({ enabled: false, enforce: false });
  });
});

/**
 * #878 r5 B1 — presence is not a signature. The hook and the runtime used to
 * honour a symlinked config.json whenever its target carried ANY `_sig` string
 * or a `.config-sig` file merely existed beside it (empty, junk, a directory),
 * while src recomputed the HMAC, found it `tampered` and held strict. All
 * three non-src readers now go through one verifier
 * (scripts/lib/config-authenticity.mjs; runtime.mjs carries a pinned copy)
 * that recomputes the HMAC as checkConfigIntegrity does. Every fixture writes
 * a real `.integrity-key` unless the row is about a missing one, so the deny
 * is the signature failing, not the key being absent.
 */
describe('#878 r5 B1 — symlinked config.json: only a verifying signature is honoured', () => {
  const OFF_BOTH = { actionGuard: { enabled: false }, interceptor: { actionGuard: { enabled: false, enforce: false } } };
  const hmac = (s: string) => createHmac('sha256', FIXTURE_KEY).update(s).digest('hex');
  const sidecar = (content: string) => writeFileSync(join(configDir, '.config-sig'), content, { mode: 0o600 });
  const linkRaw = (body: Record<string, unknown>) => linkTo('relative', body);

  type Row = { name: string; plant: () => void; src: 'tampered' | 'unverified' | 'valid' | 'self-heal'; shared: string };
  const BAD: Row[] = [
    { name: 'empty `_sig` string', plant: () => { writeIntegrityKey(); linkRaw({ ...OFF_BOTH, _sig: '' }); }, src: 'tampered', shared: 'tampered' },
    { name: 'junk `_sig` string', plant: () => { writeIntegrityKey(); linkRaw({ ...OFF_BOTH, _sig: 'deadbeef' }); }, src: 'tampered', shared: 'tampered' },
    { name: 'forged 64-hex `_sig`', plant: () => { writeIntegrityKey(); linkRaw({ ...OFF_BOTH, _sig: 'f'.repeat(64) }); }, src: 'tampered', shared: 'tampered' },
    {
      name: 'genuine `_sig` lifted from a different (enforcing) body',
      plant: () => { writeIntegrityKey(); linkRaw({ ...OFF_BOTH, _sig: signedBody({ actionGuard: { enabled: true, enforce: true } })._sig }); },
      src: 'tampered', shared: 'tampered',
    },
    { name: 'empty `.config-sig`', plant: () => { writeIntegrityKey(); linkRaw(OFF_BOTH); sidecar(''); }, src: 'tampered', shared: 'tampered' },
    { name: 'junk `.config-sig`', plant: () => { writeIntegrityKey(); linkRaw(OFF_BOTH); sidecar('00'); }, src: 'tampered', shared: 'tampered' },
    {
      name: '`.config-sig` is a directory',
      plant: () => { writeIntegrityKey(); linkRaw(OFF_BOTH); mkdirSync(join(configDir, '.config-sig')); },
      src: 'tampered', shared: 'tampered',
    },
    {
      name: 'junk `_sig` + empty `.config-sig` (no self-heal from an empty sidecar)',
      plant: () => { writeIntegrityKey(); linkRaw({ ...OFF_BOTH, _sig: 'x' }); sidecar(''); },
      src: 'tampered', shared: 'tampered',
    },
    { name: 'numeric `_sig` (not a string: legacy scheme, no sidecar)', plant: () => { writeIntegrityKey(); linkRaw({ ...OFF_BOTH, _sig: 1 }); }, src: 'unverified', shared: 'unsigned' },
    { name: 'genuine `_sig` but no `.integrity-key` to verify it with', plant: () => { linkRaw(signedBody(OFF_BOTH)); }, src: 'tampered', shared: 'tampered' },
  ];
  const GOOD: Row[] = [
    { name: 'genuine embedded `_sig`', plant: () => { writeIntegrityKey(); linkRaw(signedBody(OFF_BOTH)); }, src: 'valid', shared: 'valid' },
    {
      name: 'genuine legacy `.config-sig` over the exact bytes',
      plant: () => { writeIntegrityKey(); linkRaw(OFF_BOTH); sidecar(hmac(JSON.stringify(OFF_BOTH))); },
      src: 'valid', shared: 'valid',
    },
    {
      name: 'self-heal: stale `_sig`, genuine legacy `.config-sig` over the exact bytes',
      plant: () => {
        writeIntegrityKey();
        const body = { ...OFF_BOTH, _sig: 'deadbeef' };
        linkRaw(body);
        sidecar(hmac(JSON.stringify(body)));
      },
      src: 'self-heal', shared: 'self-heal',
    },
  ];

  describe('installed Claude Code hook (/bin/sh -c "<node> dist/index.js hook pre-tool")', () => {
    for (const row of BAD) {
      it(`${row.name}: denied (strict), not allowed as Guard off`, () => {
        row.plant();
        expect(runHookOk().decision).toBe('deny');
      });
    }
    for (const row of GOOD) {
      it(`control: ${row.name}: honoured (no decision)`, () => {
        row.plant();
        expect(runHookOk().decision).toBeUndefined();
      });
    }
  });

  describe('OpenClaw runtime loadShieldConfig', () => {
    for (const row of BAD) {
      it(`${row.name}: strict posture`, async () => {
        row.plant();
        const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
        expect(cfg.actionGuard).toMatchObject({ enabled: true, enforce: true, autoApprove: [], reviewedScripts: [] });
        expect(cfg.defenceMode).toBe('strict');
        expect(cfg.interceptor.actionGuard).toEqual({});
      });
    }
    for (const row of GOOD) {
      it(`control: ${row.name}: the target's own value`, async () => {
        row.plant();
        const cfg = await (await runtimeFor(join(configDir, 'config.json'))).loadShieldConfig();
        expect(cfg.actionGuard).toEqual({ enabled: false });
        expect(cfg.defenceMode).toBeUndefined();
      });
    }

    it('a warm runtime re-verifies when only a sidecar changes: genuine legacy sig → junk sig is strict', async () => {
      writeIntegrityKey();
      linkRaw(OFF_BOTH);
      sidecar(hmac(JSON.stringify(OFF_BOTH)));
      const runtime = await runtimeFor(join(configDir, 'config.json'));
      expect((await runtime.loadShieldConfig()).actionGuard).toEqual({ enabled: false });
      sidecar('00');
      expect((await runtime.loadShieldConfig()).actionGuard).toMatchObject({ enabled: true, enforce: true });
    });
  });

  describe('resolveBoxInterceptorConfig (the synthetic canary)', () => {
    const DEFAULTS = { enabled: true, actionGuard: { enabled: false, enforce: true, autoApprove: [] } };
    const resolveBox = async () => {
      const { resolveBoxInterceptorConfig } = await import('../setup/openclaw-selfcheck.js');
      return resolveBoxInterceptorConfig(home, DEFAULTS) as Record<string, any>;
    };
    for (const row of BAD) {
      it(`${row.name}: enabled + enforcing`, async () => {
        row.plant();
        expect((await resolveBox()).actionGuard).toMatchObject({ enabled: true, enforce: true, autoApprove: [] });
      });
    }
    for (const row of GOOD) {
      it(`control: ${row.name}: the alias's own Guard-off values`, async () => {
        row.plant();
        expect((await resolveBox()).actionGuard).toMatchObject({ enabled: false, enforce: false });
      });
    }
  });

  describe('one check: the shared verifier gives src checkConfigIntegrity\'s verdict', () => {
    for (const row of [...BAD, ...GOOD]) {
      it(`${row.name}: src ${row.src}, shared verifier ${row.shared}`, async () => {
        row.plant();
        const { inspectConfigIntegrity } = await import('../cloud/config.js');
        const { configSignatureVerdictAt } = await import('../../scripts/lib/config-authenticity.mjs');
        const prev = process.env.SHIELDCORTEX_CONFIG_DIR;
        process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
        let report;
        try {
          report = inspectConfigIntegrity();
        } finally {
          if (prev === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
          else process.env.SHIELDCORTEX_CONFIG_DIR = prev;
        }
        expect({ verdict: report.verdict, linked: report.linked }).toEqual({ verdict: row.src, linked: true });
        const configPath = join(configDir, 'config.json');
        const raw = readFileSync(configPath, 'utf-8');
        expect(configSignatureVerdictAt(configPath, JSON.parse(raw), raw)).toBe(row.shared);
      });
    }
  });

  it('fail strict: a hook copy without the verifier module holds even a GENUINELY signed link strict', () => {
    // The verifier is imported lazily, only for a link; a missing module must
    // neither crash the hook (fail open) nor honour an unverifiable link.
    const copy = join(home, 'hook-copy', 'scripts');
    mkdirSync(join(copy, 'lib'), { recursive: true });
    copyFileSync(join(repoRoot, 'scripts', 'pre-tool-hook.mjs'), join(copy, 'pre-tool-hook.mjs'));
    for (const dep of ['state-perms.mjs', 'harness-pid.mjs']) copyFileSync(join(repoRoot, 'scripts', 'lib', dep), join(copy, 'lib', dep));
    writeIntegrityKey();
    linkRaw(signedBody(OFF_BOTH));
    const command = `${process.execPath} ${join(copy, 'pre-tool-hook.mjs')}`;
    const run = runHookOk(command);
    expect(run.decision).toBe('deny');
    expect(run.stderr).toMatch(/signature verifier could not be loaded/);
    // Control: the same fixture through the real install is honoured.
    expect(runHookOk().decision).toBeUndefined();
  });

  it('the runtime\'s pinned verifier is byte-identical to scripts/lib/config-authenticity.mjs', () => {
    const region = (file: string) => {
      const text = readFileSync(join(repoRoot, file), 'utf-8');
      const begin = text.indexOf('// BEGIN config-signature-verdict');
      const end = text.indexOf('// END config-signature-verdict');
      expect(begin).toBeGreaterThanOrEqual(0);
      expect(end).toBeGreaterThan(begin);
      return text.slice(begin, end);
    };
    expect(region('hooks/openclaw/cortex-memory/runtime.mjs')).toBe(region('scripts/lib/config-authenticity.mjs'));
  });
});
