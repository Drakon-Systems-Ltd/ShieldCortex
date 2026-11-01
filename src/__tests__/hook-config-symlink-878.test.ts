import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
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

function runInstalledHook(): { decision?: string; reason?: string; code: number; stderr: string } {
  const run = spawnSync('/bin/sh', ['-c', INSTALLED_COMMAND], {
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
        return { decision: out.permissionDecision, reason: out.permissionDecisionReason, code: run.status ?? -1, stderr: run.stderr ?? '' };
      }
    } catch { /* not the decision line */ }
  }
  return { code: run.status ?? -1, stderr: run.stderr ?? '' };
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
        const run = runInstalledHook();
        expect(run.decision).toBe('deny');
      });
    }
  }

  it('control: a regular unsigned Guard-off file is still honoured (no decision)', () => {
    writeFileSync(join(configDir, 'config.json'), JSON.stringify(GUARD_OFF));
    expect(runInstalledHook().decision).toBeUndefined();
  });

  it('control: a regular unsigned enforcing file still denies', () => {
    writeFileSync(join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
    expect(runInstalledHook().decision).toBe('deny');
  });

  it('dangling link: nothing to read, the same {} src reads (src: unreadable → defaults)', () => {
    symlinkSync(join(outside, 'missing.json'), join(configDir, 'config.json'));
    expect(runInstalledHook().decision).toBeUndefined();
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
});
