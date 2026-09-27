import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach } from '@jest/globals';
import plugin, { __resetConfigStateForTest } from '../index.js';

/**
 * #602 — OpenClaw 2026.9.6 runs register() in cli-metadata (and setup-only)
 * to collect commands. api.runtime is a getter that throws on purpose.
 * That must not look like a dead plugin, and it must not latch _registered
 * so a later full register in the same process still attaches hooks.
 */

const HOST_METADATA_UNAVAILABLE =
  'Plugin "shieldcortex-realtime" runtime is intentionally unavailable during "cli-metadata" registration. Declare root commands in the manifest\'s cliCommands or defer runtime access out of register().';

const HOST_SETUP_UNAVAILABLE =
  'Plugin "shieldcortex-realtime" runtime is intentionally unavailable during "setup-only" registration. Declare root commands in the manifest\'s cliCommands or defer runtime access out of register().';

type Hooks = Record<string, (...args: unknown[]) => unknown>;

function makeApi(opts: {
  loadMode?: string;
  mode?: string;
  registrationMode?: string;
  runtimeThrows?: string;
  configThrows?: string;
}): { api: Record<string, unknown>; hooks: Hooks; log: string[] } {
  const hooks: Hooks = {};
  const log: string[] = [];
  const runtime: Record<string, unknown> = opts.configThrows
    ? { config: { current: () => { throw new Error(opts.configThrows); } } }
    : { config: { current: () => ({}) } };

  const api: Record<string, unknown> = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: {
      info: (m: string) => { log.push(`info: ${m}`); },
      warn: (m: string) => { log.push(`warn: ${m}`); },
    },
    on: (name: string, handler: (...args: unknown[]) => unknown) => { hooks[name] = handler; },
    registerCommand: () => {},
  };
  if (opts.loadMode !== undefined) api.loadMode = opts.loadMode;
  if (opts.mode !== undefined) api.mode = opts.mode;
  if (opts.registrationMode !== undefined) api.registrationMode = opts.registrationMode;

  if (opts.runtimeThrows) {
    const message = opts.runtimeThrows;
    Object.defineProperty(api, 'runtime', {
      enumerable: true,
      configurable: true,
      get() {
        throw new Error(message);
      },
    });
  } else {
    api.runtime = runtime;
  }

  return { api, hooks, log };
}

beforeEach(() => {
  __resetConfigStateForTest();
});

describe('#602 cli-metadata register is not a dead plugin', () => {
  it('cli-metadata + throwing runtime getter: no throw, no warn, no before_tool_call', () => {
    const { api, hooks, log } = makeApi({
      loadMode: 'cli-metadata',
      runtimeThrows: HOST_METADATA_UNAVAILABLE,
    });
    expect(() => plugin.register(api as any)).not.toThrow();
    expect(log.some((m) => m.startsWith('warn:'))).toBe(false);
    expect(hooks.before_tool_call).toBeUndefined();
  });

  it('setup-only + throwing runtime getter: same quiet path', () => {
    const { api, hooks, log } = makeApi({
      loadMode: 'setup-only',
      runtimeThrows: HOST_SETUP_UNAVAILABLE,
    });
    expect(() => plugin.register(api as any)).not.toThrow();
    expect(log.some((m) => m.startsWith('warn:'))).toBe(false);
    expect(hooks.before_tool_call).toBeUndefined();
  });

  it('omitted loadMode still quiets the host metadata-unavailable throw', () => {
    const { api, hooks, log } = makeApi({
      runtimeThrows: HOST_METADATA_UNAVAILABLE,
    });
    expect(() => plugin.register(api as any)).not.toThrow();
    expect(log.some((m) => m.startsWith('warn:'))).toBe(false);
    expect(hooks.before_tool_call).toBeUndefined();
  });

  it('full mode still attaches before_tool_call and does not report init failure', () => {
    const { api, hooks, log } = makeApi({ loadMode: 'full' });
    plugin.register(api as any);
    expect(hooks.before_tool_call).toEqual(expect.any(Function));
    expect(log.some((m) => m.includes('Plugin failed to initialize'))).toBe(false);
  });

  it('metadata then full in the same process still attaches before_tool_call', () => {
    const first = makeApi({
      loadMode: 'cli-metadata',
      runtimeThrows: HOST_METADATA_UNAVAILABLE,
    });
    plugin.register(first.api as any);
    expect(first.hooks.before_tool_call).toBeUndefined();

    const second = makeApi({ loadMode: 'full' });
    plugin.register(second.api as any);
    expect(second.hooks.before_tool_call).toEqual(expect.any(Function));
  });

  it('omitted-mode metadata throw then full still attaches', () => {
    const first = makeApi({ runtimeThrows: HOST_METADATA_UNAVAILABLE });
    plugin.register(first.api as any);
    const second = makeApi({ loadMode: 'full' });
    plugin.register(second.api as any);
    expect(second.hooks.before_tool_call).toEqual(expect.any(Function));
  });

  it('full mode with a real config failure is still loud (#134)', () => {
    const { api, log } = makeApi({
      loadMode: 'full',
      configThrows: 'injected host config failure',
    });
    plugin.register(api as any);
    expect(log.some((m) => m.includes('warn:') && m.includes('Plugin failed to initialize'))).toBe(true);
    expect(log.filter((m) => m.startsWith('warn:')).length).toBeGreaterThanOrEqual(2);
  });

  it('manifest declares cliCommands for shieldcortex-status', () => {
    const here = fileURLToPath(import.meta.url);
    const manifestPath = path.resolve(path.dirname(here), '..', 'openclaw.plugin.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')) as {
      cliCommands?: Array<{ name?: string; hasSubcommands?: boolean }>;
    };
    expect(manifest.cliCommands).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'shieldcortex-status', hasSubcommands: false }),
      ]),
    );
  });
});
