import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import plugin, { __resetConfigStateForTest } from '../index.js';

/**
 * Issue #134 §2 — a security plugin going inert must be loud, not a bare
 * console.warn.
 *
 * register() wraps its whole body in try/catch so a plugin failure can never
 * block channel startup — that part is correct and stays. Two things were
 * wrong with how the failure was reported:
 *
 *  1. It used `console.warn` directly, which bypasses the gateway's
 *     structured log (`api.logger`). Real-time scanning, memory capture and
 *     the Action Guard before_tool_call hook all go dark with no `[plugins]`
 *     line anywhere an operator actually looks.
 *  2. `/shieldcortex-status` was registered INSIDE the same try block that
 *     could throw, so a crash before that line meant the command never
 *     existed — the plugin couldn't even honestly report its own death.
 *
 * Reproduced here by forcing `applyPluginConfigOverride()` to throw (a bad
 * `api.runtime.config.current()`), which is the very first statement in the
 * try block — so under the OLD code NEITHER the status command NOR any
 * api.logger.warn call would ever happen.
 */

type Hooks = Record<string, (...args: any[]) => any>;
type Commands = Record<string, { name: string; handler: () => Promise<{ text: string }> }>;

function makeBrokenApi(): { api: any; hooks: Hooks; commands: Commands; log: string[] } {
  const hooks: Hooks = {};
  const commands: Commands = {};
  const log: string[] = [];
  const api = {
    id: 'shieldcortex-realtime',
    name: 'ShieldCortex Real-time Scanner',
    logger: {
      info: (m: string) => { log.push(`info: ${m}`); },
      warn: (m: string) => { log.push(`warn: ${m}`); },
    },
    on: (name: string, handler: (...args: any[]) => any) => { hooks[name] = handler; },
    registerCommand: (cmd: any) => { commands[cmd.name] = cmd; },
    runtime: {
      config: {
        // Throws synchronously — the first thing applyPluginConfigOverride()
        // does inside register()'s try block.
        current: () => { throw new Error('injected host config failure'); },
      },
    },
  };
  return { api, hooks, commands, log };
}

beforeEach(() => {
  __resetConfigStateForTest();
});

describe('#134 §2 — registration failure is surfaced loudly, not swallowed', () => {
  it('routes the failure through api.logger.warn, not a bare console.warn', () => {
    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const { api, log } = makeBrokenApi();
      plugin.register(api);

      expect(log.some((m) => m.includes('warn:') && m.includes('Plugin failed to initialize'))).toBe(true);
      expect(log.some((m) => m.includes('warn:') && m.includes('Real-time scanning is disabled'))).toBe(true);
      // The whole point: the gateway's structured logger carried this, not
      // stdout that a hook context usually discards.
      expect(consoleWarnSpy).not.toHaveBeenCalled();
    } finally {
      consoleWarnSpy.mockRestore();
    }
  });

  it('/shieldcortex-status exists even though registration crashed, and reports DEGRADED honestly', async () => {
    const { api, commands } = makeBrokenApi();
    plugin.register(api);

    expect(commands['shieldcortex-status']).toBeDefined();
    const status = await commands['shieldcortex-status'].handler();
    expect(status.text).toMatch(/DEGRADED/);
    expect(status.text).toMatch(/INACTIVE/);
    expect(status.text).toMatch(/injected host config failure/);
  });
});
