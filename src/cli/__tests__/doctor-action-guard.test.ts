import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkActionGuard } from '../doctor.js';

/**
 * Issue #94 — doctor had ZERO Action Guard check: its "Defence canary" probes
 * the firewall's instruction detector, a different layer entirely. This check
 * runs the REAL `evaluateToolCall` against three verdict probes (catastrophic
 * must block, dangerous must gate, benign must allow), resolves the box's
 * actual config for BOTH guard surfaces (the Claude Code hook reads
 * `actionGuard`, the OpenClaw plugin reads `interceptor.actionGuard`), and is
 * honestly labelled: it proves guard logic + config, not interceptor wiring —
 * wiring proof stays with the consent-gated live canary.
 */

const configPath = () => path.join(os.homedir(), '.shieldcortex', 'config.json');

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2));
}

let savedConfig: string | null = null;

beforeEach(() => {
  savedConfig = fs.existsSync(configPath()) ? fs.readFileSync(configPath(), 'utf-8') : null;
});

afterEach(() => {
  if (savedConfig === null) {
    fs.rmSync(configPath(), { force: true });
  } else {
    fs.writeFileSync(configPath(), savedConfig);
  }
});

describe('doctor — Action Guard check (#94)', () => {
  it('passes with 3/3 verdict probes on default config, and labels itself in-process', async () => {
    writeConfig({});
    const results = await checkActionGuard();
    const probe = results.find((r) => r.label === 'Action guard');
    expect(probe).toBeDefined();
    expect(probe!.status).toBe('pass');
    expect(probe!.message).toMatch(/3\/3/);
    expect(probe!.message).toMatch(/in-process/i);
    expect(probe!.message).toMatch(/wiring/i);
  });

  it('warns when the Claude Code hook surface disables enforcement (actionGuard.enforce)', async () => {
    writeConfig({ actionGuard: { enforce: false } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /enforce/i.test(r.message));
    expect(warn).toBeDefined();
    expect(warn!.message).toMatch(/Claude Code hook|actionGuard/);
  });

  it('warns when the plugin surface disables the guard (interceptor.actionGuard.enabled)', async () => {
    writeConfig({ interceptor: { actionGuard: { enabled: false } } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /disabled|off/i.test(r.message));
    expect(warn).toBeDefined();
    expect(warn!.message).toMatch(/plugin|interceptor/i);
  });

  it('warns when the two config surfaces diverge (split-key gotcha)', async () => {
    writeConfig({ actionGuard: { enforce: false }, interceptor: { actionGuard: { enforce: true } } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /diverge|differ|split/i.test(r.message));
    expect(warn).toBeDefined();
  });

  it('still reports probe results when no config file exists at all', async () => {
    fs.rmSync(configPath(), { force: true });
    const results = await checkActionGuard();
    const probe = results.find((r) => r.label === 'Action guard');
    expect(probe).toBeDefined();
    expect(probe!.status).toBe('pass');
  });
});
