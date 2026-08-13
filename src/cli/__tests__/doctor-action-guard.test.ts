import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkActionGuard, fixActionGuardConfig } from '../doctor.js';

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

/**
 * Issue #209 — the split-key gotcha is resolved, not just warned about:
 * top-level `actionGuard` now governs BOTH surfaces and
 * `interceptor.actionGuard` is a deprecated gap-fill alias. Doctor's job
 * changes accordingly: warn that the alias is in use (with the migration
 * command), report conflicts as top-level-wins, and evaluate posture
 * warnings against the EFFECTIVE merged config with per-key provenance.
 */
describe('doctor — Action Guard #209 alias resolution and migration', () => {
  it('warns that the deprecated alias is in use, pointing at --fix-action-guard', async () => {
    writeConfig({ interceptor: { actionGuard: { enforce: true } } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /deprecated/i.test(r.message));
    expect(warn).toBeDefined();
    expect(warn!.fix ?? warn!.message).toMatch(/--fix-action-guard/);
  });

  it('conflict warning names the keys and states that top-level wins', async () => {
    writeConfig({ actionGuard: { enforce: false }, interceptor: { actionGuard: { enforce: true } } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /differ/i.test(r.message));
    expect(warn).toBeDefined();
    expect(warn!.message).toMatch(/enforce/);
    expect(warn!.message).toMatch(/top-level|actionGuard.*wins/i);
  });

  it('posture warnings use the effective merged config with key provenance', async () => {
    // enforce:false comes from the ALIAS (top-level does not set it) — the
    // warn must fire and must name the alias key that caused it.
    writeConfig({ actionGuard: { enabled: true }, interceptor: { actionGuard: { enforce: false } } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /warn-mode/i.test(r.message));
    expect(warn).toBeDefined();
    expect(warn!.message).toMatch(/interceptor\.actionGuard\.enforce/);
  });

  it('does NOT warn warn-mode when top-level enforce:true overrides an alias enforce:false', async () => {
    writeConfig({ actionGuard: { enforce: true }, interceptor: { actionGuard: { enforce: false } } });
    const results = await checkActionGuard();
    expect(results.find((r) => /warn-mode/i.test(r.message))).toBeUndefined();
  });

  it('fixActionGuardConfig migrates the alias into top-level, backs up, and clears the warning', async () => {
    writeConfig({
      actionGuard: { enforce: false },
      interceptor: { enabled: true, actionGuard: { enforce: true, autoApprove: ['git_force_push'] } },
    });
    const fix = fixActionGuardConfig();
    expect(fix.changed).toBe(true);
    expect(fix.backupPath && fs.existsSync(fix.backupPath)).toBe(true);

    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    // Top-level wins on conflict (enforce stays false), alias gap-fills (autoApprove kept).
    expect(after.actionGuard).toEqual({ enforce: false, autoApprove: ['git_force_push'] });
    expect(after.interceptor.actionGuard).toBeUndefined();
    // Sibling interceptor keys survive the migration.
    expect(after.interceptor.enabled).toBe(true);

    const results = await checkActionGuard();
    expect(results.find((r) => /deprecated/i.test(r.message))).toBeUndefined();

    if (fix.backupPath) fs.rmSync(fix.backupPath, { force: true });
  });

  it('fixActionGuardConfig removes an emptied interceptor block entirely', async () => {
    writeConfig({ interceptor: { actionGuard: { enforce: false } } });
    const fix = fixActionGuardConfig();
    expect(fix.changed).toBe(true);
    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(after.actionGuard).toEqual({ enforce: false });
    expect(after.interceptor).toBeUndefined();
    if (fix.backupPath) fs.rmSync(fix.backupPath, { force: true });
  });

  it('fixActionGuardConfig is a no-op without the alias', async () => {
    writeConfig({ actionGuard: { enforce: false } });
    const fix = fixActionGuardConfig();
    expect(fix.changed).toBe(false);
  });
});

/**
 * #242 Defect B / #260 — unattended enforcement with no notify channel is how
 * eight days of backups vanished while lastRunStatus stayed ok. Doctor must
 * WARN (not fail) when enforce is on and nothing can reach a human.
 */
describe('doctor — Action Guard notify channel (#242)', () => {
  it('warns when enforce is on and notify.webhookUrl is unset (the default)', async () => {
    writeConfig({});
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /webhookUrl|notify/i.test(r.message));
    expect(warn).toBeDefined();
    expect(warn!.status).toBe('warn');
    expect(warn!.message).toMatch(/webhookUrl/i);
    expect(warn!.fix ?? '').toMatch(/notify/i);
  });

  it('does not warn when a webhook is configured and notify is enabled', async () => {
    writeConfig({
      actionGuard: {
        notify: { enabled: true, webhookUrl: 'https://hooks.example.invalid/sc' },
      },
    });
    const results = await checkActionGuard();
    expect(results.find((r) => /webhookUrl|notify channel/i.test(r.message))).toBeUndefined();
  });

  it('does not warn when notify.openclaw is the configured channel', async () => {
    writeConfig({ actionGuard: { notify: { enabled: true, openclaw: true } } });
    const results = await checkActionGuard();
    expect(results.find((r) => /webhookUrl|notify channel/i.test(r.message))).toBeUndefined();
  });

  it('does not warn about notify when the guard is not enforcing', async () => {
    writeConfig({ actionGuard: { enforce: false } });
    const results = await checkActionGuard();
    expect(results.find((r) => /webhookUrl/i.test(r.message))).toBeUndefined();
  });
});
