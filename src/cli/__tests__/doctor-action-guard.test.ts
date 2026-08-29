import fs from 'fs';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { checkActionGuard, fixActionGuardConfig } from '../doctor.js';
import { handleCloudConfig } from '../../cloud/cli.js';
import {
  getConfigDir,
  clearCloudConfigCache,
  readRawConfig,
  isConfigTampered,
} from '../../cloud/config.js';

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

// Same file the CLI setters and both runtime surfaces resolve — the jest
// sandbox (scripts/jest-config-sandbox.mjs) points this at a per-worker dir,
// so these tests never touch the developer's real ~/.shieldcortex.
const configPath = () => path.join(getConfigDir(), 'config.json');
const legacySigPath = () => path.join(getConfigDir(), '.config-sig');

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2));
  // A hand-written fixture is unsigned; a `.config-sig` left over from an
  // earlier signed write would make it read as tampered. Drop it and the
  // mtime cache so every fixture is adopted fresh.
  fs.rmSync(legacySigPath(), { force: true });
  clearCloudConfigCache();
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
  fs.rmSync(legacySigPath(), { force: true });
  clearCloudConfigCache();
  jest.restoreAllMocks();
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

  it('warns when notify.openclaw alone is set — not a DNP denial sink (#354)', async () => {
    writeConfig({ actionGuard: { notify: { enabled: true, openclaw: true } } });
    const results = await checkActionGuard();
    const warn = results.find((r) => r.status === 'warn' && /notify/i.test(r.label));
    expect(warn).toBeDefined();
    expect(warn!.message).toMatch(/openclaw only|denial-capable|webhookUrl/i);
    expect(warn!.message).not.toMatch(/native OpenClaw approval card reaches a human/i);
  });

  it('does not warn when webhook denial sink is configured even if openclaw is also on', async () => {
    writeConfig({
      actionGuard: {
        notify: {
          enabled: true,
          openclaw: true,
          webhookUrl: 'https://hooks.example.invalid/sc',
        },
      },
    });
    const results = await checkActionGuard();
    expect(results.find((r) => r.status === 'warn' && /notify/i.test(r.label))).toBeUndefined();
  });

  it('does not warn about notify when the guard is not enforcing', async () => {
    writeConfig({ actionGuard: { enforce: false } });
    const results = await checkActionGuard();
    expect(results.find((r) => /webhookUrl/i.test(r.message))).toBeUndefined();
  });
});

/**
 * #275 — the notify warn's Suggested fix must be a RUNNABLE command through the
 * signed CLI path, not bare JSON key paths: operators who followed the old
 * "set `actionGuard.notify.enabled: true`" prescription hand-edited
 * config.json, invalidated the `_sig` HMAC, and got forced into strict mode.
 */
describe('doctor — Action Guard notify fix is a signed CLI command (#275)', () => {
  const findNotifyWarn = async () => {
    const results = await checkActionGuard();
    return results.find((r) => r.status === 'warn' && /notify/.test(r.label));
  };

  it('prescribes `shieldcortex config` with a real flag, not bare key paths', async () => {
    writeConfig({});
    const warn = await findNotifyWarn();
    expect(warn).toBeDefined();
    // #354: webhook is the denial sink; openclaw is not prescribed as the unattended fix.
    expect(warn!.fix).toMatch(/shieldcortex config --action-guard-notify-webhook/);
    // The bare key-path prescription must no longer lead the fix.
    expect(warn!.fix).not.toMatch(/Set `actionGuard\.notify/);
  });

  it('leads with the runnable command and never recommends hand-editing config.json', async () => {
    writeConfig({});
    const warn = await findNotifyWarn();
    expect(warn).toBeDefined();
    expect(warn!.fix!.startsWith('Run `shieldcortex config')).toBe(true);
    // If config.json is mentioned at all it must be as a warning against
    // editing it, never as an instruction: no sentence may open with an
    // imperative Edit/Add/Set (the old fix began "Set `actionGuard...`").
    expect(warn!.fix).not.toMatch(/(^|\.\s)(Edit|Add|Set)\b/);
  });

  it('openclaw-only CLI enable does NOT clear the unattended-notify warn (#354)', async () => {
    fs.rmSync(configPath(), { force: true });
    fs.rmSync(legacySigPath(), { force: true });
    clearCloudConfigCache();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    handleCloudConfig(['--action-guard-notify-openclaw']);
    const warn = await findNotifyWarn();
    expect(warn).toBeDefined();
    expect(warn!.message).toMatch(/openclaw only|denial-capable|webhookUrl/i);
    const onDisk = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(typeof onDisk._sig).toBe('string');
  });

  it('warn clears when a webhook channel is set via the CLI (signed write)', async () => {
    fs.rmSync(configPath(), { force: true });
    fs.rmSync(legacySigPath(), { force: true });
    clearCloudConfigCache();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    handleCloudConfig(['--action-guard-notify-webhook', 'https://hooks.example.invalid/sc']);
    const warn = await findNotifyWarn();
    expect(warn).toBeUndefined();
    clearCloudConfigCache();
    readRawConfig();
    expect(isConfigTampered()).toBe(false);
  });
});

/**
 * #143 residual — the broker block is the thing operators most often believe is
 * protecting them, and it is OFF by default. Doctor must say which it is, and
 * must not let "broker configured" read as "broker working".
 */
describe('doctor — approval broker honesty (#143)', () => {
  const brokerResult = async () => {
    const results = await checkActionGuard();
    return results.find((r) => /broker/.test(r.label));
  };

  it('says the broker is present but disabled when it is not opted into', async () => {
    writeConfig({ actionGuard: { enabled: true, enforce: true, broker: { allowPreClear: true } } });
    const broker = await brokerResult();
    expect(broker).toBeDefined();
    expect(broker!.message).toMatch(/disabled/i);
    expect(broker!.message).toMatch(/opt-in/i);
    // No claim of protection from a broker that never runs.
    expect(broker!.message).not.toMatch(/armed|protecting/i);
    // The human path is still notify, armed or not.
    expect(broker!.message).toMatch(/notify channel/i);
  });

  it('treats a non-true `enabled` as disabled, exactly as the runtime does', async () => {
    for (const enabled of ['true', 1, 'yes']) {
      writeConfig({ actionGuard: { enabled: true, enforce: true, broker: { enabled } } });
      const broker = await brokerResult();
      expect(broker!.message).toMatch(/disabled/i);
    }
  });

  it('says the broker is armed when it is switched on, without overclaiming', async () => {
    writeConfig({ actionGuard: { enabled: true, enforce: true, broker: { enabled: true } } });
    const broker = await brokerResult();
    expect(broker).toBeDefined();
    expect(broker!.message).toMatch(/armed/i);
    // Armed still means: catastrophic never brokered, no judge → hold, and the
    // human is reached through notify.
    expect(broker!.message).toMatch(/catastrophic is never brokered/i);
    expect(broker!.message).toMatch(/notify channel/i);
    expect(broker!.message).not.toMatch(/disabled/i);
  });

  it('says nothing about a broker on a config that has no broker block', async () => {
    writeConfig({ actionGuard: { enabled: true, enforce: true } });
    expect(await brokerResult()).toBeUndefined();
  });

  it('does not report on the broker when the guard is not enforcing', async () => {
    // Nothing is gated, so nothing is brokered — reporting on the broker here
    // would imply a gate that is not there.
    writeConfig({ actionGuard: { enforce: false, broker: { enabled: true } } });
    expect(await brokerResult()).toBeUndefined();
  });
});

/**
 * #275 acceptance 7 — `doctor --fix-action-guard` used a bare fs.writeFileSync,
 * so the migration it performed carried the OLD `_sig` (or none) and the fix
 * itself tripped the integrity check into strict mode. The write must go
 * through cloud/config's guarded mutate path, which re-signs.
 */
describe('doctor — fixActionGuardConfig re-signs the migrated config (#275)', () => {
  it('migrated config carries a fresh `_sig` and reads back untampered', async () => {
    writeConfig({ interceptor: { actionGuard: { enforce: false } } });
    const fix = fixActionGuardConfig();
    expect(fix.changed).toBe(true);

    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    expect(typeof after._sig).toBe('string');
    expect(after._sig).toMatch(/^[0-9a-f]{64}$/);

    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(false);
    expect(raw.defenceMode).not.toBe('strict');

    if (fix.backupPath) fs.rmSync(fix.backupPath, { force: true });
  });

  it('migration on an already-signed config stays untampered too', async () => {
    // Build a SIGNED config containing the alias: sign a base config via the
    // CLI path, then splice the alias in through another signed write is not
    // possible (no setter writes `interceptor`), so adopt an unsigned fixture
    // first read, then verify the migration write re-signs from there.
    writeConfig({
      actionGuard: { enforce: false },
      interceptor: { enabled: true, actionGuard: { enforce: true, autoApprove: ['git_force_push'] } },
    });
    const fix = fixActionGuardConfig();
    expect(fix.changed).toBe(true);

    const after = JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
    // Merge semantics unchanged from #209: top-level wins, alias gap-fills.
    expect(after.actionGuard).toEqual({ enforce: false, autoApprove: ['git_force_push'] });
    expect(after.interceptor.actionGuard).toBeUndefined();
    expect(after.interceptor.enabled).toBe(true);
    expect(typeof after._sig).toBe('string');

    clearCloudConfigCache();
    readRawConfig();
    expect(isConfigTampered()).toBe(false);

    if (fix.backupPath) fs.rmSync(fix.backupPath, { force: true });
  });
});
