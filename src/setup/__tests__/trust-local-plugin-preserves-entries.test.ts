import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { trustLocalPlugin } from '../openclaw.js';

/**
 * Issue #112 follow-up — the Edith re-enable added
 * `plugins.entries.codex.config.appServer.networkProxy`, which broke
 * `shouldAutoApproveCodexAppServerApprovals()` (it auto-approves only when
 * networkProxy is undefined) and left unattended Sol/Terra/5.5 shell calls
 * waiting 120s on approvals nobody could give.
 *
 * ShieldCortex's installer was suspected. It is innocent — trustLocalPlugin()
 * only writes `plugins.allow` and its own `plugins.entries[shieldcortex-realtime]`
 * — and these tests pin that innocence: other plugins' entries (codex included)
 * must pass through byte-for-byte, and no install/re-enable may ever introduce
 * `networkProxy` or any other appServer setting.
 */

const PLUGIN_ID = 'shieldcortex-realtime';

let tmpHome: string;

function configPath(): string {
  return path.join(tmpHome, '.openclaw', 'openclaw.json');
}

function writeConfig(config: unknown): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

function readConfig(): any {
  return JSON.parse(fs.readFileSync(configPath(), 'utf-8'));
}

// The codex entry exactly as found on Edith after the incident install —
// including the networkProxy block that must never be authored or altered by us.
const EDITH_CODEX_ENTRY = {
  enabled: true,
  config: {
    appServer: {
      networkProxy: { enabled: true, host: '127.0.0.1', port: 8899 },
      approvalPolicy: 'never',
      sandbox: 'danger-full-access',
    },
  },
};

beforeEach(() => {
  // Injected via trustLocalPlugin's homeArg seam — jest's process.env is a
  // plain-object copy that never reaches the native os.homedir() binding, so
  // a HOME override cannot redirect the config path here.
  tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-trust-plugin-'));
});

afterEach(() => {
  fs.rmSync(tmpHome, { recursive: true, force: true });
});

describe('#112 follow-up — trustLocalPlugin leaves other plugins\' entries untouched', () => {
  it('preserves plugins.entries.codex (networkProxy included) byte-for-byte', () => {
    writeConfig({ plugins: { entries: { codex: EDITH_CODEX_ENTRY } } });

    expect(trustLocalPlugin('/unused', '0.0.0-test', tmpHome)).toBe(true);

    const after = readConfig();
    expect(after.plugins.entries.codex).toEqual(EDITH_CODEX_ENTRY);
    // #226: a plain install writes `enabled` and NOTHING else. The
    // conversation-access grant is a separate decision (it authorises reading
    // every prompt on the box) and is never written unasked — see the
    // consent-gated cases below.
    expect(after.plugins.entries[PLUGIN_ID]).toEqual({ enabled: true });
    expect(after.plugins.allow).toContain(PLUGIN_ID);
  });

  it('never introduces networkProxy or appServer keys anywhere in the config', () => {
    writeConfig({ plugins: { entries: {} } });

    expect(trustLocalPlugin('/unused', '0.0.0-test', tmpHome)).toBe(true);

    const raw = fs.readFileSync(configPath(), 'utf-8');
    expect(raw).not.toContain('networkProxy');
    expect(raw).not.toContain('appServer');
  });

  it('re-enable over an existing install is idempotent for everyone else too', () => {
    writeConfig({
      plugins: {
        allow: [PLUGIN_ID],
        entries: {
          codex: EDITH_CODEX_ENTRY,
          [PLUGIN_ID]: { enabled: true, config: { interceptor: { enabled: false } } },
        },
      },
    });
    const before = readConfig();

    expect(trustLocalPlugin('/unused', '0.0.0-test', tmpHome)).toBe(true);

    // Already-correct config → idempotency gate skips the write entirely.
    expect(readConfig()).toEqual(before);
  });

  it('#226: a plain install NEVER writes the conversation-access grant', () => {
    // The grant authorises this plugin to read every prompt and every model
    // response on the box. Installing a plugin is not asking for that, and #225
    // is explicit that the installer must never set it silently.
    writeConfig({ plugins: { entries: {} } });

    expect(trustLocalPlugin('/unused', '0.0.0-test', tmpHome)).toBe(true);

    expect(fs.readFileSync(configPath(), 'utf-8')).not.toContain('allowConversationAccess');
    expect(readConfig().plugins.entries[PLUGIN_ID]).toEqual({ enabled: true });
  });

  it('#226: writes the grant when the operator explicitly asks for it', () => {
    writeConfig({ plugins: { entries: { codex: EDITH_CODEX_ENTRY } } });

    expect(
      trustLocalPlugin('/unused', '0.0.0-test', tmpHome, { grantConversationAccess: true }),
    ).toBe(true);

    const after = readConfig();
    expect(after.plugins.entries[PLUGIN_ID]).toEqual({
      enabled: true,
      hooks: { allowConversationAccess: true },
    });
    // Still only OUR entry.
    expect(after.plugins.entries.codex).toEqual(EDITH_CODEX_ENTRY);
  });

  it('#226: granting preserves other hook policies the operator set', () => {
    writeConfig({
      plugins: {
        allow: [PLUGIN_ID],
        entries: {
          [PLUGIN_ID]: { enabled: true, hooks: { allowPromptInjection: false } },
        },
      },
    });

    expect(
      trustLocalPlugin('/unused', '0.0.0-test', tmpHome, { grantConversationAccess: true }),
    ).toBe(true);

    expect(readConfig().plugins.entries[PLUGIN_ID].hooks).toEqual({
      allowPromptInjection: false,
      allowConversationAccess: true,
    });
  });

  it('#226: an install WITHOUT consent never revokes a grant the operator already made', () => {
    writeConfig({
      plugins: {
        allow: [PLUGIN_ID],
        entries: { [PLUGIN_ID]: { enabled: false, hooks: { allowConversationAccess: true } } },
      },
    });

    expect(trustLocalPlugin('/unused', '0.0.0-test', tmpHome)).toBe(true);

    expect(readConfig().plugins.entries[PLUGIN_ID]).toEqual({
      enabled: true,
      hooks: { allowConversationAccess: true },
    });
  });

  it('preserves our own user-set interceptor config when (re)enabling', () => {
    writeConfig({
      plugins: {
        entries: {
          [PLUGIN_ID]: { enabled: false, config: { interceptor: { enabled: false } } },
        },
      },
    });

    expect(trustLocalPlugin('/unused', '0.0.0-test', tmpHome)).toBe(true);

    const after = readConfig();
    expect(after.plugins.entries[PLUGIN_ID].enabled).toBe(true);
    expect(after.plugins.entries[PLUGIN_ID].config).toEqual({ interceptor: { enabled: false } });
  });
});
