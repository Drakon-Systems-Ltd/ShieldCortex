/**
 * #577 round 3, nit — prove at RUNTIME that consent reaches reconciliation.
 *
 * Round 2 threaded `--allow-conversation-access` (#226) from each command's one
 * parse point down to the plugin reconcile, replacing a `process.argv` read
 * several modules below the strict parser. The tests for it asserted the SOURCE
 * of `stepVerifyProtection` / `runPluginReconcilePass` — which shows the call is
 * written correctly and nothing else. The behavioural claim is "the value the
 * operator typed is the value reconciliation receives", and only a spy at that
 * boundary can say it.
 *
 * So: mock `setup/openclaw-reconcile.js`, drive the real `update` and `repair`
 * paths, and read `grantConversationAccess` off the recorded call. `process.argv`
 * is set to a command line WITHOUT the flag throughout, so the only thing that
 * can produce `true` is the threaded parameter — and the reconciler's own argv
 * fallback (`options.grantConversationAccess ?? resolveConversationAccessConsent`)
 * can never fire, because an explicit boolean always arrives.
 *
 * `unstable_mockModule` needs the mock registered before the module under test
 * is loaded, hence the dynamic imports and this file's existence as a suite of
 * its own.
 */
import { afterAll, afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

interface ReconcileCall { grantConversationAccess?: boolean; home?: string }

const calls: ReconcileCall[] = [];

jest.unstable_mockModule('../../setup/openclaw-reconcile.js', () => ({
  reconcileOpenClawPluginState: jest.fn(async (options: ReconcileCall) => {
    calls.push(options);
    return { ok: true, applied: false, state: 'healthy', messages: [], verdict: { state: 'healthy' } };
  }),
  formatReconcileReport: () => ['reconcile: mocked'],
  protectionLedgerFromReconcile: () => ({ status: 'ok', summary: 'mocked', detail: [] }),
}));

// repair's other two passes mutate the host (a native rebuild and a chmod walk).
// Neither is the subject here, and both are statically imported, so they are
// mocked out rather than run.
jest.unstable_mockModule('../../setup/native-binding.js', () => ({
  ensureNativeBinding: jest.fn(async () => ({ status: 'ok' })),
}));
jest.unstable_mockModule('../../setup/state-permissions.js', () => ({
  secureStatePermissions: jest.fn(() => []),
  mkdirSecure: jest.fn(),
  SECURE_OPEN_MODE: 0o600,
}));

const { stepVerifyProtection } = await import('../update.js');
const { runRepair } = await import('../repair.js');

let tmp = '';
let prevArgv: string[] = [];
let writes: string[] = [];

/** A HOME whose plugin registry says the realtime plugin IS registered, so
 *  stepVerifyProtection reaches the reconcile instead of returning its
 *  "plugin not registered" skip. */
function registeredHome(): string {
  const home = path.join(tmp, 'home');
  const plugins = path.join(home, '.openclaw', 'plugins');
  fs.mkdirSync(plugins, { recursive: true });
  fs.writeFileSync(
    path.join(plugins, 'installs.json'),
    JSON.stringify({ installRecords: { 'shieldcortex-realtime': { version: '5.2.0' } } }),
  );
  return home;
}

const origWrite = process.stdout.write.bind(process.stdout);

beforeEach(() => {
  calls.length = 0;
  writes = [];
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc577-consent-'));
  prevArgv = process.argv;
  // The flag is NOT here. Any `true` below therefore came from the parameter.
  process.argv = [process.argv[0], process.argv[1], 'update'];
  process.stdout.write = ((c: string | Uint8Array) => { writes.push(String(c)); return true; }) as typeof process.stdout.write;
});

afterEach(() => {
  process.stdout.write = origWrite;
  process.argv = prevArgv;
  fs.rmSync(tmp, { recursive: true, force: true });
});

afterAll(() => { process.stdout.write = origWrite; });

describe('#577 — update: consent arrives at the reconcile boundary', () => {
  it('with the flag parsed, reconciliation receives grantConversationAccess: true', async () => {
    const home = registeredHome();
    await stepVerifyProtection(home, { verbose: false, allowConversationAccess: true });
    expect(calls).toHaveLength(1);
    expect(calls[0].grantConversationAccess).toBe(true);
    expect(calls[0].home).toBe(home);
    expect(process.argv.join(' ')).not.toContain('--allow-conversation-access');
  });

  it('without it, reconciliation receives an explicit false — never undefined', async () => {
    // Explicit matters: `undefined` is what re-arms the reconciler's own
    // process.argv fallback, which is the read #577 removed.
    await stepVerifyProtection(registeredHome(), { verbose: false });
    expect(calls).toHaveLength(1);
    expect(calls[0].grantConversationAccess).toBe(false);
  });

  it('a stray --allow-conversation-access in process.argv cannot grant it', async () => {
    process.argv = [process.argv[0], process.argv[1], 'update', '--allow-conversation-access'];
    await stepVerifyProtection(registeredHome(), { verbose: false, allowConversationAccess: false });
    expect(calls).toHaveLength(1);
    expect(calls[0].grantConversationAccess).toBe(false);
  });
});

describe('#577 — repair: consent arrives at the reconcile boundary', () => {
  it('`repair --allow-conversation-access` reconciles with consent true', async () => {
    await runRepair(['--allow-conversation-access'], { env: {} });
    expect(calls).toHaveLength(1);
    expect(calls[0].grantConversationAccess).toBe(true);
  });

  it('the environment twin grants it at the same single parse point', async () => {
    await runRepair([], { env: { SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS: '1' } });
    expect(calls).toHaveLength(1);
    expect(calls[0].grantConversationAccess).toBe(true);
  });

  it('a bare `repair` reconciles with an explicit false', async () => {
    await runRepair([], { env: {} });
    expect(calls).toHaveLength(1);
    expect(calls[0].grantConversationAccess).toBe(false);
  });

  it('`repair --help` reaches no reconcile at all', async () => {
    const prevExit = process.exitCode;
    try {
      await runRepair(['--help'], { env: {} });
      expect(process.exitCode).toBe(0);
    } finally {
      process.exitCode = prevExit;
    }
    expect(calls).toEqual([]);
  });
});
