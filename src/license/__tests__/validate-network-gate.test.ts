/**
 * #430 — licence validation must make no network call unless a licence key
 * is actually configured.
 *
 * SKILL.md promises "network is off by default". The one legitimate
 * licence exception — validating an activated key against the SaaS API —
 * only applies when a key exists. These tests pin the gate: no licence
 * file, no key field, or an unparseable key ⇒ zero fetches; a configured
 * key ⇒ exactly one fetch to the licence endpoint, independent of the
 * Cloud sync setting.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const { validateOnline, validateOnceNow, scheduleOnlineValidation } = await import('../validate.js');

const realFetch = globalThis.fetch;
let fetchMock: jest.Mock;
let configDir: string;
let prevConfigDir: string | undefined;

/** Build a key whose payload parses (sid present) — signature irrelevant here. */
function craftKey(sid: string): string {
  const payload = Buffer.from(
    JSON.stringify({
      tier: 'enterprise',
      teamId: 'team_test',
      exp: 4102444800, // 2100-01-01
      sid,
      email: 'qa@example.com',
    })
  ).toString('base64url');
  const sig = Buffer.from('not-a-real-signature').toString('base64url');
  return `sc_ent_${payload}.${sig}`;
}

function writeLicenseFile(contents: Record<string, unknown>): void {
  writeFileSync(join(configDir, 'license.json'), JSON.stringify(contents, null, 2));
}

/** Let a fire-and-forget promise chain settle. */
function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

beforeEach(() => {
  prevConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
  configDir = mkdtempSync(join(tmpdir(), 'sc-license-gate-'));
  process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
  fetchMock = jest.fn();
  globalThis.fetch = fetchMock as unknown as typeof fetch;
});

afterEach(() => {
  globalThis.fetch = realFetch;
  if (prevConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = prevConfigDir;
  rmSync(configDir, { recursive: true, force: true });
});

describe('licence network gate (#430)', () => {
  it('validateOnline makes no network call when no licence file exists', async () => {
    await validateOnline();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('validateOnline makes no network call when the licence file has no key', async () => {
    writeLicenseFile({ activatedAt: '2026-01-01T00:00:00Z', validationStatus: 'unvalidated' });
    await validateOnline();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('validateOnline makes no network call when the key payload is unparseable', async () => {
    writeLicenseFile({ key: 'sc_ent_not-a-real-key-no-dot' });
    await validateOnline();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('scheduleOnlineValidation fires nothing without a key', async () => {
    scheduleOnlineValidation();
    await flush();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('validateOnceNow returns unvalidated without a key and makes no call', async () => {
    expect(await validateOnceNow()).toBe('unvalidated');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('with a key configured, validates against the licence endpoint even with Cloud sync off', async () => {
    // No config.json in the sandbox dir ⇒ Cloud sync disabled. This is the
    // documented exception: an activated key is revocation-checked online.
    writeLicenseFile({ key: craftKey('sub_test_430'), validationStatus: 'unvalidated' });
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'active' }),
    });

    await validateOnline();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const url = String(fetchMock.mock.calls[0][0]);
    expect(url).toBe('https://api.shieldcortex.ai/v1/license/validate?sid=sub_test_430');

    const stored = JSON.parse(readFileSync(join(configDir, 'license.json'), 'utf-8'));
    expect(stored.validationStatus).toBe('valid');
  });

  it('leaves validation status unchanged when the licence server is unreachable', async () => {
    writeLicenseFile({ key: craftKey('sub_test_430'), validationStatus: 'unvalidated' });
    fetchMock.mockRejectedValue(new Error('ENOTFOUND api.shieldcortex.ai'));

    await validateOnline();

    const stored = JSON.parse(readFileSync(join(configDir, 'license.json'), 'utf-8'));
    expect(stored.validationStatus).toBe('unvalidated');
  });
});
