import { describe, it, expect } from '@jest/globals';
import { fetchLatestVersion } from '../cli/update.js';
import type { CapturedError } from '../integrations/child-output.js';

/**
 * #248 item 4 — `fetchLatestVersion` discarded WHY the registry lookup
 * failed. An E401 (bad/expired token), ENOTFOUND (offline/DNS) and a proxy
 * failure all collapsed to a bare `null`, which the caller then reports as
 * "registry unreachable" — true for ENOTFOUND, actively wrong for a rejected
 * token, and downstream `null` reads as "already up to date" with no hint an
 * operator should go check their npm auth.
 */

function rejectWith(over: Partial<CapturedError>) {
  return () => Promise.reject(Object.assign(new Error('npm view failed'), {
    exitCode: 1,
    command: 'npm view shieldcortex version',
    stdout: '',
    stderr: '',
    ...over,
  }) as CapturedError);
}

describe('#248 — fetchLatestVersion surfaces why the lookup failed', () => {
  it('resolves the version on success, with no reason', async () => {
    const r = await fetchLatestVersion({
      run: (() => Promise.resolve({ stdout: '4.48.1\n', stderr: '' })) as never,
    });
    expect(r.version).toBe('4.48.1');
    expect(r.reason).toBeUndefined();
  });

  it('carries the auth-rejection reason, not just null, on E401', async () => {
    const r = await fetchLatestVersion({
      run: rejectWith({ stderr: 'npm error code E401\nnpm error 401 Unauthorized - GET https://registry.npmjs.org/shieldcortex\n' }) as never,
    });
    expect(r.version).toBeNull();
    expect(r.reason).toBeTruthy();
    expect(r.reason).toMatch(/E401|Unauthorized/i);
  });

  it('carries the DNS/offline reason on ENOTFOUND', async () => {
    const r = await fetchLatestVersion({
      run: rejectWith({ stderr: 'npm error code ENOTFOUND\nnpm error request to https://registry.npmjs.org/shieldcortex failed, reason: getaddrinfo ENOTFOUND registry.npmjs.org\n' }) as never,
    });
    expect(r.version).toBeNull();
    expect(r.reason).toMatch(/ENOTFOUND/);
  });

  it('the E401 and ENOTFOUND reasons are distinguishable from each other', async () => {
    const auth = await fetchLatestVersion({
      run: rejectWith({ stderr: 'npm error code E401\nnpm error 401 Unauthorized\n' }) as never,
    });
    const offline = await fetchLatestVersion({
      run: rejectWith({ stderr: 'npm error code ENOTFOUND\nnpm error getaddrinfo ENOTFOUND registry.npmjs.org\n' }) as never,
    });
    expect(auth.reason).not.toBe(offline.reason);
  });

  it('still resolves null with a reason when the binary itself is missing', async () => {
    const r = await fetchLatestVersion({
      run: rejectWith({ spawnFailed: true, exitCode: null, code: 'ENOENT' }) as never,
    });
    expect(r.version).toBeNull();
    expect(r.reason).toMatch(/not found/i);
  });
});
