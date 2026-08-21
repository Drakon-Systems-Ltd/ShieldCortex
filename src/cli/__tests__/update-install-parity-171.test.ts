/**
 * #171 — `shieldcortex update` must reach the same fixes as `install`.
 *
 * Field question, 1 Aug 2026, after the operator-experience release: "what
 * about shieldcortex update — does that still work?" Auditing it found the
 * recurring codebase defect, again: two fixes had landed on the install path
 * and never reached update's parallel flow.
 *
 *   - #163 permission hardening lives in `setupClaudeMd()` step 5; update
 *     calls `setupHooks()` directly and skipped it — so a box that upgraded
 *     via `update` kept its world-readable memories.db.
 *   - update force-installed the plugin and LEFT THE GATEWAY RUNNING THE OLD
 *     BUILD, with one gray "restart …" hint. On-disk current + gateway stale
 *     is the state three fleet boxes spent the week stuck in.
 *
 * These are wiring tests in the #146/#160 tradition: the helpers are tested
 * elsewhere; what rotted was whether THIS caller invokes them. Source-level,
 * like enforcement-surface-parity — a runtime test of `runUpdate()` would need
 * npm, a registry and a gateway.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const updateSrc = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'update.ts'), 'utf-8');

function bodyOf(fnName: string): string {
  const at = updateSrc.indexOf(`async function ${fnName}`);
  expect({ fn: fnName, found: at >= 0 }).toEqual({ fn: fnName, found: true });
  return updateSrc.slice(at, updateSrc.indexOf('\n}', at));
}

describe('#171 — update runs the #163 permission hardening', () => {
  it('a state-permissions stage exists and calls the shared helper', () => {
    const body = bodyOf('stepStatePermissions');
    expect(body).toMatch(/secureStatePermissions\(/);
    // The SAME directory install hardens — not a re-derived path.
    expect(body).toMatch(/getConfigDir\(\)/);
  });

  it('runUpdate invokes it', () => {
    const body = bodyOf('runUpdate');
    expect(body).toMatch(/await stepStatePermissions\(\)/);
  });
});

describe('#171 — update ends by verifying protection, like repair', () => {
  it('a verify stage exists and runs the reconcile flow', () => {
    const body = bodyOf('stepVerifyProtection');
    expect(body).toMatch(/reconcileOpenClawPluginState\(/);
    expect(body).toMatch(/formatReconcileReport\(/);
  });

  it('expected version is read fresh from disk, never the in-process pkg version', () => {
    // After the npm step the on-disk package is the NEW build; the running
    // process is the OLD one. Pinning expectations to the old version would
    // certify the staleness this stage exists to end.
    const body = bodyOf('stepVerifyProtection');
    expect(body).toMatch(/expectedVersion:\s*readPackageVersion\(\)/);
    expect(body).not.toMatch(/expectedVersion:\s*currentVersion/);
  });

  it('an applied-but-failed verify sets a non-zero exit code — no false all-clear', () => {
    // Ledger maps true unprotected → failed; unproven (canary live / roster unread)
    // stays attention. runUpdate exits 1 only on protection.status === 'failed'.
    const stepBody = bodyOf('stepVerifyProtection');
    const runBody = bodyOf('runUpdate');
    expect(stepBody).toMatch(/protectionLedgerFromReconcile/);
    expect(stepBody).toMatch(/ledger\.status/);
    expect(runBody).toMatch(/process\.exitCode\s*=\s*1/);
    expect(runBody).toMatch(/protection\.status === 'failed'/);
  });

  it('runUpdate invokes it', () => {
    const body = bodyOf('runUpdate');
    expect(body).toMatch(/await stepVerifyProtection\(home\)/);
  });

  it('skips cleanly when no plugin is registered — a Claude-Code-only box is not an error', () => {
    const body = bodyOf('stepVerifyProtection');
    // #248: the plain `isRealtimePluginRegistered(home)` boolean collapsed
    // "not installed" and "registry unreadable" into the same silent skip —
    // the split-result read is what lets "not registered" stay a clean skip
    // while "unreadable" gets its own surfaced branch.
    expect(body).toMatch(/readRealtimePluginRegistration\(home\)/);
    expect(body).toMatch(/!registration\.registered/);
  });

  it('surfaces (does not silently skip) when the registry could not be confirmed', () => {
    const body = bodyOf('stepVerifyProtection');
    expect(body).toMatch(/registration\.unreadable/);
    expect(body).toMatch(/protection check skipped/);
  });
});
