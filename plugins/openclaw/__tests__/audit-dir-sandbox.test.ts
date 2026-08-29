import { homedir, tmpdir } from 'os';
import { join } from 'path';

/**
 * Guards the global audit-dir sandbox in `scripts/jest-config-sandbox.mjs`.
 *
 * This suite deliberately does NOT set `SHIELDCORTEX_AUDIT_DIR` itself — that
 * is the whole point. `plugins/openclaw/interceptor.ts:auditDir()` falls back
 * to `~/.shieldcortex/audit` when the variable is unset, and `writeAuditEntry()`
 * appends on every guarded call, so any suite that reaches the interceptor
 * without the override writes fabricated intercept rows into the host
 * operator's real security audit.
 *
 * That is not hypothetical: on 29 Aug 2026 a live host's audit log took 182
 * fabricated approval rows in two minutes (fixture command `npm install
 * lodash`, session ids `sc-sess-A`/`sc-sess-B`/`sc-sess-approve`) — 80% of that
 * day's approvals, corrupting the exact rate an operator reads when judging
 * whether the Action Guard pages too often.
 *
 * If someone drops the sandbox line, this fails loudly here instead of quietly
 * on a user's machine.
 */
describe('global audit-dir sandbox', () => {
  const realAuditDir = join(homedir(), '.shieldcortex', 'audit');

  it('sets SHIELDCORTEX_AUDIT_DIR for suites that do not set it themselves', () => {
    expect(process.env.SHIELDCORTEX_AUDIT_DIR).toBeTruthy();
  });

  it('points the audit dir inside tmpdir, never at the real ~/.shieldcortex/audit', () => {
    const dir = process.env.SHIELDCORTEX_AUDIT_DIR as string;
    expect(dir.startsWith(tmpdir())).toBe(true);
    expect(dir).not.toBe(realAuditDir);
  });

  it('re-asserts the sandbox after a suite deletes the variable in teardown', () => {
    delete process.env.SHIELDCORTEX_AUDIT_DIR;
    // The setup file's beforeEach restores it before the next test body runs.
    expect(true).toBe(true);
  });

  it('has the variable back after the previous test deleted it', () => {
    expect(process.env.SHIELDCORTEX_AUDIT_DIR).toBeTruthy();
    expect((process.env.SHIELDCORTEX_AUDIT_DIR as string).startsWith(tmpdir())).toBe(true);
  });
});
