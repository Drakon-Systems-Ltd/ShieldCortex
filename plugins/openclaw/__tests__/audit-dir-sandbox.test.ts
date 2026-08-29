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

  // These two run in declaration order and are a PAIR: the first establishes
  // that the variable is genuinely unset, so the second passing is proof the
  // setup file's beforeEach restored it — not proof it was never removed.
  // Ten suites `delete process.env.SHIELDCORTEX_AUDIT_DIR` in teardown; without
  // the re-assert, the next suite would silently fall back to the real
  // ~/.shieldcortex/audit.
  it('a teardown-style delete really does unset the variable', () => {
    delete process.env.SHIELDCORTEX_AUDIT_DIR;
    expect(process.env.SHIELDCORTEX_AUDIT_DIR).toBeUndefined();
  });

  it('restores the sandbox before the next test, after that delete', () => {
    const dir = process.env.SHIELDCORTEX_AUDIT_DIR;
    expect(dir).toBeTruthy();
    expect((dir as string).startsWith(tmpdir())).toBe(true);
    expect(dir).not.toBe(realAuditDir);
  });
});
