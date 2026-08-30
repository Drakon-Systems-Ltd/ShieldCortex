import { homedir, tmpdir } from 'os';
import { join, relative, isAbsolute } from 'path';

/** True containment, not a string prefix: `/tmp/x` must not "contain" `/tmp/xy`.
 *  A prefix test would pass for a sibling directory whose name merely starts
 *  with the tmpdir path, which is exactly the false green a guard must not have. */
function isInside(parent: string, child: string): boolean {
  const rel = relative(parent, child);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

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
    expect(isInside(tmpdir(), dir)).toBe(true);
    expect(dir).not.toBe(realAuditDir);
    expect(isInside(join(homedir(), '.shieldcortex'), dir)).toBe(false);
  });

  // These two are a PAIR and depend on declaration order: the first unsets the
  // variable, the second proves the setup file's beforeEach put it back. Ten
  // suites `delete process.env.SHIELDCORTEX_AUDIT_DIR` in teardown; without the
  // re-assert the next suite silently falls back to the real
  // ~/.shieldcortex/audit.
  //
  // The dependency is made EXPLICIT rather than assumed. Jest runs in
  // declaration order by default, but if that is ever randomized this guard must
  // fail loudly instead of passing vacuously — a test that quietly stops testing
  // is the same class of defect as the leak it guards.
  let deleteCaseRan = false;

  it('a teardown-style delete really does unset the variable', () => {
    delete process.env.SHIELDCORTEX_AUDIT_DIR;
    expect(process.env.SHIELDCORTEX_AUDIT_DIR).toBeUndefined();
    deleteCaseRan = true;
  });

  it('restores the sandbox before the next test, after that delete', () => {
    expect(deleteCaseRan).toBe(true); // ordering precondition, not an assumption
    const dir = process.env.SHIELDCORTEX_AUDIT_DIR;
    expect(dir).toBeTruthy();
    expect(isInside(tmpdir(), dir as string)).toBe(true);
    expect(dir).not.toBe(realAuditDir);
  });
});
