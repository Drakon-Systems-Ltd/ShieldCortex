/**
 * #218 wiring — `shieldcortex repair` must re-harden the state tree.
 *
 * doctor's permission check fails after a gateway restart (a recreated lock
 * file / log dir under default umask), and doctor's own fix text points the
 * operator at `repair`. Before this, `repair` ran only the native-binding and
 * plugin-reconcile passes — so the command doctor recommended did not correct
 * what doctor failed on: the exact one-call-site gap of #222/#103, one layer
 * over.
 *
 * Source-level, in the #171 tradition (update-install-parity-171.test.ts): the
 * helper `secureStatePermissions` is tested directly in
 * state-permissions-at-create-218.test.ts; what would rot silently is whether
 * THIS caller invokes it. A runtime test of `runRepair()` would chmod the real
 * ~/.shieldcortex.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const repairSrc = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'repair.ts'), 'utf-8');

describe('#218 — repair re-hardens the state tree', () => {
  it('a state-permission pass exists and calls the shared helper on getConfigDir()', () => {
    const at = repairSrc.indexOf('function runStatePermissionPass');
    expect(at).toBeGreaterThanOrEqual(0);
    const body = repairSrc.slice(at, repairSrc.indexOf('\n}', at));
    expect(body).toMatch(/secureStatePermissions\(/);
    // The SAME resolver install/update pass — honours SHIELDCORTEX_CONFIG_DIR,
    // not a hardcoded homedir subset.
    expect(body).toMatch(/getConfigDir\(\)/);
  });

  it('runRepair actually invokes it', () => {
    const at = repairSrc.indexOf('export async function runRepair');
    expect(at).toBeGreaterThanOrEqual(0);
    const body = repairSrc.slice(at, repairSrc.indexOf('\nexport ', at + 1) >= 0 ? repairSrc.indexOf('\nexport ', at + 1) : repairSrc.length);
    expect(body).toMatch(/runStatePermissionPass\(\)/);
  });

  it('a permission it could not fix is a hard error, never a false all-clear', () => {
    const at = repairSrc.indexOf('function runStatePermissionPass');
    const body = repairSrc.slice(at, repairSrc.indexOf('\n}', at));
    expect(body).toMatch(/process\.exitCode = 1/);
  });
});

describe('#218 — doctor points at repair, and its manual advice is guard-safe', () => {
  const doctorSrc = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'doctor.ts'), 'utf-8');

  it('the permission fix recommends `shieldcortex repair`, not a full install', () => {
    // Find the permission-hardening fix line specifically.
    const idx = doctorSrc.indexOf("(it re-hardens the state tree)");
    expect(idx).toBeGreaterThanOrEqual(0);
    const line = doctorSrc.slice(doctorSrc.lastIndexOf('\n', idx) + 1, doctorSrc.indexOf('\n', idx));
    expect(line).toMatch(/shieldcortex repair/);
  });

  it('the manual one-liner does NOT use a `{…}` brace expansion the guard gates', () => {
    // The touch-approval-store rule fires on the expanded `.shieldcortex/approvals`
    // path — a brace list would make our own printed advice require approval.
    const idx = doctorSrc.indexOf("(it re-hardens the state tree)");
    const line = doctorSrc.slice(doctorSrc.lastIndexOf('\n', idx) + 1, doctorSrc.indexOf('\n', idx));
    expect(line).not.toMatch(/\{audit|approvals,logs\}/);
    expect(line).toMatch(/chmod 700 ~\/\.shieldcortex\/audit/);
  });
});
