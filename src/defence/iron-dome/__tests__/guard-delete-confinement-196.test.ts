/**
 * #196 — #170's delete-confinement exemption must not launder an unconfined
 * delete.
 *
 * #170 made danger a property of the TARGET rather than the verb, which is the
 * right principle and fixed the largest measured source of denied honest work.
 * But it is the one change on that branch that WIDENS what the guard permits,
 * and a wrong relaxation fails in the quiet direction: it reads as nothing at
 * all until something is deleted. Both defects pinned here were fail-open and
 * both were found by reading the relaxation before it shipped, not by its own
 * tests passing.
 *
 * The unconfined target below is `/etc/foo` on purpose. It trips
 * `recursive-force-delete` only, not the target-aware `delete-root-or-home`,
 * so each case isolates the exemption from the rule #170 deliberately left
 * alone. A probe against `/` would pass for the wrong reason.
 *
 * Both directions are pinned in this file. Tightening work that only asserts
 * "this is blocked again" is how a relaxation quietly dies and the false
 * positives come back.
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/** Assembled at runtime so the fixtures are not attack-shaped literals on disk. */
const RMRF = ['rm', '-rf'].join(' ');
const SYSTEM_TARGET = ['/', 'etc', '/', 'foo'].join('');

function verdict(command: string) {
  return evaluateToolCall('Bash', { command });
}

describe('#196 — the confinement exemption cannot be laundered', () => {
  it('an unconfined recursive delete is still catastrophic', () => {
    expect(verdict(`${RMRF} ${SYSTEM_TARGET}`).decision).toBe('block');
  });

  it('a confined recursive delete is still ordinary work (#170 relief holds)', () => {
    expect(verdict(`${RMRF} dist`).decision).toBe('allow');
    expect(verdict(`cd dashboard && ${RMRF} .next && npm run build`).decision).toBe('allow');
  });

  it('H1 — a scan that truncates never exempts what it could not read', () => {
    const filler = Array.from({ length: 70 }, (_, i) => `${RMRF} build${i}`).join(' && ');
    expect(verdict(`${filler} && ${RMRF} ${SYSTEM_TARGET}`).decision).toBe('block');
  });

  it('H2 — a command substitution is command position, and is examined', () => {
    expect(verdict(`${RMRF} dist && out=$(${RMRF} ${SYSTEM_TARGET})`).decision).toBe('block');
    expect(verdict(`(${RMRF} ${SYSTEM_TARGET})`).decision).toBe('block');
  });

  it('an rm the splitter cannot account for keeps the gate for the whole line', () => {
    const v = verdict(`${RMRF} dist && find . -name "*.log" -exec ${RMRF} {} +`);
    expect(v.decision).not.toBe('allow');
  });

  it('`rm` inside a path or identifier costs the exemption nothing', () => {
    expect(verdict(`${RMRF} build/rm-cache`).decision).toBe('allow');
    expect(verdict(`${RMRF} src/rm/generated`).decision).toBe('allow');
  });
});
