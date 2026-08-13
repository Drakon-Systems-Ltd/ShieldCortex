import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * Issue #194 — write-then-exec re-armed a heredoc body whenever the written
 * file was NAMED on an interpreter's command line, without checking that the
 * interpreter actually RUNS it.
 *
 * `findInterpreterRunFiles` matched `interpreter … <candidate>` with the
 * candidate anywhere after the interpreter, so `node scripts/run-jest.mjs
 * src/zz.test.ts` counted as executing `src/zz.test.ts`. It does not: jest is
 * the program, the test file is an argument it reads.
 *
 * That is the write-a-test-then-run-it workflow. A fixture containing danger
 * vocabulary — which is what a security tool's tests are made of — was hard
 * blocked at the CATASTROPHIC tier, where there is no prompt and no appeal, and
 * where `enforce: false` does not help. It blocked this repo's own
 * investigation of a neighbouring FP twice inside ten minutes.
 *
 * Program position is defined once, in `detectScriptInvocations`; the fix
 * reuses it instead of keeping a second, wider definition.
 */

// Bait assembled at runtime so this file is not itself scanner-bait.
const C = ['c', 'u', 'r', 'l'].join('');
const RMRF = ['r', 'm', ' ', '-', 'r', 'f'].join('');

/** A fixture body of the shape a guard's own corpus is made of. */
const BODY = `const CMDS = ['git log -p | grep -E "${RMRF}|${C}.*sh"'];`;
const write = (target: string): string => `cd /repo && cat > ${target} <<'EOF'\n${BODY}\nEOF`;

const decide = (command: string) => evaluateToolCall('Bash', { command }, undefined, undefined);

describe('#194 — naming a file is not running it', () => {
  it.each([
    ['jest names the test file', `${write('src/zz.test.ts')}\nnode scripts/run-jest.mjs src/zz.test.ts`],
    ['pytest names the test file', `${write('tests/test_x.py')}\npython3 -m pytest tests/test_x.py`],
    ['runner does not name it', `${write('src/zz.test.ts')}\nnode scripts/run-jest.mjs`],
    ['no interpreter at all', `${write('src/zz.test.ts')}\ngit add src/zz.test.ts`],
    ['read back with cat', `${write('src/zz.test.ts')}\ncat src/zz.test.ts`],
  ])('the body stays inert: %s', (_name, cmd) => {
    const v = decide(cmd);
    expect(v.decision).toBe('allow');
    expect(v.signals).not.toContain('recursive-force-delete');
    expect(v.signals).not.toContain('pipe-download-to-shell');
  });

  it.each([
    ['run directly', `${write('/tmp/p.sh')}\nbash /tmp/p.sh`],
    ['run by relative path', `${write('p.sh')}\nbash ./p.sh`],
    ['sourced', `${write('p.sh')}\n. p.sh`],
    ['nested inside bash -c', `${write('/tmp/p.sh')}\nbash -c 'bash /tmp/p.sh'`],
  ])('a genuine write-then-exec still blocks: %s', (_name, cmd) => {
    expect(decide(cmd).decision).toBe('block');
  });

  /**
   * SUPERSEDED BY #217, DELIBERATELY.
   *
   * This case previously sat in the block list above: writing a body and
   * running it with `python3` was treated as write-then-exec, and the body was
   * scanned with SHELL rules. #217 reports that as a precision defect, and it
   * is the same one #188 already fixed for folded script source — a shell verb
   * in interpreter CODE position is an identifier, and its vocabulary is only
   * live if it can reach an exec sink.
   *
   * A SHELL target is unaffected and still blocks (the four cases above): that
   * body really is the source of a command. What changed is only the non-shell
   * target, and only when it is provably sink-free.
   *
   * The dangerous twin is pinned directly beneath, so the relaxation cannot
   * widen past "no way to reach a process".
   */
  it('a sink-free body run by a non-shell interpreter is data, not command (#217)', () => {
    const v = decide(`${write('/tmp/p.py')}\npython3 /tmp/p.py`);
    expect(v.decision).toBe('allow');
    expect(v.signals).not.toContain('recursive-force-delete');
  });

  it.each([
    ['python with a process sink', `cd /repo && cat > /tmp/s.py <<'EOF'\nimport os\nos.system("${RMRF} /")\nEOF\npython3 /tmp/s.py`],
    ['node with a process sink', `cd /repo && cat > /tmp/s.mjs <<'EOF'\nimport { execSync } from 'node:child_process';\nexecSync("${RMRF} /");\nEOF\nnode /tmp/s.mjs`],
    ['node that WRITES a shell script then runs it', `cd /repo && cat > /tmp/g.mjs <<'EOF'\nimport { writeFileSync } from 'node:fs';\nwriteFileSync('/tmp/g.sh', '${RMRF} /');\nEOF\nnode /tmp/g.mjs && bash /tmp/g.sh`],
  ])('but a body that can reach a process still blocks: %s', (_name, cmd) => {
    expect(decide(cmd).decision).toBe('block');
  });

  it('an interpreter-consumed heredoc is untouched by any of this', () => {
    // `bash <<'EOF' … EOF` executes its body directly — never inert.
    const v = decide(`bash <<'EOF'\n${RMRF} / --no-preserve-root\nEOF`);
    expect(v.decision).toBe('block');
  });
});
