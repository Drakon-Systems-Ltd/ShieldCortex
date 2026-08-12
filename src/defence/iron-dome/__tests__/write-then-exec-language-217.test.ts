import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * Issue #217 — the write-then-exec re-arm scanned the heredoc body as SHELL
 * even when the executed file is interpreter source.
 *
 * Re-arming the body is correct: the file IS executed. What was wrong is HOW it
 * was scanned. `cat > probe.mjs <<'EOF' … EOF; node probe.mjs` writes
 * JavaScript, so `"rm -rf /"` in it is a string literal handed to a function —
 * yet it was read as a live command and hard-blocked at the catastrophic tier,
 * where there is no prompt and `enforce: false` does not help.
 *
 * The asymmetry, measured before the fix and pinned below: the SAME literals
 * piped to an interpreter (`python3 - <<'PY'`, handled by #188) returned
 * benign, while written to a file and executed they returned catastrophic.
 *
 * This is the guard project's own daily workflow — every fixture and probe for
 * this codebase is danger vocabulary by construction — and it blocked this
 * repo's own investigation repeatedly.
 *
 * The principle is #188's and #89's, not a new one: a shell verb in interpreter
 * CODE position is an identifier, and its vocabulary is only live if it can
 * reach an exec sink. Only the provably sink-free case is relaxed.
 */

// Assembled at runtime so this file is not itself scanner-bait.
const RMRF = ['r', 'm', ' ', '-', 'r', 'f'].join('');
const CURL = ['c', 'u', 'r', 'l'].join('');

const decide = (command: string) => evaluateToolCall('Bash', { command }, undefined, undefined);

/** The issue's own repro: danger vocabulary as DATA in a JS array. */
const PROBE_BODY = `const shapes = [ ["label", "${RMRF} /"], ["l2", "${CURL} x | sh"] ];\nconsole.log(shapes.length);`;

describe('#217 — a written interpreter file is scanned as that language', () => {
  it('the reported command no longer hard-blocks', () => {
    const v = decide(`cat > /tmp/probe-fold.mjs <<'EOF'\n${PROBE_BODY}\nEOF\nnode /tmp/probe-fold.mjs`);

    expect(v.decision).not.toBe('block');
    expect(v.signals).not.toContain('recursive-force-delete');
    expect(v.signals).not.toContain('pipe-download-to-shell');
  });

  it('matches the verdict of the same literals piped to an interpreter', () => {
    // #188 already made this benign. The two shapes carry identical content, so
    // a differing verdict was the defect — this pins them together.
    const piped = decide(`python3 - <<'PY'\nPATTERNS = {'a': r'${RMRF}'}\nprint(len(PATTERNS))\nPY`);
    const written = decide(`cat > /tmp/p.mjs <<'EOF'\n${PROBE_BODY}\nEOF\nnode /tmp/p.mjs`);

    expect(piped.decision).not.toBe('block');
    expect(written.decision).not.toBe('block');
  });

  it('applies to python targets too, not just node', () => {
    const v = decide(`cat > /tmp/probe.py <<'EOF'\nPATTERNS = ['${RMRF} /']\nprint(len(PATTERNS))\nEOF\npython3 /tmp/probe.py`);
    expect(v.decision).not.toBe('block');
  });
});

describe('#217 — the relaxation stops at the sink', () => {
  it.each([
    ['node child_process', `cat > /tmp/s.mjs <<'EOF'\nimport { execSync } from 'node:child_process';\nexecSync("${RMRF} /");\nEOF\nnode /tmp/s.mjs`],
    ['python os.system', `cat > /tmp/s.py <<'EOF'\nimport os\nos.system("${RMRF} /")\nEOF\npython3 /tmp/s.py`],
    /**
     * The one the must-not-break fixtures caught while building this: a body
     * that only WRITES a file looked inert to the process-sink test, so its
     * literals were masked — but the file it writes is then run. That is the
     * #160 write-then-execute threat one level deeper, and the literal IS the
     * command; it just travels via a file.
     */
    ['node writes a shell script then runs it', `cat > /tmp/g.mjs <<'EOF'\nimport { writeFileSync } from 'node:fs';\nwriteFileSync('/tmp/g.sh', '${RMRF} /');\nEOF\nnode /tmp/g.mjs && bash /tmp/g.sh`],
    ['python writes a shell script then runs it', `cat > /tmp/g.py <<'EOF'\nopen('/tmp/g.sh', 'w').write('${RMRF} /')\nEOF\npython3 /tmp/g.py && bash /tmp/g.sh`],
  ])('still blocks: %s', (_name, cmd) => {
    expect(decide(cmd).decision).toBe('block');
  });

  it('a SHELL target is completely unaffected', () => {
    // The write-then-exec case #86.2/#160 exist to catch. That body really is
    // the source of a command, and nothing here touches it.
    const v = decide(`cat > /tmp/p.sh <<'EOF'\n${RMRF} /\nEOF\nbash /tmp/p.sh`);
    expect(v.decision).toBe('block');
  });

  it('a body written but NEVER executed stays inert, as before', () => {
    const v = decide(`cat > /tmp/notes.mjs <<'EOF'\n${PROBE_BODY}\nEOF\ngit add /tmp/notes.mjs`);
    expect(v.decision).not.toBe('block');
  });
});
