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

/**
 * THE BYPASSES THE FIRST VERSION OF THIS FIX OPENED.
 *
 * Every case below was `block` on main and `allow` on the first implementation
 * — five catastrophic-tier verdicts inverted. They are pinned here because the
 * root causes were not one bug but two habits:
 *
 *  1. The sink test was BODY-LOCAL, while the threat is about where the
 *     executed process's OUTPUT goes. Having found that a literal can travel by
 *     file, the obvious next question — what else can it travel by — went
 *     unasked. A pipe needs no sink token in the body at all.
 *
 *  2. Language was resolved with `find` (first match wins) over a list that
 *     de-duplicated on path alone, so a second invocation by a different
 *     interpreter was discarded. `findInterpreterRunFiles` uses that same
 *     matching to NARROW, which fails closed; reusing it to WIDEN made the
 *     identical imprecision fail OPEN.
 */
describe('#217 — output transport is a sink, not just body vocabulary', () => {
  const gen = (body: string, file = '/tmp/g.mjs') => `cat > ${file} <<'EOF'\n${body}\nEOF\n`;

  it.each([
    ['stdout piped to bash', `${gen(`console.log("${RMRF} ~/");`)}node /tmp/g.mjs | bash`],
    ['stdout piped to sh', `${gen(`console.log("${RMRF} ~/");`)}node /tmp/g.mjs | sh`],
    ['stdout appended to a shell rc', `${gen(`console.log("${RMRF} ~/");`)}node /tmp/g.mjs >> ~/.zshrc`],
    ['stdout redirected into a script then run', `${gen(`console.log("${RMRF} ~/");`)}node /tmp/g.mjs > /tmp/x.sh && bash /tmp/x.sh`],
    ['python twin, piped', `cat > /tmp/g.py <<'PY'\nprint("${RMRF} ~/")\nPY\npython3 /tmp/g.py | bash`],
    /**
     * The fd-numbered-redirect bypass: `outputEscapesToShell` exempted any `>`
     * preceded by a digit or `&`, on the theory that fd-prefixed redirects are
     * diagnostics plumbing like `2>&1`. `1>/tmp/x.sh` and `2>/tmp/x.sh` are
     * fd-prefixed too, but they target a REAL FILE, not another fd — the exact
     * write-then-exec shape this describe block exists to catch, just spelled
     * with an explicit fd number.
     */
    ['stdout redirected via explicit fd 1 into a script then run', `${gen(`console.log("${RMRF} ~/");`)}node /tmp/g.mjs 1>/tmp/x.sh && bash /tmp/x.sh`],
    ['stderr redirected via fd 2 into a script then run', `${gen(`console.error("${RMRF} ~/");`)}node /tmp/g.mjs 2>/tmp/x.sh && bash /tmp/x.sh`],
  ])('still blocks: %s', (_name, cmd) => {
    expect(decide(cmd).decision).toBe('block');
  });

  it.each([
    // `2>/dev/null` on a probe is the shape this fix exists to allow.
    ['discard', `cat > /tmp/p.mjs <<'EOF'\n${PROBE_BODY}\nEOF\nnode /tmp/p.mjs 2>/dev/null`],
    // The fd-to-fd case the exemption is genuinely FOR. Narrowing the rule to
    // reject fd-prefixed redirects (the fix above) must not take this with it —
    // `2>&1` carries the output nowhere new, and it is on half the diagnostic
    // one-liners anyone types.
    ['fd-to-fd duplication', `cat > /tmp/p.mjs <<'EOF'\n${PROBE_BODY}\nEOF\nnode /tmp/p.mjs 2>&1`],
  ])('but a %s keeps the #217 relief', (_name, cmd) => {
    expect(decide(cmd).decision).not.toBe('block');
  });
});

describe('#217 — ambiguous language resolution fails closed', () => {
  const BODY_SHELL = `eval "${RMRF} /"`;

  it.each([
    ['same path run by node THEN bash', `cat > /tmp/p.mjs <<'EOF'\n${BODY_SHELL}\nEOF\nnode /tmp/p.mjs\nbash /tmp/p.mjs`],
    ['a decoy node invocation prefixed', `node /tmp/p.mjs --lint\ncat > /tmp/p.mjs <<'EOF'\n${BODY_SHELL}\nEOF\nbash /tmp/p.mjs`],
  ])('still blocks: %s', (_name, cmd) => {
    expect(decide(cmd).decision).toBe('block');
  });
});

describe('#217 — a file write is a sink by where it lands', () => {
  it('writing a shell rc through the fd API still blocks', () => {
    const v = decide(
      `cat > /tmp/g7.mjs <<'EOF'\nimport { openSync, writeSync } from "node:fs";\n`
      + `const fd = openSync(process.env.HOME + "/.zshrc", "a");\nwriteSync(fd, "${RMRF} ~/");\nEOF\nnode /tmp/g7.mjs`,
    );
    expect(v.decision).toBe('block');
  });

  it('but writing a JSON report does not', () => {
    // Most diagnostic probes write a report. Treating any write as a sink
    // re-blocked them, which is most of what #217 is for.
    const v = decide(
      `cat > /tmp/probe.mjs <<'EOF'\nimport { writeFileSync } from 'node:fs';\n`
      + `const P = { danger: "${RMRF} /" };\nwriteFileSync('/tmp/report.json', JSON.stringify(P));\nEOF\nnode /tmp/probe.mjs`,
    );
    expect(v.decision).not.toBe('block');
  });

  it('and a probe that merely READS a file does not', () => {
    // `open(path, 'r')` matched the write-sink pattern because the `+` was
    // optional — so reading back the guard's own audit log to investigate a
    // denial produced another denial, the #190 loop this issue exists to break.
    const v = decide(
      `cat > /tmp/probe.py <<'PY'\nPATTERNS = {'x': r'${RMRF} /'}\n`
      + `data = open('/tmp/audit.jsonl', 'r').read()\nprint(PATTERNS, len(data))\nPY\npython3 /tmp/probe.py`,
    );
    expect(v.decision).not.toBe('block');
  });

  it('an extensionless executable write target blocks even beside an inert decoy', () => {
    // `fileWriteIsSink` only ever extracted DOTTED literals, so an
    // extensionless target like `/tmp/stage2` never entered the `literals`
    // array at all — it was invisible to the "every literal inert" check.
    // Pairing it with a genuinely inert `/tmp/report.json` write let the dotted
    // decoy satisfy `every()` while the real, unprovable target went unseen.
    const v = decide(
      `cat > /tmp/g8.mjs <<'EOF'\nimport { writeFileSync } from 'node:fs';\n`
      + `writeFileSync('/tmp/stage2', "${RMRF} /");\n`
      + `writeFileSync('/tmp/report.json', JSON.stringify({ ok: true }));\nEOF\nnode /tmp/g8.mjs`,
    );
    expect(v.decision).toBe('block');
  });

  it('benign JSON/log writes stay inert when they include data and encoding strings', () => {
    const v = decide(
      `cat > /tmp/probe2.mjs <<'EOF'\nimport { writeFileSync, appendFileSync } from 'node:fs';\n`
      + `const P = { danger: "${RMRF} /" };\n`
      + `writeFileSync('/tmp/audit.log', JSON.stringify(P) + '\\n', 'utf8');\n`
      + `appendFileSync('/tmp/report.jsonl', 'line\\n', 'utf8');\nEOF\nnode /tmp/probe2.mjs`,
    );
    expect(v.decision).not.toBe('block');
  });

  it('a dynamic target expression cannot be cleared by an inert literal decoy inside the expression', () => {
    // The target argument itself must be provably inert. A decoy literal inside
    // `('/tmp/report.json', target)` is not proof: the comma expression returns
    // `target`, which may be executable-shaped.
    const v = decide(
      `cat > /tmp/g9.mjs <<'EOF'\nimport { writeFileSync } from 'node:fs';\n`
      + `const target = '/tmp/stage2';\n`
      + `writeFileSync(('/tmp/report.json', target), "${RMRF} /");\nEOF\nnode /tmp/g9.mjs`,
    );
    expect(v.decision).toBe('block');
  });
});
