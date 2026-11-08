/**
 * #1025 — AUDIT-ONLY native-exec provenance signal, through the PURE
 * evaluator with a test-owned provenance probe, plus the fs store against
 * real files under a test-owned directory.
 *
 * The invariant every test here pins: wiring the probe NEVER changes the
 * verdict. The only difference it may make is an optional `nativeExec`
 * field. No DENY, no HOLD, no severity change, no new signal.
 *
 * The command shapes are the frozen #907 PR 1 (93810414) review set — the r1
 * B1-B6, r2 N1-N5, r3 B1-B5 and r4 rows, and Case-Drakon's B1-B3 on 956c76f9
 * and 93810414 — re-pinned as audit-signal tests. They are evaluated as
 * strings only; no payload is executed, and no fixture is a runnable image
 * (the "native" files are a 64-byte ELF magic stub).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  evaluateToolCall,
  nativeArtifactCaptures,
  type ToolGuardOptions,
  type ToolGuardVerdict,
} from '../tool-action-guard.js';
import {
  canonicalTarget,
  classifyNativeProvenance,
  createNativeArtifactProbe,
  isNativeImageHeader,
  pruneNativeProvenance,
  recordNativeArtifactCaptures,
  rulePProducer,
  type NativeArtifactProvenance,
  type NativeArtifactRecord,
} from '../native-exec-provenance.js';

const WORK = '/work/proj';
const ELF_STUB = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...new Array(56).fill(0)]);

/** A test-owned probe: absolute path → provenance. Relative tokens resolve
 *  against WORK, exactly as the real probe resolves against the call cwd. */
function probeFor(known: Record<string, NativeArtifactProvenance>): (token: string) => NativeArtifactProvenance | null {
  return (token: string) => {
    const abs = token.startsWith('/') ? path.posix.normalize(token) : path.posix.normalize(`${WORK}/${token}`);
    return known[abs] ?? null;
  };
}

/** Evaluate once unwired and once wired. The wired verdict minus `nativeExec`
 *  must EQUAL the unwired one — decision, severity, signals, reason, all. */
function both(command: string, known: Record<string, NativeArtifactProvenance>, extra: ToolGuardOptions = {}) {
  const args = { command };
  const base = evaluateToolCall('Bash', args, undefined, Object.keys(extra).length ? extra : undefined);
  const wired = evaluateToolCall('Bash', args, undefined, { ...extra, nativeArtifactProvenance: probeFor(known) });
  const { nativeExec, ...rest } = wired;
  expect(rest).toEqual(base);
  expect(wired.decision).toBe(base.decision);
  expect(wired.severity).toBe(base.severity);
  return { base, wired, nativeExec };
}

const actions = (v: ToolGuardVerdict['nativeExec']) => (v?.uses ?? []).map(u => u.action).sort();
const agent = (...paths: string[]) => Object.fromEntries(paths.map(p => [p, 'agent-written' as const]));
const H = `${WORK}/helper`;
const BIN_H = `${WORK}/bin/helper`;
const SUB_H = `${WORK}/sub/helper`;
const LIB = `${WORK}/lib.so`;

describe('#1025 the field is observation only', () => {
  it('no probe wired → no field, verdict identical to today', () => {
    const v = evaluateToolCall('Bash', { command: './helper' });
    expect(v.nativeExec).toBeUndefined();
  });

  it('a probe that throws is "not observed", never an evaluation error', () => {
    const v = evaluateToolCall('Bash', { command: './helper' }, undefined, {
      nativeArtifactProvenance: () => { throw new Error('boom'); },
    });
    expect(v.nativeExec).toBeUndefined();
    expect(v).toEqual(evaluateToolCall('Bash', { command: './helper' }));
  });

  it('a probe returning junk is ignored', () => {
    const v = evaluateToolCall('Bash', { command: './helper' }, undefined, {
      nativeArtifactProvenance: (() => 'deny') as unknown as ToolGuardOptions['nativeArtifactProvenance'],
    });
    expect(v.nativeExec).toBeUndefined();
  });

  it('the field carries enums only — no path text', () => {
    const { nativeExec } = both('./helper; LD_PRELOAD=./lib.so /bin/true', agent(H, LIB));
    expect(JSON.stringify(nativeExec)).not.toMatch(/helper|lib\.so|work/);
  });

  it('a decision the guard already makes is left exactly as it is (catastrophic stays catastrophic, allow stays allow)', () => {
    const cat = both('./helper && rm -rf /', agent(H));
    expect(cat.wired.decision).toBe('block');
    expect(cat.nativeExec?.uses.length ?? 0).toBeGreaterThan(0);
    const allow = both('./helper --version', agent(H));
    expect(allow.wired.decision).toBe(allow.base.decision);
  });
});

describe('#1025 acceptance rows (frozen §8 a/b/c), audit-only', () => {
  it('(a) agent-written native bytes, separate exec → exec/agent-written, decision unchanged', () => {
    const { nativeExec } = both('./helper', agent(H));
    expect(nativeExec).toEqual({ uses: [{ action: 'exec', provenance: 'agent-written' }] });
  });

  it('(b) compile then separate exec → exec/compiled-output (Q1 = AUDIT), decision unchanged', () => {
    const { nativeExec } = both('./helper', { [H]: 'compiled-output' });
    expect(nativeExec).toEqual({ uses: [{ action: 'exec', provenance: 'compiled-output' }] });
  });

  it('(c) LD_PRELOAD of an agent-written library → load/agent-written, decision unchanged', () => {
    const { nativeExec } = both('LD_PRELOAD=./lib.so /bin/true', agent(LIB));
    expect(nativeExec).toEqual({ uses: [{ action: 'load', provenance: 'agent-written' }] });
  });

  it('ambiguous provenance (same pre-state, two kinds) is recorded as ambiguous, never escalated', () => {
    const { nativeExec } = both('./helper', { [H]: 'ambiguous' });
    expect(nativeExec).toEqual({ uses: [{ action: 'exec', provenance: 'ambiguous' }] });
  });

  it('unknown provenance (no record) → no field: current behaviour', () => {
    expect(both('./helper', {}).nativeExec).toBeUndefined();
    expect(both('/usr/bin/ls', {}).nativeExec).toBeUndefined();
  });
});

describe('#1025 same-call compile then run (no store needed, header not inspected)', () => {
  it.each([
    'cc a.c -o helper && ./helper',
    'gcc -O2 -o helper a.c; ./helper',
    'clang a.c -ohelper && ./helper',
    'gcc a.c && ./a.out',
    'go build -o helper . && ./helper',
    'cc a.c -o out/helper && out/helper',
  ])('%j → exec/compiled-output sameCall', (cmd) => {
    const { nativeExec } = both(cmd, {});
    expect(nativeExec?.uses).toContainEqual({ action: 'exec', provenance: 'compiled-output', sameCall: true });
  });

  it('an object-only compile does not claim a runnable output', () => {
    expect(both('cc -c a.c -o a.o && ./helper', {}).nativeExec).toBeUndefined();
  });

  it('sameCall is prospective: statement order and whether the compile ran are not modelled', () => {
    // The output is named from the compile command; no header is read and
    // nothing proves the compile (or the run) happened.
    for (const cmd of ['./helper; cc a.c -o helper', 'false && cc a.c -o helper; ./helper']) {
      expect(both(cmd, {}).nativeExec).toEqual({ uses: [{ action: 'exec', provenance: 'compiled-output', sameCall: true }] });
    }
  });

  it('a fresh redirect target run in the same call is NOT claimed (usually a script)', () => {
    expect(both("printf 'x' > helper && chmod +x helper && ./helper", {}).nativeExec).toBeUndefined();
  });
});

describe('#1025 loader paths (frozen r4 lane-1 / Case non-blocking load misses)', () => {
  it.each([
    'export LD_PRELOAD=./lib.so; ls',
    'declare -x LD_PRELOAD=./lib.so; ls',
    'LD_PRELOAD=./lib.so env echo hi',
    'env LD_PRELOAD=./lib.so /bin/echo hi',
    'DYLD_INSERT_LIBRARIES=./lib.so /bin/ls',
    'LD_AUDIT=./lib.so /bin/ls',
    'LD_PRELOAD=/usr/lib/libc.so.6:./lib.so /bin/ls',
    `python3 -c "import ctypes; ctypes.CDLL('./lib.so')"`,
    `node -e "process.dlopen(module, './lib.so')"`,
    `ruby -e "require 'fiddle'; Fiddle.dlopen('./lib.so')"`,
    'f() { :; }; LD_PRELOAD=./lib.so f',
    'export LD_PRELOAD=./lib.so; f() { :; }; f',
    'export LD_PRELOAD=./lib.so; false && unset LD_PRELOAD; /usr/bin/true',
    'export LD_PRELOAD=./lib.so; (unset LD_PRELOAD); /usr/bin/true',
    'cd() { true; }; cd /tmp && LD_PRELOAD=./lib.so /bin/ls',
    // r4: `set +a` that does not run, or runs only in a subshell, leaves
    // allexport on, so the plain assignment is still exported.
    'set -a; LD_PRELOAD=./lib.so; false && set +a; /usr/bin/true',
    'set -a; LD_PRELOAD=./lib.so; (set +a); /usr/bin/true',
    'set -o allexport; LD_PRELOAD=./lib.so; if false; then set +a; fi; /usr/bin/true',
  ])('%j → load/agent-written, decision unchanged', (cmd) => {
    const { nativeExec } = both(cmd, agent(LIB));
    expect(nativeExec?.uses).toContainEqual({ action: 'load', provenance: 'agent-written' });
  });

  it('builtin-only and unexported preloads may still be logged: over-reporting a load is the safe side', () => {
    for (const cmd of ['LD_PRELOAD=./lib.so echo hi', 'LD_PRELOAD=./lib.so', 'export -n LD_PRELOAD=./lib.so; ls']) {
      const { nativeExec } = both(cmd, agent(LIB));
      for (const u of nativeExec?.uses ?? []) expect(['load', 'reference']).toContain(u.action);
    }
  });
});

describe('#1025 frozen r1 B1 — a wrapper / interpreter NAME addressed by path', () => {
  const names = ['python3', 'node', 'bash', 'env', 'timeout', 'sudo'];
  const known = agent(...names.map(n => `${WORK}/${n}`));
  it.each([
    './python3', "./python3 -c 'print(1)'", './node ./x.js', './bash ./run.sh', './env ls',
    './timeout 5 ls', './sudo true', 'sudo ./python3', 'timeout 5 ./python3 -V', 'env FOO=1 ./python3',
  ])('%j → exec/agent-written', (cmd) => {
    expect(both(cmd, known).nativeExec?.uses).toContainEqual({ action: 'exec', provenance: 'agent-written' });
  });

  it('a native file handed to an interpreter as its script is named, not claimed as exec', () => {
    for (const cmd of ['python3 ./helper', 'bash ./helper', 'sh -e ./helper', 'node ./helper']) {
      expect(actions(both(cmd, agent(H)).nativeExec)).toEqual(['reference']);
    }
  });
});

describe('#1025 frozen r1 B2 — path spellings of one target', () => {
  it.each([
    ['bin/helper', BIN_H],
    ['./bin/helper', BIN_H],
    [BIN_H, BIN_H],
    ['cd bin && ./helper', BIN_H],
    ['node_modules/.bin/tool', `${WORK}/node_modules/.bin/tool`],
    ['LD_PRELOAD=lib/libx.so /bin/true', `${WORK}/lib/libx.so`],
  ])('%j reaches %s', (cmd, target) => {
    expect(both(cmd, agent(target)).nativeExec?.uses.length ?? 0).toBeGreaterThan(0);
  });

  it('`$PWD/bin/helper` (runtime-built path) is a documented residual: not observed, decision unchanged', () => {
    expect(both('$PWD/bin/helper', agent(BIN_H)).nativeExec).toBeUndefined();
  });
});

describe('#1025 frozen r1 B3 — use versus mention', () => {
  const known = agent(H, BIN_H);
  it.each([
    'make && ./helper', 'true; ./helper', 'true\n./helper', '(./helper)', '{ ./helper; }',
    'echo $(./helper)', 'echo "$(./helper)"', 'echo `./helper`', 'diff <(./helper) expected.txt',
    "bash -c './helper'", "sh -c 'cd bin && ./helper'", 'eval ./helper', "bash <<'EOF'\n./helper\nEOF",
    "cat <<'EOF' | sh\n./helper\nEOF", 'cat <<EOF\n$(./helper)\nEOF', '2>/dev/null ./helper',
    './helper > out.txt 2>&1', 'nohup ./helper >/dev/null 2>&1 &', 'if ./helper; then echo ok; fi',
    'while ./helper; do break; done', 'X=1 ./helper', 'export LD_PRELOAD=./helper; ls',
    "echo 'not this' # but\n./helper",
  ])('real use %j is observed; decision unchanged', (cmd) => {
    expect(both(cmd, known).nativeExec?.uses.length ?? 0).toBeGreaterThan(0);
  });

  it.each([
    "cat <<'EOF'\n./helper\nLD_PRELOAD=./helper ls\nEOF",
    "tee notes.md <<'EOF' >/dev/null\n./helper\nEOF",
    "printf '%s\\n' ./helper",
    'ls # ./helper',
    '# ./helper\nls',
    "grep -n './helper' notes.md",
    'command -v ./helper',
    'python3 - <<\'PY\'\nprint("./helper")\nPY',
  ])('mention %j is at most a `reference`, never claimed as exec or load', (cmd) => {
    for (const u of both(cmd, known).nativeExec?.uses ?? []) expect(u.action).toBe('reference');
  });

  it('every mention shape leaves the decision unchanged (the label may be wrong; the verdict never moves)', () => {
    for (const cmd of [
      'cat <<EOF\n./helper\nbin/helper --flag\nEOF',
      'echo "first line\n./helper\nlast"',
      'git commit -m "fix helper\n\n./helper now built by make"',
      'files=(./helper bin/helper); echo "${files[@]}"',
    ]) both(cmd, known);
  });

  it('documented over-capture: a compiler in a multi-line quoted message may mint an inert record', () => {
    // The fail-safe statement splitter splits inside quotes. The record only
    // matters if `helper` later becomes a native image it did not pre-date.
    const caps = nativeArtifactCaptures('Bash', { command: 'git commit -m "build\ncc helper.c -o helper"' });
    for (const c of caps) expect(c.kind).toBe('compiled-output');
  });

  it.each([
    "cat <<'EOF'\ncc helper.c -o helper\nEOF",
    "echo 'cc helper.c -o helper'",
    '# cc helper.c -o helper',
  ])('a compiler only MENTIONED in %j mints no compile capture', (cmd) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd }).filter(c => c.kind === 'compiled-output')).toEqual([]);
  });

  it.each([
    ['make && cc helper.c -o helper', 'helper'],
    ["bash -c 'cc helper.c -o out/helper'", 'out/helper'],
    ['x=$(cc helper.c -o helper)', 'helper'],
  ])('a compiler actually run in %j is captured', (cmd, out) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd })).toContainEqual({ token: out, kind: 'compiled-output' });
  });
});

describe('#1025 Case-Drakon B1 (956c76f9 + 93810414) — non-literal eval / SHELL -c program', () => {
  it.each([
    'eval "$(echo ./helper)"',
    'eval $(echo ./helper)',
    'bash -c "$(echo ./helper)"',
    'sh -c "$(echo ./helper)"',
    'eval "$(printf %s ./helper)"',
  ])('%j → observed (as a reference at least), decision unchanged', (cmd) => {
    expect(both(cmd, agent(H)).nativeExec?.uses.length ?? 0).toBeGreaterThan(0);
  });

  it('a fully computed name is a documented residual: not observed, decision unchanged', () => {
    expect(both('eval "$(echo .)/helper"', agent(H)).nativeExec).toBeUndefined();
  });

  it('bare PATH name (no `/`) is a documented residual', () => {
    expect(both('helper', agent(H)).nativeExec).toBeUndefined();
  });
});

describe('#1025 Case-Drakon B2/B3 + frozen r1 B4 / r2 N1-N2 / r3 B1-B2 — row D (executable memory) is out of scope', () => {
  // Strings only; never run. Row D was a separate #907 floor; #1025's
  // acceptance list is exec / compile / load, so these pin that the wired
  // probe adds nothing and changes nothing.
  it.each([
    "node -e 'console.log(`${ 1 /* } */ + mmap(PROT_EXEC) }`)'",
    "node -e 'console.log(`${ /}/ + mmap(PROT_EXEC) }`)'",
    "node -e 'console.log(`${ 1 // }\n + mmap(PROT_EXEC) }`)'",
    // Case B3: a valid nested f-string. Shell double quotes, so `\"` reaches
    // Python as `"` and the inner single quotes are literal.
    String.raw`python3 -c "import mmap; print(f\"{f'{mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)}'}\")"`,
    `python3 -c 'import mmap; mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)'`,
    `python3 -c "print('mmap PROT_EXEC')"`,
    'grep -rn "mmap PROT_EXEC" docs/',
    `python3 -c '# inert${String.fromCharCode(13)}import mmap; mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)'`,
  ])('%j → decision unchanged, no nativeExec', (cmd) => {
    expect(both(cmd, agent(H)).nativeExec).toBeUndefined();
  });

  it.each([
    ['python3 ./fstr.py'], ['node ./t.mjs'],
    // Case B2 folded: block comment, regex literal, line comment.
    ['node ./b2-comment.mjs'], ['node ./b2-regex.mjs'], ['node ./b2-line.mjs'],
    // Case B3 folded: valid nested f-string.
    ['python3 ./b3.py'],
  ])('folded script body %j leaves the decision unchanged, no nativeExec', (cmd) => {
    const src: Record<string, string> = {
      'fstr.py': `import mmap\nprint(f"{len('}') + bool(mmap.mmap(-1,4096,prot=mmap.PROT_EXEC))}")\n`,
      't.mjs': 'console.log(`${"}" + mmap(PROT_EXEC)}`)\n',
      'b2-comment.mjs': 'console.log(`${ 1 /* } */ + mmap(PROT_EXEC) }`)\n',
      'b2-regex.mjs': 'console.log(`${ /}/ + mmap(PROT_EXEC) }`)\n',
      'b2-line.mjs': 'console.log(`${ 1 // }\n + mmap(PROT_EXEC) }`)\n',
      'b3.py': `import mmap\nprint(f"{f'{mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)}'}")\n`,
    };
    const resolveScriptSource = (p: string) => src[path.basename(p)] ?? null;
    expect(both(cmd, agent(H), { resolveScriptSource }).nativeExec).toBeUndefined();
  });
});

describe('#1025 frozen r2 N5 / B1, r3 B4 — directory shapes', () => {
  it.each([
    'false && cd sub; ./helper', 'cd sub; ./helper', 'cd . || true; ./helper', 'cd /no/such/dir || ./helper',
    'pushd . && ./helper', 'timeout 1 cd /tmp && ./helper', '(cd sub); ./helper', 'cd sub & ./helper',
    'f() { cd sub; }; f; ./helper', 'cd "$X" || true; ./helper', 'cd() { :; }; cd sub && ./helper',
    'function cd { true; }; cd /tmp && ./helper',
  ])('%j → ./helper in the call cwd is observed', (cmd) => {
    expect(both(cmd, agent(H)).nativeExec?.uses).toContainEqual({ action: 'exec', provenance: 'agent-written' });
  });

  it.each([
    'cd sub && ./helper', 'cd sub && make && ./helper', 'command cd sub && ./helper', 'pushd sub && ./helper',
    'if true; then cd sub; fi; ./helper', 'cd sub\n./helper', 'eval cd sub; ./helper',
    // a function NAMED eval whose body changes directory (bash non-POSIX mode
    // runs the function, so ./helper resolves under sub/)
    'eval() { cd sub; }; eval; ./helper',
  ])('%j → sub/helper (literal cd) is observed', (cmd) => {
    expect(both(cmd, agent(SUB_H)).nativeExec?.uses).toContainEqual({ action: 'exec', provenance: 'agent-written' });
  });

  it.each(['cd - && ./helper', 'cd "$DIR" && ./helper', 'CDPATH=/opt cd sub && ./helper'])(
    '%j with only an unnamed directory holding the image: residual, decision unchanged', (cmd) => {
      both(cmd, agent('/opt/sub/helper'));
    },
  );

  it('compile captures follow literal cd too (over-capture is harmless under Rule P)', () => {
    const toks = nativeArtifactCaptures('Bash', { command: 'cd out && cc a.c -o app' }).map(c => c.token).sort();
    expect(toks).toEqual(['app', 'out/app']);
  });
});

describe('#1025 frozen r2 N4 / r3 B5 / r2 N3 — heredocs, continuations, syntax roles', () => {
  it.each([
    'cat <<EOF\nhi\nEOF\n./helper', "cat <<'EOF'\nhi\nEOF\n./helper", 'cat <<-EOF\n\thi\n\tEOF\n./helper',
    'x=$(cat <<EOF\nhi\nEOF)\n./helper', 'cat <<EO\\\nF\nhi\nEOF\n./helper', "cat <<'EOF'\nhi\nEO\\\nF\nEOF\n./helper",
    // continued CLOSING delimiter: unquoted body joins `EO\<nl>F` into `EOF`
    'cat <<EOF\nhi\nEO\\\nF\n./helper',
    'f() { ./helper; }; f', 'function g { ./helper; }; g', 'case x in x) ./helper;; esac',
    'case $(./helper) in x) echo;; esac', 'f() { ./helper; }; export -f f; bash -c f',
  ])('%j → observed, decision unchanged', (cmd) => {
    expect(both(cmd, agent(H)).nativeExec?.uses.length ?? 0).toBeGreaterThan(0);
  });

  it('definitions and patterns that run nothing still never move the decision', () => {
    for (const cmd of [
      'f() { ./helper; }', 'f() { ./helper; }; echo defined', 'case x in ./helper) echo hi;; esac',
      'f() { ./helper; }\ncase x in\n./helper) echo hi;;\nesac',
    ]) both(cmd, agent(H));
  });
});

describe('#1025 captures', () => {
  const cap = (toolName: string, args: Record<string, unknown>) => nativeArtifactCaptures(toolName, args);
  it('write-family tool path → agent-written, any extension', () => {
    expect(cap('Write', { file_path: '/w/helper', content: 'x' })).toEqual([{ token: '/w/helper', kind: 'agent-written' }]);
    expect(cap('Edit', { file_path: '/w/lib.so', old_string: 'a', new_string: 'b' })).toEqual([{ token: '/w/lib.so', kind: 'agent-written' }]);
  });
  it.each([
    ["printf '\\x7fELF' > helper", 'helper'],
    ['base64 -d payload.b64 >> ./helper', './helper'],
    ['echo AAAA | base64 -d | tee helper > /dev/null', 'helper'],
    ['dd if=blob of=helper bs=1', 'helper'],
    ['curl -sSL -o helper https://example.invalid/x', 'helper'],
    ['curl --output=helper https://example.invalid/x', 'helper'],
    ['wget -O helper https://example.invalid/x', 'helper'],
    ['xxd -r -p hex.txt 1>helper', 'helper'],
  ])('shell write %j → agent-written %s', (cmd, token) => {
    expect(cap('Bash', { command: cmd })).toContainEqual({ token, kind: 'agent-written' });
  });
  it('an oversized command is neither captured nor observed (bounded hot path)', () => {
    const big = `cc a.c -o helper && ./helper # ${'x'.repeat(60_000)}`;
    expect(cap('Bash', { command: big })).toEqual([]);
    expect(both(big, agent(H)).nativeExec).toBeUndefined();
  });
  it('fd duplications, /dev/* and runtime-built targets are not captured', () => {
    expect(cap('Bash', { command: 'ls 2>&1 >/dev/null' })).toEqual([]);
    expect(cap('Bash', { command: 'echo x > "$OUT"' })).toEqual([]);
  });
});

// -- Pure provenance core -----------------------------------------------------

describe('#1025 Rule P and classification (pure)', () => {
  const id = (ino: number) => ({ dev: 1, ino, size: 64, mtimeMs: 1000 + ino });
  const rec = (kind: NativeArtifactRecord['kind'], preId: NativeArtifactRecord['preId'], at: number): NativeArtifactRecord => ({ kind, preId, at });

  it('a record whose pre-state still equals the file did not produce it (failed write) → no signal', () => {
    expect(rulePProducer([rec('agent-written', id(5), 1)], id(5))).toBeNull();
  });
  it('the newest differing record is the producer', () => {
    expect(rulePProducer([rec('compiled-output', 'absent', 1), rec('agent-written', id(4), 2)], id(5))).toBe('agent-written');
  });
  it('same pre-state, different kinds → ambiguous', () => {
    expect(rulePProducer([rec('agent-written', id(4), 1), rec('compiled-output', id(4), 2)], id(5))).toBe('ambiguous');
  });
  it('an unknown pre-state (failed capture stat) is not evidence of a change', () => {
    expect(rulePProducer([rec('agent-written', 'unknown', 1)], id(5))).toBeNull();
    expect(rulePProducer([rec('compiled-output', 'unknown', 1), rec('agent-written', 'unknown', 2)], id(5))).toBeNull();
    expect(classifyNativeProvenance([rec('agent-written', 'unknown', 1)], id(5), ELF_STUB)).toBeNull();
    // a later unknown of another kind may be the producer → no attribution
    expect(rulePProducer([rec('agent-written', 'absent', 1), rec('compiled-output', 'unknown', 2)], id(5))).toBeNull();
    // ... one of the same kind, or an older one, does not change the answer
    expect(rulePProducer([rec('agent-written', 'absent', 1), rec('agent-written', 'unknown', 2)], id(5))).toBe('agent-written');
    expect(rulePProducer([rec('compiled-output', 'unknown', 1), rec('agent-written', 'absent', 2)], id(5))).toBe('agent-written');
  });

  it('an unknown-only record set yields no nativeExec through the evaluator, decision unchanged', () => {
    const records = [rec('agent-written', 'unknown', 1)];
    const probe = () => classifyNativeProvenance(records, id(5), ELF_STUB);
    for (const command of ['./helper', 'LD_PRELOAD=./lib.so /bin/true', './helper && rm -rf /']) {
      const base = evaluateToolCall('Bash', { command });
      const wired = evaluateToolCall('Bash', { command }, undefined, { nativeArtifactProvenance: probe });
      expect(wired.nativeExec).toBeUndefined();
      expect(wired).toEqual(base);
    }
  });

  it('a script / data header is never a native observation', () => {
    const txt = new TextEncoder().encode('#!/bin/sh\necho hi\n');
    expect(classifyNativeProvenance([rec('agent-written', 'absent', 1)], id(5), txt)).toBeNull();
    expect(classifyNativeProvenance([rec('agent-written', 'absent', 1)], id(5), ELF_STUB)).toBe('agent-written');
    expect(classifyNativeProvenance([rec('agent-written', 'absent', 1)], 'absent', ELF_STUB)).toBeNull();
    expect(classifyNativeProvenance([], id(5), ELF_STUB)).toBeNull();
  });
  it('native magic: ELF, Mach-O, fat, PE', () => {
    for (const m of [[0x7f, 0x45, 0x4c, 0x46], [0xcf, 0xfa, 0xed, 0xfe], [0xca, 0xfe, 0xba, 0xbe], [0x4d, 0x5a, 0, 0]]) {
      expect(isNativeImageHeader(new Uint8Array(m))).toBe(true);
    }
    expect(isNativeImageHeader(new Uint8Array([0x23, 0x21, 0x2f, 0x62]))).toBe(false);
  });
  it('canonicalTarget: relative with no usable cwd is unresolvable (no process.cwd() fallback)', () => {
    expect(canonicalTarget('helper', undefined, '/home/t', (p) => p)).toBeNull();
    expect(canonicalTarget('./helper', '/w', '/home/t', (p) => p)).toBe('/w/helper');
    expect(canonicalTarget('~/x', '/w', '/home/t', (p) => p)).toBe('/home/t/x');
  });
});

// -- fs store (real files under a test-owned directory) ------------------------

describe('#1025 fs store', () => {
  let root: string;
  let stateDir: string;
  let work: string;
  const KEY = 'sc-0123456789abcdef';

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-store-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    fs.mkdirSync(work, { recursive: true });
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const record = (token: string, kind: 'agent-written' | 'compiled-output', key = KEY) =>
    recordNativeArtifactCaptures({ sessionKey: key, captures: [{ token, kind }], cwd: work, stateDir, home: root });
  const probe = (key = KEY) => createNativeArtifactProbe({ sessionKey: key, cwd: work, stateDir, home: root });

  it('write recorded, bytes land, later probe → agent-written; every spelling agrees', () => {
    expect(record('helper', 'agent-written')).toBe(1);
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    const p = probe();
    expect(p('./helper')).toBe('agent-written');
    expect(p('helper')).toBe('agent-written');
    expect(p(path.join(work, 'helper'))).toBe('agent-written');
  });

  it('the stored record holds no path text', () => {
    record('secret-dir-name/helper', 'agent-written');
    const dir = path.join(stateDir, KEY);
    for (const n of fs.readdirSync(dir)) {
      expect(n).not.toMatch(/secret|helper/);
      expect(fs.readFileSync(path.join(dir, n), 'utf8')).not.toMatch(/secret|helper/);
    }
  });

  it('failed write (file unchanged since the record) → not observed', () => {
    fs.writeFileSync(path.join(work, 'tool'), ELF_STUB, { mode: 0o755 });
    record('tool', 'agent-written');
    expect(probe()('./tool')).toBeNull();
  });

  it('a script written by the agent is not a native observation', () => {
    record('run.sh', 'agent-written');
    fs.writeFileSync(path.join(work, 'run.sh'), '#!/bin/sh\necho hi\n', { mode: 0o755 });
    expect(probe()('./run.sh')).toBeNull();
  });

  it('another session does not see this session\'s records', () => {
    record('helper', 'agent-written');
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    expect(probe('sc-fedcba9876543210')('./helper')).toBeNull();
  });

  it('a malformed session key records nothing and observes nothing (no path escape)', () => {
    expect(record('helper', 'agent-written', '../escape')).toBe(0);
    expect(fs.existsSync(path.join(root, 'escape'))).toBe(false);
    expect(probe('../escape')('./helper')).toBeNull();
  });

  it('an unwritable store records nothing and never throws', () => {
    fs.writeFileSync(stateDir, 'not a directory');
    expect(record('helper', 'agent-written')).toBe(0);
    expect(probe()('./helper')).toBeNull();
  });

  it('a damaged record is ignored, never thrown', () => {
    record('helper', 'agent-written');
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    const dir = path.join(stateDir, KEY);
    for (const n of fs.readdirSync(dir)) fs.writeFileSync(path.join(dir, n), '{not json');
    expect(probe()('./helper')).toBeNull();
  });

  it('prune sweeps expired sessions and leaves every name it did not create', () => {
    record('helper', 'agent-written');
    fs.mkdirSync(path.join(stateDir, 'junk'));
    fs.writeFileSync(path.join(stateDir, 'junk', 'keep.txt'), 'keep');
    pruneNativeProvenance({ stateDir, now: Date.now() + 2 * 24 * 60 * 60 * 1000 });
    expect(fs.readdirSync(stateDir)).toEqual(['junk']);
    expect(fs.readFileSync(path.join(stateDir, 'junk', 'keep.txt'), 'utf8')).toBe('keep');
  });

  it('end to end through the evaluator: Write → bytes land → exec is observed; decision unchanged', () => {
    const caps = nativeArtifactCaptures('Write', { file_path: path.join(work, 'helper'), content: 'x' });
    recordNativeArtifactCaptures({ sessionKey: KEY, captures: caps, cwd: work, stateDir, home: root });
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    const base = evaluateToolCall('Bash', { command: './helper' });
    const v = evaluateToolCall('Bash', { command: './helper' }, undefined, { nativeArtifactProvenance: probe() });
    const { nativeExec, ...rest } = v;
    expect(rest).toEqual(base);
    expect(nativeExec).toEqual({ uses: [{ action: 'exec', provenance: 'agent-written' }] });
  });

  it('end to end: compile capture → later exec → compiled-output', () => {
    const caps = nativeArtifactCaptures('Bash', { command: 'cc main.c -o app' });
    recordNativeArtifactCaptures({ sessionKey: KEY, captures: caps, cwd: work, stateDir, home: root });
    fs.writeFileSync(path.join(work, 'app'), ELF_STUB, { mode: 0o755 });
    const v = evaluateToolCall('Bash', { command: './app' }, undefined, { nativeArtifactProvenance: probe() });
    expect(v.nativeExec).toEqual({ uses: [{ action: 'exec', provenance: 'compiled-output' }] });
  });
});

// -- Fold r1: the store is agent-reachable, so it must never block, follow a
// planted link, or delete what it did not create. ---------------------------

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const DIST_STORE = path.join(REPO, 'dist', 'defence', 'iron-dome', 'native-exec-provenance.js');
const DAY_MS = 24 * 60 * 60 * 1000;

/** The record file name prefix the store uses for `canonical` in `key`. */
const hashFor = (key: string, canonical: string) => createHmac('sha256', key).update(canonical).digest('hex');
const VALID_RECORD = JSON.stringify({ kind: 'agent-written', preId: 'absent', at: 1 });

/** Every entry under `dir` — lstat, so a link is listed and never followed —
 *  with file bodies and directory mtimes, so "nothing was touched" is exact. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string, rel: string) => {
    for (const n of fs.readdirSync(d).sort()) {
      const p = path.join(d, n);
      const r = rel ? `${rel}/${n}` : n;
      const st = fs.lstatSync(p);
      if (st.isSymbolicLink()) out.push(`${r} -> ${fs.readlinkSync(p)}`);
      else if (st.isDirectory()) { out.push(`${r}/ @${st.mtimeMs}`); walk(p, r); }
      else if (st.isFile()) out.push(`${r} = ${fs.readFileSync(p, 'utf8')}`);
      else out.push(`${r} (special)`);
    }
  };
  walk(dir, '');
  return out;
}

function makeStale(p: string): void {
  const old = new Date(Date.now() - 3 * DAY_MS);
  fs.utimesSync(p, old, old);
}

describe('#1025 fold r1 — planted links and non-regular entries in the store', () => {
  let root: string;
  let stateDir: string;
  let work: string;
  let victim: string;
  const KEY = 'sc-0123456789abcdef';
  const OTHER = 'sc-fedcba9876543210';
  const DECOY = 'sc-00000000000000aa';

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-fold-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    victim = path.join(root, 'victim');
    fs.mkdirSync(work, { recursive: true });
    fs.mkdirSync(path.join(victim, 'precious-dir'), { recursive: true });
    fs.writeFileSync(path.join(victim, 'precious-dir', 'keep.txt'), 'keep');
    // A stale, session-looking directory: the one name the sweep may remove
    // from the REAL store, so it must survive when the store is a link.
    fs.mkdirSync(path.join(victim, DECOY));
    fs.writeFileSync(path.join(victim, DECOY, 'keep.txt'), 'keep');
    makeStale(path.join(victim, DECOY));
    makeStale(path.join(victim, 'precious-dir'));
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const record = (key = KEY, extra: { maxSessions?: number } = {}) => recordNativeArtifactCaptures({
    sessionKey: key, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir, home: root, ...extra,
  });
  const probe = (key = KEY) => createNativeArtifactProbe({ sessionKey: key, cwd: work, stateDir, home: root });
  const helperHash = () => hashFor(KEY, path.join(work, 'helper'));

  it('store root symlinked to another tree: record, sweep and probe do nothing through it', () => {
    fs.symlinkSync(victim, stateDir);
    const before = snapshot(victim);
    expect(record()).toBe(0);
    pruneNativeProvenance({ stateDir });
    pruneNativeProvenance({ stateDir, now: Date.now() + 2 * DAY_MS });
    expect(snapshot(victim)).toEqual(before);
    expect(fs.lstatSync(stateDir).isSymbolicLink()).toBe(true);

    // A valid record reachable only through the link is not evidence.
    fs.mkdirSync(path.join(victim, KEY));
    fs.writeFileSync(path.join(victim, KEY, `${helperHash()}.1.ab`), VALID_RECORD);
    expect(probe()('./helper')).toBeNull();
  });

  it('store root symlinked, named with a trailing separator: record, sweep and probe still refuse it', () => {
    // lstat('link/') resolves the link, so the root must be checked as a
    // normalised lexical path, not as the caller spelled it.
    fs.symlinkSync(victim, stateDir);
    fs.mkdirSync(path.join(victim, KEY));
    fs.writeFileSync(path.join(victim, KEY, `${helperHash()}.1.ab`), VALID_RECORD);
    const before = snapshot(victim);
    for (const sd of [`${stateDir}${path.sep}`, `${stateDir}${path.sep}${path.sep}`, `${stateDir}${path.sep}.${path.sep}`]) {
      expect(recordNativeArtifactCaptures({
        sessionKey: OTHER, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir: sd, home: root,
      })).toBe(0);
      expect(recordNativeArtifactCaptures({
        sessionKey: KEY, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir: sd, home: root,
      })).toBe(0);
      expect(pruneNativeProvenance({ stateDir: sd })).toBeNull();
      expect(pruneNativeProvenance({ stateDir: sd, now: Date.now() + 2 * DAY_MS })).toBeNull();
      expect(createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir: sd, home: root })('./helper')).toBeNull();
    }
    expect(snapshot(victim)).toEqual(before);
    expect(fs.lstatSync(stateDir).isSymbolicLink()).toBe(true);
  });

  it('a REAL store root named with a trailing separator still records and is probed', () => {
    const sd = `${stateDir}${path.sep}`;
    fs.rmSync(path.join(work, 'helper'));
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir: sd, home: root,
    })).toBe(1);
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    expect(createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir: sd, home: root })('./helper')).toBe('agent-written');
    expect(pruneNativeProvenance({ stateDir: sd })).toBe(1);
  });

  it('a session directory symlinked elsewhere: nothing written or read through it; the sweep leaves link and target', () => {
    fs.mkdirSync(stateDir);
    const target = path.join(victim, 'session-target');
    fs.mkdirSync(target);
    fs.writeFileSync(path.join(target, `${helperHash()}.1.ab`), VALID_RECORD);
    makeStale(target);
    fs.symlinkSync(target, path.join(stateDir, KEY));
    const before = snapshot(victim);
    expect(record()).toBe(0);
    expect(probe()('./helper')).toBeNull();
    pruneNativeProvenance({ stateDir, now: Date.now() + 2 * DAY_MS });
    expect(snapshot(victim)).toEqual(before);
    expect(fs.lstatSync(path.join(stateDir, KEY)).isSymbolicLink()).toBe(true);
  });

  it('the sweep removes only stale REAL session directories; other names, links, files and fresh sessions stay', () => {
    fs.mkdirSync(stateDir);
    const mk = (name: string, stale: boolean) => {
      fs.mkdirSync(path.join(stateDir, name));
      fs.writeFileSync(path.join(stateDir, name, 'x'), 'x');
      if (stale) makeStale(path.join(stateDir, name));
    };
    mk('sc-aaaaaaaaaaaaaaaa', true); // stale session: swept
    mk('sc-bbbbbbbbbbbbbbbb', false); // fresh session: kept
    mk('junk', true); // not a session name: kept, however old
    mk('sc-short', true);
    fs.writeFileSync(path.join(stateDir, 'sc-cccccccccccccccc'), 'a file, not a session');
    fs.symlinkSync(path.join(victim, DECOY), path.join(stateDir, 'sc-dddddddddddddddd'));
    const victimBefore = snapshot(victim);
    const live = pruneNativeProvenance({ stateDir });
    expect(fs.readdirSync(stateDir).sort()).toEqual(['junk', 'sc-bbbbbbbbbbbbbbbb', 'sc-cccccccccccccccc', 'sc-dddddddddddddddd', 'sc-short']);
    expect(live).toBe(1);
    expect(snapshot(victim)).toEqual(victimBefore);
  });

  it('at the session cap a NEW session goes unrecorded; no existing session is evicted for room', () => {
    expect(record(KEY, { maxSessions: 1 })).toBe(1);
    expect(record(OTHER, { maxSessions: 1 })).toBe(0);
    expect(fs.readdirSync(stateDir)).toEqual([KEY]);
    // The existing session keeps recording.
    expect(record(KEY, { maxSessions: 1 })).toBe(1);
  });

  it('record-named entries that are links, directories or oversized are not evidence', () => {
    const dir = path.join(stateDir, KEY);
    fs.mkdirSync(dir, { recursive: true });
    const H = helperHash();
    const outside = path.join(root, 'outside-record.json');
    fs.writeFileSync(outside, VALID_RECORD);
    fs.symlinkSync(outside, path.join(dir, `${H}.1.aa`));
    fs.mkdirSync(path.join(dir, `${H}.2.bb`));
    fs.writeFileSync(path.join(dir, `${H}.3.cc`), VALID_RECORD + ' '.repeat(64 * 1024));
    expect(probe()('./helper')).toBeNull();
    // Sanity: a regular, small record beside them is still read.
    fs.writeFileSync(path.join(dir, `${H}.4.dd`), VALID_RECORD);
    expect(probe()('./helper')).toBe('agent-written');
  });
});

/** Run the BUILT probe in a child with a hard timeout, so a regression to a
 *  blocking open fails this test instead of hanging Jest. */
function probeInChild(opts: { sessionKey: string; cwd: string; stateDir: string; home: string }, token: string) {
  const script = 'import(process.argv[1]).then((m) => {'
    + ' const p = m.createNativeArtifactProbe(JSON.parse(process.argv[2]));'
    + ' process.stdout.write(JSON.stringify({ r: p(process.argv[3]) })); });';
  const started = Date.now();
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script, pathToFileURL(DIST_STORE).href, JSON.stringify(opts), token], {
    encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL',
  });
  return { ...r, ms: Date.now() - started };
}

/** Whether a `mkfifo` executable can be started at all. Run with no operands
 *  (prints usage, creates nothing) and a timeout; only "not found" counts as
 *  unavailable, so a broken mkfifo still runs, and fails, the tests below. */
const HAS_MKFIFO = process.platform !== 'win32'
  && (spawnSync('mkfifo', [], { stdio: 'ignore', timeout: 5000 }).error as NodeJS.ErrnoException | undefined)?.code !== 'ENOENT';

(HAS_MKFIFO ? describe : describe.skip)('#1025 fold r1 — a FIFO in the store never parks the probe (POSIX: mkfifo)', () => {
  let root: string;
  let stateDir: string;
  let work: string;
  const KEY = 'sc-0123456789abcdef';

  beforeEach(() => {
    expect(fs.existsSync(DIST_STORE)).toBe(true); // `node scripts/run-jest.mjs` builds dist first
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-fifo-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    fs.mkdirSync(work, { recursive: true });
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const opts = () => ({ sessionKey: KEY, cwd: work, stateDir, home: root });
  const mkfifo = (p: string) => {
    const r = spawnSync('mkfifo', [p], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
    expect({ error: r.error?.message, status: r.status, stderr: r.stderr }).toEqual({ error: undefined, status: 0, stderr: '' });
  };
  const expectPrompt = (r: ReturnType<typeof probeInChild>, expected: unknown) => {
    expect({ error: r.error?.message, signal: r.signal, status: r.status, stderr: r.stderr }).toEqual({ error: undefined, signal: null, status: 0, stderr: '' });
    expect(JSON.parse(r.stdout)).toEqual({ r: expected });
  };

  it('a FIFO named like a record (same path hash) is skipped; the real record beside it is still read', () => {
    const dir = path.join(stateDir, KEY);
    fs.mkdirSync(dir, { recursive: true });
    const H = hashFor(KEY, path.join(work, 'helper'));
    fs.writeFileSync(path.join(dir, `${H}.1.aa`), VALID_RECORD);
    mkfifo(path.join(dir, `${H}.9.ffffff`));
    expectPrompt(probeInChild(opts(), './helper'), 'agent-written');
  }, 30_000);

  it('a FIFO as the probed artifact, as the session directory, or as the store root is "not observed", promptly', () => {
    const dir = path.join(stateDir, KEY);
    fs.mkdirSync(dir, { recursive: true });
    mkfifo(path.join(work, 'pipe'));
    fs.writeFileSync(path.join(dir, `${hashFor(KEY, path.join(work, 'pipe'))}.1.aa`), VALID_RECORD);
    expectPrompt(probeInChild(opts(), './pipe'), null);

    fs.rmSync(dir, { recursive: true });
    mkfifo(dir);
    expectPrompt(probeInChild(opts(), './helper'), null);

    fs.rmSync(stateDir, { recursive: true });
    mkfifo(stateDir);
    expectPrompt(probeInChild(opts(), './helper'), null);
  }, 30_000);
});
