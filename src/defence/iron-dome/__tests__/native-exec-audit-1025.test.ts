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
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
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
  readArtifactHeader,
  MAX_PROBE_DIR_ENTRIES,
  MAX_RECORDS_PER_PATH,
  MAX_STORE_ROOT_ENTRIES,
  MAX_MISSING_PARENT_COMPONENTS,
  MAX_RESOLVE_COMPONENTS,
  MAX_RESOLVE_SYMLINKS,
  MAX_SWEEP_DELETIONS,
  createNativeProvenanceBudget,
  NATIVE_PROBE_BUDGET_MS,
  NATIVE_PROVENANCE_RECORD_CAP,
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
    // r4: a catastrophic block is terminal, so the probe is not even asked.
    expect(cat.nativeExec).toBeUndefined();
    expect(cat.wired).toEqual(cat.base);
    const allow = both('./helper --version', agent(H));
    expect(allow.wired.decision).toBe(allow.base.decision);
    expect(allow.nativeExec?.uses.length ?? 0).toBeGreaterThan(0);
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

// -- Fold r2: planted VOLUME in the store must not stall the probe. Before
// the fold the probe read every record-named file for a hash, once per
// candidate spelling, so 50k empty files took a catastrophic deny past the
// hook timeout (a hook that never answers is an allow). ----------------------

/** Spy on every `opendirSync`: how many entries each listing read and
 *  whether its handle was closed. `failAfter`: make `readSync` throw EIO once
 *  that many entries have been read. */
function watchDirs(failAfter?: number) {
  const real = fs.opendirSync.bind(fs);
  const dirs: Array<{ path: string; entries: number; closed: boolean }> = [];
  jest.spyOn(fs, 'opendirSync').mockImplementation(((p: fs.PathLike, o?: fs.OpenDirOptions) => {
    const d = real(p, o);
    const rec = { path: String(p), entries: 0, closed: false };
    dirs.push(rec);
    const read = d.readSync.bind(d);
    const close = d.closeSync.bind(d);
    d.readSync = (() => {
      if (failAfter !== undefined && rec.entries >= failAfter) {
        throw Object.assign(new Error('EIO: injected'), { code: 'EIO' });
      }
      const e = read();
      if (e) rec.entries++;
      return e;
    }) as typeof d.readSync;
    d.closeSync = (() => { rec.closed = true; close(); }) as typeof d.closeSync;
    return d;
  }) as typeof fs.opendirSync);
  return dirs;
}

/** Create `n` EMPTY files named `<prefix><i><suffix>` in `dir`. */
function plantEmpty(dir: string, n: number, name: (i: number) => string): void {
  for (let i = 0; i < n; i++) fs.closeSync(fs.openSync(path.join(dir, name(i)), 'w'));
}

/** Sixteen distinct tokens that all canonicalise to `<cwd>/helper`. */
const SPELLINGS = Array.from({ length: 16 }, (_, i) => `${'./'.repeat(i + 1)}helper`);

describe('#1025 fold r2 — store volume is bounded work, never a stall', () => {
  let root: string;
  let stateDir: string;
  let work: string;
  let dir: string;
  const KEY = 'sc-0123456789abcdef';
  const OTHER = 'sc-fedcba9876543210';

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-volume-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    dir = path.join(stateDir, KEY);
    fs.mkdirSync(work, { recursive: true });
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
  });
  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(root, { recursive: true, force: true });
  });

  const probe = (clock?: () => number) => createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir, home: root, clock });
  const H = () => hashFor(KEY, path.join(work, 'helper'));
  const record = (i: number, kind = 'agent-written') => JSON.stringify({ kind, preId: 'absent', at: i });
  const writeRecords = (hash: string, n: number, body: (i: number) => string = record) => {
    for (let i = 0; i < n; i++) fs.writeFileSync(path.join(dir, `${hash}.${i + 1}.ab`), body(i));
  };

  it('20k empty record-named files + 16 spellings: dangerous-tier decision unchanged, listing capped, no record read', () => {
    writeRecords(H(), 1); // a genuine record the stuffing buries
    plantEmpty(dir, 20_000, (i) => `${H()}.${i}.ff`);
    // r4: a non-terminal verdict, so the probe really runs (a catastrophic
    // block skips it — pinned in the next assertion block).
    const command = ['git push --force origin main', ...SPELLINGS].join(' ; ');
    const base = evaluateToolCall('Bash', { command });
    expect(base.decision).toBe('require_approval');
    const catastrophic = [['rm', '-rf', '~'].join(' '), ...SPELLINGS].join(' ; ');
    let catCalls = 0;
    const cat = evaluateToolCall('Bash', { command: catastrophic }, undefined, {
      nativeArtifactProvenance: () => { catCalls++; return null; },
    });
    expect(cat).toEqual(evaluateToolCall('Bash', { command: catastrophic }));
    expect(cat.decision).toBe('block');
    expect(catCalls).toBe(0);

    const dirs = watchDirs();
    const opens = jest.spyOn(fs, 'openSync');
    const p = probe();
    let calls = 0;
    const counted = (t: string) => { calls++; return p(t); };
    const started = Date.now();
    const wired = evaluateToolCall('Bash', { command }, undefined, { nativeArtifactProvenance: counted });
    const ms = Date.now() - started;

    const { nativeExec, ...rest } = wired;
    expect(rest).toEqual(base);
    expect(nativeExec).toBeUndefined(); // an over-full directory is no evidence
    expect(calls).toBeGreaterThanOrEqual(SPELLINGS.length); // every spelling reached the probe
    expect(dirs).toHaveLength(1); // listed once for the whole call
    expect(dirs[0].entries).toBe(MAX_PROBE_DIR_ENTRIES + 1); // stopped at the overflow sentinel
    expect(dirs[0].closed).toBe(true);
    expect(opens).not.toHaveBeenCalled(); // not one planted file opened
    expect(ms).toBeLessThan(5_000); // generous: the unbounded probe took ~7 s here
  });

  it('listing boundary: exactly MAX_PROBE_DIR_ENTRIES entries is read; one more junk name makes the whole directory no evidence', () => {
    writeRecords(H(), 1);
    plantEmpty(dir, MAX_PROBE_DIR_ENTRIES - 1, (i) => `junk-${i}`);
    expect(probe()('./helper')).toBe('agent-written');
    fs.writeFileSync(path.join(dir, 'one-more-junk'), '');
    const dirs = watchDirs();
    expect(probe()('./helper')).toBeNull();
    expect(dirs[0]).toEqual({ path: dir, entries: MAX_PROBE_DIR_ENTRIES + 1, closed: true });
  });

  it('per-path cap boundary: MAX_RECORDS_PER_PATH records classify; one more makes the WHOLE hash not observed', () => {
    writeRecords(H(), MAX_RECORDS_PER_PATH);
    const opens = jest.spyOn(fs, 'openSync');
    expect(probe()('./helper')).toBe('agent-written');
    expect(opens).toHaveBeenCalledTimes(MAX_RECORDS_PER_PATH + 1); // records + the artifact header

    // One more ENTRY under the hash, even an empty one: not a partial read.
    fs.writeFileSync(path.join(dir, `${H()}.999999.ab`), '');
    opens.mockClear();
    expect(probe()('./helper')).toBeNull();
    expect(opens).not.toHaveBeenCalled();
  });

  it('per-hash memo: 16 spellings cost one read set, for a positive and for a null classification', () => {
    writeRecords(H(), 10);
    const opens = jest.spyOn(fs, 'openSync');
    const p = probe();
    for (const t of SPELLINGS) expect(p(t)).toBe('agent-written');
    expect(opens).toHaveBeenCalledTimes(10 + 1);

    // Records that do not parse: the null is remembered too.
    for (const n of fs.readdirSync(dir)) fs.writeFileSync(path.join(dir, n), '{not json');
    opens.mockClear();
    const q = probe();
    for (const t of SPELLINGS) expect(q(t)).toBeNull();
    expect(opens).toHaveBeenCalledTimes(10);
  });

  it('16 spellings x MAX_RECORDS_PER_PATH empty files: one read set in total', () => {
    plantEmpty(dir, MAX_RECORDS_PER_PATH, (i) => `${H()}.${i}.ab`);
    const lstats = jest.spyOn(fs, 'lstatSync');
    const p = probe();
    for (const t of SPELLINGS) expect(p(t)).toBeNull();
    const recordLstats = lstats.mock.calls.filter(([a]) => String(a).startsWith(`${dir}${path.sep}`));
    expect(recordLstats).toHaveLength(MAX_RECORDS_PER_PATH);
  });

  describe('one budget per probe, shared by every candidate', () => {
    const second = () => {
      fs.writeFileSync(path.join(work, 'other'), ELF_STUB, { mode: 0o755 });
      fs.writeFileSync(path.join(work, 'third'), ELF_STUB, { mode: 0o755 });
      writeRecords(hashFor(KEY, path.join(work, 'other')), 1);
      writeRecords(hashFor(KEY, path.join(work, 'third')), 1);
    };

    it('starts at first use (not creation) and spans distinct candidates; past it, a valid path is null', () => {
      writeRecords(H(), 1);
      second();
      let t = 0;
      const p = probe(() => t);
      t = 10_000; // long after creation: the budget has not started yet
      expect(p('./helper')).toBe('agent-written');
      t = 10_000 + NATIVE_PROBE_BUDGET_MS - 1;
      expect(p('./other')).toBe('agent-written');
      t = 10_000 + NATIVE_PROBE_BUDGET_MS + 1;
      expect(p('./third')).toBeNull();
      // A fresh probe (the next call) has its own budget.
      expect(probe(() => t)('./third')).toBe('agent-written');
    });

    it('is enforced during the listing: the handle is still closed and no record is opened', () => {
      writeRecords(H(), 1);
      let n = 0;
      // Spent at the check before the first directory read (r3: the budget is
      // also checked before the root/session lstats and before the open).
      const clock = () => (n++ < 4 ? 0 : 1_000_000);
      const dirs = watchDirs();
      const opens = jest.spyOn(fs, 'openSync');
      expect(probe(clock)('./helper')).toBeNull();
      expect(dirs).toEqual([{ path: dir, entries: 0, closed: true }]);
      expect(opens).not.toHaveBeenCalled();
    });

    it('is enforced during path resolution', () => {
      writeRecords(H(), 1);
      let t = 0;
      const lstat = fs.lstatSync;
      const native = jest.spyOn(fs.realpathSync, 'native');
      // Store lstats (root, session dir, records) are under stateDir; the
      // resolver's per-component lstats are prefixes of `work`.
      const resolving = (q: unknown) => !String(q).startsWith(stateDir);
      const ls = jest.spyOn(fs, 'lstatSync').mockImplementation(((q: fs.PathLike, o?: fs.StatSyncOptions) => {
        if (resolving(q)) t = 1_000_000; // the first component lookup spends the budget
        return lstat(q, o as fs.StatSyncOptions);
      }) as typeof fs.lstatSync);
      // `a/b/c` does not exist, so resolution walks up one lookup at a time.
      expect(probe(() => t)('./a/b/c/helper')).toBeNull();
      expect(ls.mock.calls.filter(([q]) => resolving(q))).toHaveLength(1);
      expect(native).not.toHaveBeenCalled();
    });

    it('is enforced between record reads', () => {
      writeRecords(H(), 10);
      let t = 0;
      const open = fs.openSync;
      const opens = jest.spyOn(fs, 'openSync').mockImplementation(((...a: Parameters<typeof fs.openSync>) => {
        t = 1_000_000; // the first record read spends the budget
        return open(...a);
      }) as typeof fs.openSync);
      expect(probe(() => t)('./helper')).toBeNull();
      expect(opens).toHaveBeenCalledTimes(1);
    });

    it('is rechecked after a SUCCESSFUL resolution: a spent budget beats a memo hit', () => {
      writeRecords(H(), 1);
      let t = 0;
      const p = probe(() => t);
      expect(p('./helper')).toBe('agent-written'); // classified and memoised in budget
      // A lexically DIFFERENT spelling (r3 memoises same-spelling resolution)
      // that resolves to the same canonical path, so the hash memo is hit.
      fs.symlinkSync(work, path.join(work, 'link'));
      const lstat = fs.lstatSync;
      const readlink = jest.spyOn(fs, 'readlinkSync');
      // The link's absolute target is walked again; the LAST lookup of the
      // resolution (`work` itself, after the readlink) succeeds but spends it.
      const ls = jest.spyOn(fs, 'lstatSync').mockImplementation(((q: fs.PathLike, o?: fs.StatSyncOptions) => {
        const real = lstat(q, o as fs.StatSyncOptions);
        if (readlink.mock.calls.length > 0 && String(q) === work) t = 1_000_000;
        return real;
      }) as typeof fs.lstatSync);
      const opens = jest.spyOn(fs, 'openSync');
      expect(p('./link/helper')).toBeNull(); // same hash, memoised 'agent-written'
      expect(readlink).toHaveBeenCalledTimes(1);
      expect(ls.mock.calls.filter(([q]) => String(q) === work).length).toBe(2);
      expect(opens).not.toHaveBeenCalled();
    });

    it('is rechecked after the artifact header read: the final syscall spending the budget is null', () => {
      writeRecords(H(), 1);
      // Control: the same store, in budget, classifies.
      expect(probe(() => 0)('./helper')).toBe('agent-written');

      let t = 0;
      let n = 0;
      const open = fs.openSync;
      const opens = jest.spyOn(fs, 'openSync').mockImplementation(((...a: Parameters<typeof fs.openSync>) => {
        if (++n === 2) t = 1_000_000; // open 1 is the record, open 2 the artifact header
        return open(...a);
      }) as typeof fs.openSync);
      const p = probe(() => t);
      expect(p('./helper')).toBeNull();
      expect(opens).toHaveBeenCalledTimes(2);
      expect(String(opens.mock.calls[1][0])).toBe(path.join(work, 'helper'));
      // And it stays null: no later spelling reclassifies or reads again.
      expect(p('././helper')).toBeNull();
      expect(opens).toHaveBeenCalledTimes(2);
    });

    it('a clock that throws or returns NaN is a spent budget, never a throw', () => {
      writeRecords(H(), 1);
      expect(probe(() => { throw new Error('clock'); })('./helper')).toBeNull();
      expect(probe(() => Number.NaN)('./helper')).toBeNull();
    });
  });

  it('directory errors: an unreadable listing is null and its handle is closed; an unopenable one is null', () => {
    writeRecords(H(), 1);
    plantEmpty(dir, 10, (i) => `junk-${i}`);
    const dirs = watchDirs(3);
    expect(probe()('./helper')).toBeNull();
    expect(dirs).toEqual([{ path: dir, entries: 3, closed: true }]);
    jest.restoreAllMocks();

    jest.spyOn(fs, 'opendirSync').mockImplementation((() => {
      throw Object.assign(new Error('EACCES: injected'), { code: 'EACCES' });
    }) as typeof fs.opendirSync);
    expect(probe()('./helper')).toBeNull();
    expect(recordNativeArtifactCaptures({ sessionKey: KEY, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir, home: root })).toBe(0);
    expect(pruneNativeProvenance({ stateDir })).toBeNull();
  });

  it('record side: a stuffed session directory is listed to the record cap plus one overflow sentinel and nothing is published', () => {
    const cap = () => recordNativeArtifactCaptures({
      sessionKey: KEY, captures: [{ token: 'new', kind: 'agent-written' }], cwd: work, stateDir, home: root,
    });
    plantEmpty(dir, NATIVE_PROVENANCE_RECORD_CAP - 1, (i) => `junk-${i}`);
    expect(cap()).toBe(1); // one slot left
    expect(cap()).toBe(0); // exactly at the cap

    plantEmpty(dir, 20_000, (i) => `more-${i}`);
    const dirs = watchDirs();
    const started = Date.now();
    expect(cap()).toBe(0);
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(dirs).toEqual([{ path: dir, entries: NATIVE_PROVENANCE_RECORD_CAP + 1, closed: true }]);
  });

  it('record side: a stuffed store root is listed to its cap plus one overflow sentinel; nothing is swept and no NEW session is created, while an existing session keeps recording', () => {
    const stale = path.join(stateDir, 'sc-aaaaaaaaaaaaaaaa');
    fs.mkdirSync(stale);
    makeStale(stale);
    plantEmpty(stateDir, MAX_STORE_ROOT_ENTRIES, (i) => `junk-${i}`);
    const dirs = watchDirs();
    expect(recordNativeArtifactCaptures({
      sessionKey: OTHER, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir, home: root,
    })).toBe(0);
    expect(dirs).toEqual([{ path: stateDir, entries: MAX_STORE_ROOT_ENTRIES + 1, closed: true }]);
    expect(fs.existsSync(stale)).toBe(true); // over-full root: nothing removed
    expect(fs.existsSync(path.join(stateDir, OTHER))).toBe(false);

    // The session that already has its directory never lists the root, so it
    // keeps recording (bounded by its own record cap).
    dirs.length = 0;
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, captures: [{ token: 'helper', kind: 'agent-written' }], cwd: work, stateDir, home: root,
    })).toBe(1);
    expect(dirs).toEqual([{ path: dir, entries: 0, closed: true }]);
    expect(fs.existsSync(stale)).toBe(true);
  });
});

describe('#1025 fold r2 — the store is refused when another uid owns it', () => {
  let root: string;
  let stateDir: string;
  let work: string;
  const KEY = 'sc-0123456789abcdef';
  const NEW = 'sc-fedcba9876543210';
  const HAS_GETUID = typeof process.getuid === 'function';

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-uid-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    fs.mkdirSync(work, { recursive: true });
    fs.mkdirSync(path.join(stateDir, KEY), { recursive: true });
    fs.writeFileSync(path.join(stateDir, KEY, `${hashFor(KEY, path.join(work, 'helper'))}.1.ab`), VALID_RECORD);
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
  });
  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(root, { recursive: true, force: true });
  });

  /** lstat reports `foreign` paths as owned by a different uid. */
  const foreignOwner = (...foreign: string[]) => {
    const real = fs.lstatSync;
    jest.spyOn(fs, 'lstatSync').mockImplementation(((p: fs.PathLike, o?: fs.StatSyncOptions) => {
      const st = real(p, o as never) as fs.Stats;
      if (!foreign.includes(String(p))) return st;
      const fake = Object.create(Object.getPrototypeOf(st)) as fs.Stats;
      return Object.assign(fake, st, { uid: st.uid + 1 });
    }) as typeof fs.lstatSync);
  };
  const probe = () => createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir, home: root });
  const record = (key: string) => recordNativeArtifactCaptures({
    sessionKey: key, captures: [{ token: 'helper2', kind: 'agent-written' }], cwd: work, stateDir, home: root,
  });

  it('control: owned by this uid, the store is read and written', () => {
    expect(probe()('./helper')).toBe('agent-written');
    expect(record(KEY)).toBe(1);
  });

  (HAS_GETUID ? it : it.skip)('another uid owns the ROOT: nothing read, recorded or swept', () => {
    const stale = path.join(stateDir, 'sc-aaaaaaaaaaaaaaaa');
    fs.mkdirSync(stale);
    makeStale(stale);
    foreignOwner(stateDir);
    expect(probe()('./helper')).toBeNull();
    expect(record(KEY)).toBe(0);
    expect(record(NEW)).toBe(0);
    expect(pruneNativeProvenance({ stateDir })).toBeNull();
    expect(fs.existsSync(stale)).toBe(true);
  });

  (HAS_GETUID ? it : it.skip)('another uid owns the SESSION directory: its records are not evidence and nothing is written into it', () => {
    const before = fs.readdirSync(path.join(stateDir, KEY));
    foreignOwner(path.join(stateDir, KEY));
    expect(probe()('./helper')).toBeNull();
    expect(record(KEY)).toBe(0);
    expect(fs.readdirSync(path.join(stateDir, KEY))).toEqual(before);
  });

  (HAS_GETUID ? it : it.skip)('the sweep removes only stale session directories this uid owns', () => {
    const mine = path.join(stateDir, 'sc-aaaaaaaaaaaaaaaa');
    const theirs = path.join(stateDir, 'sc-bbbbbbbbbbbbbbbb');
    for (const d of [mine, theirs]) { fs.mkdirSync(d); makeStale(d); }
    foreignOwner(theirs);
    expect(pruneNativeProvenance({ stateDir })).toBe(1); // KEY is live; theirs is not counted
    expect(fs.existsSync(mine)).toBe(false);
    expect(fs.existsSync(theirs)).toBe(true);
  });

  it('no process.getuid (Windows): ownership is not checked', () => {
    foreignOwner(stateDir, path.join(stateDir, KEY));
    const getuid = Object.getOwnPropertyDescriptor(process, 'getuid');
    Object.defineProperty(process, 'getuid', { value: undefined, configurable: true, writable: true });
    try {
      expect(probe()('./helper')).toBe('agent-written');
      expect(record(KEY)).toBe(1);
    } finally {
      if (getuid) Object.defineProperty(process, 'getuid', getuid);
      else delete (process as { getuid?: unknown }).getuid;
    }
    expect(typeof process.getuid).toBe(HAS_GETUID ? 'function' : 'undefined');
  });
});

describe('#1025 fold r3 — one shared deadline; record and sweep are bounded', () => {
  let root: string;
  let stateDir: string;
  let work: string;
  const KEY = 'sc-0123456789abcdef';
  const DAY = 24 * 60 * 60 * 1000;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-r3-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    fs.mkdirSync(work, { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  });
  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('~600-level deep tree under a catastrophic redirect: decision unchanged, quick; direct record of the deep missing target is bounded', () => {
    // r4: scaled so the tree fits PATH_MAX (macOS 1024) under the tmpdir.
    const DEEP = Math.min(600, Math.floor(((process.platform === 'darwin' ? 1024 : 4096) - work.length - 16) / 2));
    expect(DEEP).toBeGreaterThan(300);
    const deep = path.join(work, ...new Array(DEEP).fill('a'));
    fs.mkdirSync(deep, { recursive: true });
    const target = `${'a/'.repeat(DEEP)}${'b/'.repeat(600)}x`;
    const command = `${['rm', '-rf', '~'].join(' ')} ; echo hi > ${target}`;
    const base = evaluateToolCall('Bash', { command });
    expect(base.decision).toBe('block');
    const budget = createNativeProvenanceBudget();
    const started = Date.now();
    const wired = evaluateToolCall('Bash', { command }, undefined, {
      nativeArtifactProvenance: createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir, home: root, budget }),
    });
    const { nativeExec, ...rest } = wired;
    expect(rest).toEqual(base);
    expect(nativeExec).toBeUndefined();
    // Direct recording of the same target (not merely the block skip): the
    // 600 missing components exceed MAX_MISSING_PARENT_COMPONENTS → null.
    const native = jest.spyOn(fs.realpathSync, 'native');
    const lstats = jest.spyOn(fs, 'lstatSync');
    const n = recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root,
      captures: Array.from({ length: 16 }, (_, i) => ({ token: `${'./'.repeat(i + 1)}${target}`, kind: 'agent-written' as const })),
    });
    expect(n).toBe(0);
    // One resolution (memoised across the 16 spellings), at most cap+1
    // walks, each at most one lstat per component of the deep spelling; the
    // native resolver is never called.
    expect(native).not.toHaveBeenCalled();
    const walked = lstats.mock.calls.filter(([q]) => String(q).startsWith(work)).length;
    expect(walked).toBeGreaterThan(0);
    expect(walked).toBeLessThanOrEqual((MAX_MISSING_PARENT_COMPONENTS + 1) * (DEEP + 2));
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  describe('r4: path resolution is a budget-checked walker, never realpath(3)', () => {
    const FOREVER = () => createNativeProvenanceBudget({ budgetMs: 1e12 });
    const rec = (token: string, budget = FOREVER()) => recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root, budget, captures: [{ token, kind: 'agent-written' }],
    });
    const chain = (n: number) => {
      for (let i = 0; i < n; i++) fs.symlinkSync(i < n - 1 ? `L${i + 1}` : '.', path.join(work, `L${i}`));
    };

    it(`follows up to MAX_RESOLVE_SYMLINKS (${MAX_RESOLVE_SYMLINKS}) links and records`, () => {
      chain(MAX_RESOLVE_SYMLINKS);
      const native = jest.spyOn(fs.realpathSync, 'native');
      const readlink = jest.spyOn(fs, 'readlinkSync');
      expect(rec('L0/x')).toBe(1);
      expect(readlink).toHaveBeenCalledTimes(MAX_RESOLVE_SYMLINKS);
      expect(native).not.toHaveBeenCalled();
    });

    it('one link past the expansion cap is not recorded, even with an unlimited budget; never throws', () => {
      chain(MAX_RESOLVE_SYMLINKS + 1);
      const readlink = jest.spyOn(fs, 'readlinkSync');
      expect(rec('L0/x')).toBe(0);
      expect(readlink).toHaveBeenCalledTimes(MAX_RESOLVE_SYMLINKS);
    });

    it('dot-dot components inside link targets count against MAX_RESOLVE_COMPONENTS (not normalised away)', () => {
      fs.mkdirSync(path.join(work, 'a'));
      const seg = Math.floor(((process.platform === 'darwin' ? 1024 : 4096) - 8) / 5);
      const links = Math.min(MAX_RESOLVE_SYMLINKS, Math.ceil(MAX_RESOLVE_COMPONENTS / (2 * seg)) + 1);
      for (let i = 0; i < links; i++) {
        fs.symlinkSync(`${'a/../'.repeat(seg)}${i < links - 1 ? `L${i + 1}` : '.'}`, path.join(work, `L${i}`));
      }
      const lstats = jest.spyOn(fs, 'lstatSync');
      const readlink = jest.spyOn(fs, 'readlinkSync');
      const started = Date.now();
      const n = rec('L0/x');
      const walked = lstats.mock.calls.filter(([q]) => String(q).startsWith(work)).length;
      if (2 * seg * links > MAX_RESOLVE_COMPONENTS) {
        // The component cap fires before the chain ends: not recorded.
        expect(n).toBe(0);
        expect(readlink.mock.calls.length).toBeLessThan(links);
      }
      expect(walked).toBeLessThanOrEqual(MAX_RESOLVE_COMPONENTS);
      expect(readlink.mock.calls.length).toBeLessThanOrEqual(MAX_RESOLVE_SYMLINKS);
      expect(Date.now() - started).toBeLessThan(2_000);
    });

    it('the deadline is checked before every lstat and readlink: expiry at the link stops before its readlink', () => {
      chain(2);
      let t = 0;
      const budget = createNativeProvenanceBudget({ clock: () => t });
      const lstat = fs.lstatSync;
      jest.spyOn(fs, 'lstatSync').mockImplementation(((q: fs.PathLike, o?: fs.StatSyncOptions) => {
        const st = lstat(q, o as fs.StatSyncOptions);
        if (String(q) === path.join(work, 'L0')) t = 1e12;
        return st;
      }) as typeof fs.lstatSync);
      const readlink = jest.spyOn(fs, 'readlinkSync');
      expect(rec('L0/x', budget)).toBe(0);
      expect(readlink).not.toHaveBeenCalled();
    });
  });

  it('a missing tail of up to MAX_MISSING_PARENT_COMPONENTS is still recorded', () => {
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root,
      captures: [{ token: 'p/q/x', kind: 'compiled-output' }],
    })).toBe(1);
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root,
      captures: [{ token: 'p/q/r/x', kind: 'compiled-output' }],
    })).toBe(0);
  });

  it('dedupe: 16 spellings of one kind → one record; the same path with both kinds keeps both (ambiguous stays honest)', () => {
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root,
      captures: SPELLINGS.map((t) => ({ token: t, kind: 'agent-written' as const })),
    })).toBe(1);
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root,
      captures: [{ token: './y', kind: 'agent-written' }, { token: '././y', kind: 'compiled-output' }],
    })).toBe(2);
  });

  it('planted expired session dir with 20k files: skipped (left whole), call quick; small expired dirs pruned within the shared cap', () => {
    const big = path.join(stateDir, 'sc-ffffffffffffffff');
    fs.mkdirSync(big, { mode: 0o700 });
    plantEmpty(big, 20_000, (i) => `f${i}`);
    const small = ['sc-1111111111111111', 'sc-2222222222222222', 'sc-3333333333333333'].map((k) => path.join(stateDir, k));
    for (const d of small) { fs.mkdirSync(d, { mode: 0o700 }); plantEmpty(d, 100, (i) => `r${i}`); }
    const old = (Date.now() - 3 * DAY) / 1000;
    for (const d of [big, ...small]) fs.utimesSync(d, old, old);
    const unlinks = jest.spyOn(fs, 'unlinkSync');
    const rmdirs = jest.spyOn(fs, 'rmdirSync');
    const rms = jest.spyOn(fs, 'rmSync');
    const started = Date.now();
    expect(pruneNativeProvenance({ stateDir })).toBe(0);
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(rms).not.toHaveBeenCalled(); // never recursive
    expect(unlinks.mock.calls.length + rmdirs.mock.calls.length).toBeLessThanOrEqual(MAX_SWEEP_DELETIONS);
    expect(fs.readdirSync(big)).toHaveLength(20_000); // over-full: left in place, not renamed
    const left = fs.readdirSync(stateDir).filter((n) => n !== 'sc-ffffffffffffffff');
    expect(left).toHaveLength(1); // two 101-deletion dirs fit in 256; the third waits
    // Next sweep takes the rest; the big one still stands.
    expect(pruneNativeProvenance({ stateDir })).toBe(0);
    expect(fs.readdirSync(stateDir)).toEqual(['sc-ffffffffffffffff']);
  });

  it('an expired dir with a nested directory is skipped entirely', () => {
    const d = path.join(stateDir, 'sc-4444444444444444');
    fs.mkdirSync(path.join(d, 'nested'), { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(d, 'r1'), '');
    const old = (Date.now() - 3 * DAY) / 1000;
    fs.utimesSync(d, old, old);
    const unlinks = jest.spyOn(fs, 'unlinkSync');
    expect(pruneNativeProvenance({ stateDir })).toBe(0);
    expect(unlinks).not.toHaveBeenCalled();
    expect(fs.readdirSync(d).sort()).toEqual(['nested', 'r1']);
  });

  it('shared budget: probe spends it → record publishes nothing and touches no fs; latched against a clock that recovers', () => {
    let t = 0;
    const budget = createNativeProvenanceBudget({ clock: () => t });
    const p = createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir, home: root, budget });
    expect(p('./helper')).toBeNull(); // starts the deadline
    t = NATIVE_PROBE_BUDGET_MS + 1;
    expect(budget.expired()).toBe(true);
    t = 0; // a clock that goes back never revives it
    const spies = ['lstatSync', 'mkdirSync', 'opendirSync', 'writeFileSync', 'renameSync', 'statSync', 'realpathSync', 'readlinkSync']
      .map((m) => jest.spyOn(fs, m as 'lstatSync'));
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root, budget,
      captures: [{ token: './y', kind: 'agent-written' }],
    })).toBe(0);
    for (const s of spies) expect(s).not.toHaveBeenCalled();
    expect(pruneNativeProvenance({ stateDir, budget })).toBeNull();
  });

  it('record → sweep share one deadline: expiry during the first-record sweep records nothing', () => {
    let n = 0;
    const budget = createNativeProvenanceBudget({ clock: () => (n++ < 6 ? 0 : 1e9) });
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root, budget,
      captures: [{ token: './y', kind: 'agent-written' }],
    })).toBe(0);
    expect(fs.existsSync(path.join(stateDir, KEY))).toBe(false);
  });

  it('a NaN or throwing clock is an expired budget, never a throw', () => {
    for (const clock of [() => Number.NaN, () => { throw new Error('clock'); }]) {
      const budget = createNativeProvenanceBudget({ clock: clock as () => number });
      expect(recordNativeArtifactCaptures({
        sessionKey: KEY, cwd: work, stateDir, home: root, budget,
        captures: [{ token: './y', kind: 'agent-written' }],
      })).toBe(0);
      expect(pruneNativeProvenance({ stateDir, budget })).toBeNull();
    }
  });

  it('decision parity with a REAL recorded ELF: disabled / enabled (nativeExec present) / expired (absent)', () => {
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root,
      captures: [{ token: './helper', kind: 'agent-written' }],
    })).toBe(1);
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    // r4: a catastrophic block is terminal and is never observed.
    const cases: Array<[string, string, boolean]> = [
      [`${['rm', '-rf', '~'].join(' ')} ; ./helper`, 'block', false],
      ['git push --force origin main ; ./helper', 'require_approval', true],
      ['LD_PRELOAD=./helper /bin/true', 'allow', true],
    ];
    for (const [command, decision, observed] of cases) {
      const base = evaluateToolCall('Bash', { command });
      expect(base.decision).toBe(decision);
      expect(base.nativeExec).toBeUndefined();
      const wire = (budget: ReturnType<typeof createNativeProvenanceBudget>) => evaluateToolCall('Bash', { command }, undefined, {
        nativeArtifactProvenance: createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir, home: root, budget }),
      });
      const enabled = wire(createNativeProvenanceBudget());
      const expiredRun = wire(createNativeProvenanceBudget({ clock: () => Number.NaN }));
      if (observed) {
        expect(enabled.nativeExec).toBeDefined();
        expect(enabled.nativeExec?.uses).toEqual(expect.arrayContaining([expect.objectContaining({ provenance: 'agent-written' })]));
      } else {
        expect(enabled.nativeExec).toBeUndefined();
      }
      expect(expiredRun.nativeExec).toBeUndefined();
      const { nativeExec: _a, ...e } = enabled;
      const { nativeExec: _b, ...x } = expiredRun;
      expect(e).toEqual(base);
      expect(x).toEqual(base);
    }
  });

  it('expiry checkpoints driven by mocked fs ops: write→rename and open→fstat', () => {
    // Publication: the write spends the budget → no rename, record is 0.
    let t = 0;
    const budget = createNativeProvenanceBudget({ clock: () => t });
    const realWrite = fs.writeFileSync;
    jest.spyOn(fs, 'writeFileSync').mockImplementation(((...a: Parameters<typeof fs.writeFileSync>) => {
      realWrite(...a);
      t = 1e9;
    }) as typeof fs.writeFileSync);
    const renames = jest.spyOn(fs, 'renameSync');
    expect(recordNativeArtifactCaptures({
      sessionKey: KEY, cwd: work, stateDir, home: root, budget,
      captures: [{ token: './y', kind: 'agent-written' }],
    })).toBe(0);
    expect(renames).not.toHaveBeenCalled();
    jest.restoreAllMocks();

    // Header read: the open spends the budget → no fstat, null.
    fs.writeFileSync(path.join(work, 'h'), ELF_STUB);
    let u = 0;
    const b2 = createNativeProvenanceBudget({ clock: () => u });
    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((...a: Parameters<typeof fs.openSync>) => {
      const fd = realOpen(...a);
      u = 1e9;
      return fd;
    }) as typeof fs.openSync);
    const fstats = jest.spyOn(fs, 'fstatSync');
    expect(readArtifactHeader(path.join(work, 'h'), () => b2.expired())).toBeNull();
    expect(fstats).not.toHaveBeenCalled();
  });
});

/**
 * #1031 (B2) — `sameCall` is derived from the compile command, not the store,
 * so a `null` from the probe used to become a `sameCall` label even after the
 * call's shared 250 ms budget was spent. The release promise is "after which
 * nothing more is labelled". The evaluator now asks the probe's own budget
 * (`probe.expired()`) before that label. Real budget, real probe, real
 * evaluator; the verdict is the unwired one in every case.
 */
describe('#1031 B2 — sameCall stops at the shared provenance deadline', () => {
  const KEY = 'sc-0123456789abcdef';
  const COMMAND = 'cc main.c -o app && ./app';
  const SAME_CALL = { uses: [{ action: 'exec', provenance: 'compiled-output', sameCall: true }] };
  let root: string;
  let stateDir: string;
  let work: string;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1031-b2-')));
    stateDir = path.join(root, 'state');
    work = path.join(root, 'work');
    fs.mkdirSync(work, { recursive: true });
    fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  });
  afterEach(() => {
    jest.restoreAllMocks();
    fs.rmSync(root, { recursive: true, force: true });
  });

  /** A clock that reads the given ticks in order, then stays on the last. */
  const ticking = (...ticks: number[]) => {
    let n = 0;
    return () => ticks[Math.min(n++, ticks.length - 1)];
  };
  const probeWith = (budget: ReturnType<typeof createNativeProvenanceBudget>) =>
    createNativeArtifactProbe({ sessionKey: KEY, cwd: work, stateDir, home: root, budget });
  const FS_OPS = ['lstatSync', 'statSync', 'opendirSync', 'openSync', 'readSync', 'readdirSync', 'readlinkSync', 'realpathSync', 'mkdirSync', 'writeFileSync', 'renameSync'] as const;

  it('control: a live budget labels the same-call compile-and-run (the path under test is reached)', () => {
    const base = evaluateToolCall('Bash', { command: COMMAND });
    const probe = probeWith(createNativeProvenanceBudget({ clock: () => 0 }));
    const wired = evaluateToolCall('Bash', { command: COMMAND }, undefined, { nativeArtifactProvenance: probe });
    expect(probe.expired()).toBe(false);
    expect(wired.nativeExec).toEqual(SAME_CALL);
    const { nativeExec: _n, ...rest } = wired;
    expect(rest).toEqual(base);
  });

  it('a budget already spent (clock 0 → 251 → 0, latched): no sameCall, verdict identical to unwired, no filesystem call', () => {
    const budget = createNativeProvenanceBudget({ clock: ticking(0, NATIVE_PROBE_BUDGET_MS + 1, 0) });
    expect(budget.expired()).toBe(false); // 0: starts the deadline
    expect(budget.expired()).toBe(true); // 251: past it
    expect(budget.expired()).toBe(true); // 0 again: latched
    const probe = probeWith(budget);
    expect(probe.expired()).toBe(true);
    const base = evaluateToolCall('Bash', { command: COMMAND });
    const spies = FS_OPS.map((m) => jest.spyOn(fs, m as 'lstatSync'));
    const wired = evaluateToolCall('Bash', { command: COMMAND }, undefined, { nativeArtifactProvenance: probe });
    expect(wired.nativeExec).toBeUndefined();
    expect(wired).toEqual(base);
    for (const s of spies) expect(s).not.toHaveBeenCalled();
  });

  it('a budget spent DURING the call (first check at 0, the next at 251): no sameCall', () => {
    const probe = probeWith(createNativeProvenanceBudget({ clock: ticking(0, NATIVE_PROBE_BUDGET_MS + 1) }));
    const base = evaluateToolCall('Bash', { command: COMMAND });
    const wired = evaluateToolCall('Bash', { command: COMMAND }, undefined, { nativeArtifactProvenance: probe });
    expect(probe.expired()).toBe(true);
    expect(wired.nativeExec).toBeUndefined();
    expect(wired).toEqual(base);
  });

  it('a NaN clock, or a probe whose expired() throws, is a spent budget: no sameCall, never a throw', () => {
    const base = evaluateToolCall('Bash', { command: COMMAND });
    const nan = probeWith(createNativeProvenanceBudget({ clock: () => Number.NaN }));
    const throwing = Object.assign((_t: string): NativeArtifactProvenance | null => null, {
      expired: (): boolean => { throw new Error('budget fault'); },
    });
    for (const probe of [nan, throwing]) {
      const wired = evaluateToolCall('Bash', { command: COMMAND }, undefined, { nativeArtifactProvenance: probe });
      expect(wired.nativeExec).toBeUndefined();
      expect(wired).toEqual(base);
    }
  });

  it('a spent budget suppresses the sameCall label only: the decision of a held compile-and-run is unchanged', () => {
    // A require_approval verdict alongside a sameCall candidate: audit-only, so
    // the spent budget may remove the label and nothing else.
    const command = 'git push --force origin main ; cc main.c -o app && ./app';
    const base = evaluateToolCall('Bash', { command });
    expect(base.decision).toBe('require_approval');
    const live = evaluateToolCall('Bash', { command }, undefined, { nativeArtifactProvenance: probeWith(createNativeProvenanceBudget({ clock: () => 0 })) });
    const spent = evaluateToolCall('Bash', { command }, undefined, { nativeArtifactProvenance: probeWith(createNativeProvenanceBudget({ clock: () => Number.NaN })) });
    expect(live.nativeExec).toEqual(SAME_CALL);
    expect(spent.nativeExec).toBeUndefined();
    const { nativeExec: _l, ...l } = live;
    expect(l).toEqual(base);
    expect(spent).toEqual(base);
  });
});
