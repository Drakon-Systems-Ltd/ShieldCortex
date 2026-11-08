/**
 * #907 PR 1 — the native-exec-of-agent-artifact floor, its door and its audit
 * row, through the PURE evaluator with a test-owned ledger view, stat and
 * header (design docs/design/907-native-exec-of-agent-artifact.md §3, §4, §8).
 *
 * Every injected callback here is test-owned: the evaluator receives a bound
 * view, a stat and a header reader exactly as the hook / interceptor supply
 * them. No production test switch. The fs store is exercised against real
 * files at the bottom.
 *
 * Q1 (owner, 8 Nov 2026) = AUDIT: row B is an allow carrying
 * `exec-of-agent-compiled-artifact`, never a hold or a deny.
 */
import { describe, expect, it, afterEach } from '@jest/globals';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { evaluateToolCall, nativeArtifactCaptures } from '../tool-action-guard.js';
import {
  canonicalTarget,
  classifyArtifactState,
  rulePProducer,
  type AgentArtifactRecord,
  type AgentArtifactView,
  type ContentId,
  type LedgerEntry,
  type PreId,
  type RecordKind,
} from '../agent-artifact-provenance.js';
import {
  buildArtifactView,
  readArtifactHeader,
  recordArtifactCapture,
  statContentId,
} from '../agent-artifact-store.js';

const UMBRELLA = 'native-exec-of-agent-artifact';
const SIG_A = 'exec-agent-written-native-bytes';
const SIG_C = 'load-agent-written-native-object';
const SIG_D = 'map-exec-agent-written-memory';
const SIG_B = 'exec-of-agent-compiled-artifact';
const SIG_J = 'unclassified-executable';

const ELF = new Uint8Array([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
const TEXT = new TextEncoder().encode('#!/bin/sh\necho hi\n');

const HOME = '/home/tester';
const WORK = '/work/proj';
const INSTALL_TOOL = `${WORK}/node_modules/.bin/tool`; // INSTALLED_BIN_DIR_RE arm
const LOCAL_BIN_TOOL = `${HOME}/.local/bin/tool`; // `~/.local/bin` under the pinned home

// -- A test-owned world: files + one session's record directory --------------

interface FakeFile { id: ContentId; header: Uint8Array }

class World {
  files = new Map<string, FakeFile>();
  recs: LedgerEntry[] = [];
  listable = true;
  keyed = true;
  cap: number | undefined;
  relistOverride: (() => string[] | null) | undefined;
  /** test-owned hook run inside statPath, BEFORE the stat (interleaving). */
  onStat: ((p: string) => void) | undefined;
  private ino = 100;
  private seq = 0;

  hash(p: string): string {
    return createHash('sha256').update(p).digest('hex');
  }
  put(p: string, header: Uint8Array): ContentId {
    const id: ContentId = { dev: 1, ino: ++this.ino, size: header.length, mtimeMs: 1000 + this.ino };
    this.files.set(p, { id, header });
    return id;
  }
  idOf(p: string): PreId {
    return this.files.get(p)?.id ?? 'absent';
  }
  record(p: string, kind: RecordKind, preId: PreId = this.idOf(p)): void {
    const at = 1_000_000 + ++this.seq;
    const body: AgentArtifactRecord = { kind, preId, at };
    this.recs.push({ name: `${this.hash(p)}.${at}.${(this.seq).toString(16).padStart(4, '0')}`, body });
  }
  damaged(p: string): void {
    const at = 1_000_000 + ++this.seq;
    this.recs.push({ name: `${this.hash(p)}.${at}.abcd`, body: null });
  }
  tmp(p: string): void {
    const at = 1_000_000 + ++this.seq;
    this.recs.push({ name: `${this.hash(p)}.${at}.abcd.tmp`, body: null });
  }
  unresolved(): void {
    const at = 1_000_000 + ++this.seq;
    this.recs.push({ name: `unresolved.${at}.abcd`, body: null });
  }
  view(): AgentArtifactView {
    const snapshot = this.recs.map((e) => ({ ...e }));
    return {
      listable: this.listable,
      entries: snapshot,
      relist: this.relistOverride ?? (() => this.recs.map((e) => e.name)),
      canonical: (token, cwd) => canonicalTarget(token, cwd, HOME, (p) => p),
      pathHash: (c) => this.hash(c),
      cap: this.cap,
      keyed: this.keyed,
    };
  }
  check(command: string, extra: Record<string, unknown> = {}) {
    return evaluateToolCall('Bash', { command }, undefined, {
      artifactView: this.keyed ? this.view() : { ...this.view(), keyed: false, listable: false },
      statPath: (p) => {
        this.onStat?.(p);
        return this.files.get(p)?.id ?? 'absent';
      },
      readFileHeader: (p) => this.files.get(p)?.header ?? null,
      cwd: WORK,
      ...extra,
    });
  }
}

const isFloor = (v: { decision: string; signals: string[] }, sig: string) =>
  v.decision === 'block' && v.signals.includes(UMBRELLA) && v.signals.includes(sig);
const isDoor = (v: { decision: string; signals: string[] }) =>
  v.decision === 'require_approval' && v.signals.includes(SIG_J) && !v.signals.includes(UMBRELLA);
const touchesNative = (v: { signals: string[] }) =>
  [UMBRELLA, SIG_A, SIG_B, SIG_C, SIG_J].some((s) => v.signals.includes(s));

// -- §8 acceptance rows -------------------------------------------------------

describe('#907 acceptance rows (evaluator, injected view)', () => {
  it('(a) write creates native bytes, separate exec → DENY exec-agent-written-native-bytes', () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written'); // preId absent
    w.put(`${WORK}/helper`, ELF);
    const v = w.check('./helper');
    expect(isFloor(v, SIG_A)).toBe(true);
    expect(v.severity).toBe('catastrophic');
    expect(v.reason).toMatch(/agent-written native bytes/);
  });

  it('(b) supported compile then separate exec → row B at Q1 = AUDIT (allow + signal), never DENY', () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'compiled-output');
    w.put(`${WORK}/helper`, ELF);
    const v = w.check('./helper');
    expect(v.decision).toBe('allow');
    expect(v.signals).toContain(SIG_B);
    expect(v.signals).not.toContain(UMBRELLA);
    expect(v.severity).not.toBe('benign'); // audited: the hook logs non-benign allows
  });

  it('(c) LD_PRELOAD of a just-written library → DENY load-agent-written-native-object', () => {
    const w = new World();
    w.record(`${WORK}/libx.so`, 'agent-written');
    w.put(`${WORK}/libx.so`, ELF);
    const v = w.check('LD_PRELOAD=./libx.so /bin/true');
    expect(isFloor(v, SIG_C)).toBe(true);
  });

  it('(d)(i) inline python body mapping executable memory → DENY map-exec-agent-written-memory', () => {
    const body = 'import mmap; m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC); m.write(b"\\xc3")';
    const v = evaluateToolCall('Bash', { command: `python3 -c '${body}'` });
    expect(isFloor(v, SIG_D)).toBe(true);
    const ct = evaluateToolCall('Bash', { command: "python3 -c 'import ctypes; buf = ctypes.create_string_buffer(b\"\\xc3\"); f = ctypes.CFUNCTYPE(None)(ctypes.addressof(buf))'" });
    expect(isFloor(ct, SIG_D)).toBe(true);
  });

  it('(d)(ii) written script then run (folded file body) → DENY map-exec-agent-written-memory', () => {
    const src = 'import mmap\nm = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n';
    const v = evaluateToolCall('Bash', { command: 'python3 ./jit.py' }, undefined, {
      resolveScriptSource: (p: string) => (p.endsWith('jit.py') ? src : null),
    });
    expect(isFloor(v, SIG_D)).toBe(true);
  });

  it('row D does not match a shell MENTION outside an inspected program body', () => {
    const v = evaluateToolCall('Bash', { command: 'grep -rn "mmap PROT_EXEC" docs/' });
    expect(v.signals).not.toContain(SIG_D);
  });
});

// -- Rule P / complete-history controls ---------------------------------------

describe('#907 Rule P / complete-history controls', () => {
  it('failed write against an existing native file, no prior record → row J at a non-install path', () => {
    const w = new World();
    w.put(`${WORK}/bin/tool`, ELF);
    w.record(`${WORK}/bin/tool`, 'agent-written'); // preId = current identity: unproved
    expect(isDoor(w.check('./bin/tool'))).toBe(true);
  });

  it('failed write against an existing native file at an install root → current behaviour, never DENY', () => {
    const w = new World();
    w.put(INSTALL_TOOL, ELF);
    w.record(INSTALL_TOOL, 'agent-written');
    const v = w.check(INSTALL_TOOL);
    expect(touchesNative(v)).toBe(false);
  });

  it('direct write then a compile that does not change the file → DENY (compile record unproved)', () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written');
    w.put(`${WORK}/helper`, ELF);
    w.record(`${WORK}/helper`, 'compiled-output'); // preId = produced identity, no change
    expect(isFloor(w.check('./helper'), SIG_A)).toBe(true);
  });

  it('failed write then a compile that changes it (same preId, different kinds) → row J, not DENY, not row B', () => {
    const w = new World();
    const i0 = w.put(`${WORK}/helper`, ELF);
    w.record(`${WORK}/helper`, 'agent-written', i0);
    w.record(`${WORK}/helper`, 'compiled-output', i0);
    w.put(`${WORK}/helper`, ELF); // the compile changed the file
    const v = w.check('./helper');
    expect(isDoor(v)).toBe(true);
    expect(v.signals).not.toContain(SIG_B);
  });

  it.each([
    ['non-install path', `${WORK}/helper`],
    ['node_modules/.bin', INSTALL_TOOL],
    ['~/.local/bin (pinned home)', LOCAL_BIN_TOOL],
  ])('window exhaustion: create + four non-changing write-family calls → DENY (%s), never state 2', (_l, p) => {
    const w = new World();
    w.record(p, 'agent-written');
    w.put(p, ELF);
    for (let k = 0; k < 4; k++) w.record(p, 'agent-written'); // chmod / failed writes
    expect(isFloor(w.check(p), SIG_A)).toBe(true);
  });

  it('write-family call creating a native file inside ~/.local/bin → exec → DENY', () => {
    const w = new World();
    w.record(LOCAL_BIN_TOOL, 'agent-written');
    w.put(LOCAL_BIN_TOOL, ELF);
    expect(isFloor(w.check('~/.local/bin/tool'), SIG_A)).toBe(true);
  });

  it.each([
    ['(i) unreadable', (w: World, p: string) => w.damaged(p)],
    ['(ii) unparseable', (w: World, p: string) => w.damaged(p)],
    ['(iii) left as .tmp', (w: World, p: string) => w.tmp(p)],
  ])('retained-old-plus-lost-new %s → row J, never DENY, never row B', (_l, lose) => {
    const w = new World();
    const p = `${WORK}/helper`;
    w.record(p, 'compiled-output');
    w.put(p, ELF);
    lose(w, p);
    w.put(p, ELF);
    const v = w.check('./helper');
    expect(isDoor(v)).toBe(true);
    expect(v.signals).not.toContain(SIG_B);
  });

  it.each([
    ['non-install', `${WORK}/helper`],
    ['install root', INSTALL_TOOL],
  ])('record directory at the cap, older producing record retained → row J (%s)', (_l, p) => {
    const w = new World();
    w.record(p, 'agent-written');
    w.put(p, ELF);
    w.record(`${WORK}/other`, 'agent-written');
    w.cap = 2;
    expect(isDoor(w.check(p))).toBe(true);
  });

  it('unresolved.* record present → install-root native with no producer → row J', () => {
    const w = new World();
    w.put(INSTALL_TOOL, ELF);
    w.unresolved();
    expect(isDoor(w.check(INSTALL_TOOL))).toBe(true);
  });

  it('record directory unlistable at exec → install-root native with no producer → row J', () => {
    const w = new World();
    w.put(INSTALL_TOOL, ELF);
    w.listable = false;
    expect(isDoor(w.check(INSTALL_TOOL))).toBe(true);
  });

  it("capture-side stat null (preId 'unknown') → exec of that path → row J", () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written', 'unknown');
    w.put(`${WORK}/helper`, ELF);
    expect(isDoor(w.check('./helper'))).toBe(true);
  });

  it('record and query spell the same file differently → one pathHash → same verdict', () => {
    for (const spelling of ['./helper', `${WORK}/helper`, `${WORK}/sub/../helper`]) {
      const w = new World();
      w.record(`${WORK}/helper`, 'agent-written');
      w.put(`${WORK}/helper`, ELF);
      expect(isFloor(w.check(spelling), SIG_A)).toBe(true);
    }
    const w = new World();
    w.record(`${HOME}/bin/x`, 'agent-written');
    w.put(`${HOME}/bin/x`, ELF);
    expect(isFloor(w.check('~/bin/x'), SIG_A)).toBe(true);
  });

  it.each([
    ['non-install', `${WORK}/helper`],
    ['install root', INSTALL_TOOL],
  ])('no session key → native exec → row J (%s)', (_l, p) => {
    const w = new World();
    w.keyed = false;
    w.put(p, ELF);
    expect(isDoor(w.check(p))).toBe(true);
  });

  it('statPath → null for a native image → row J; statPath absent → outside', () => {
    const w = new World();
    w.put(`${WORK}/helper`, ELF);
    const base = w.view();
    const v = evaluateToolCall('Bash', { command: './helper' }, undefined, {
      artifactView: base, statPath: () => null, readFileHeader: () => ELF, cwd: WORK,
    });
    expect(isDoor(v)).toBe(true);
    const gone = evaluateToolCall('Bash', { command: './missing' }, undefined, {
      artifactView: base, statPath: () => 'absent', readFileHeader: () => null, cwd: WORK,
    });
    expect(touchesNative(gone)).toBe(false);
  });
});

// -- Observation boundary (round-4 B1, §3.1 item 5) ---------------------------

describe('#907 observation-boundary controls (interleaved record lands between list and re-list)', () => {
  it('same preId, failed write then compile interleaved → row J, never DENY, never row B', () => {
    const w = new World();
    const p = `${WORK}/helper`;
    const i0 = w.put(p, ELF);
    w.record(p, 'agent-written', i0);
    w.onStat = () => {
      w.onStat = undefined;
      w.record(p, 'compiled-output', i0);
      w.put(p, ELF);
    };
    const v = w.check('./helper');
    expect(isDoor(v)).toBe(true);
    expect(v.signals).not.toContain(SIG_B);
  });

  it('stale compile record, newer direct write interleaved → row J (not row B); listed before → DENY', () => {
    const p = `${WORK}/helper`;
    const w = new World();
    w.record(p, 'compiled-output');
    w.put(p, ELF);
    w.onStat = () => {
      w.onStat = undefined;
      w.record(p, 'agent-written');
      w.put(p, ELF);
    };
    const v = w.check('./helper');
    expect(isDoor(v)).toBe(true);
    expect(v.signals).not.toContain(SIG_B);

    const stable = new World();
    stable.record(p, 'compiled-output');
    stable.put(p, ELF);
    stable.record(p, 'agent-written');
    stable.put(p, ELF);
    expect(isFloor(stable.check('./helper'), SIG_A)).toBe(true);
  });

  it('stale empty listing, first write at ~/.local/bin interleaved → row J (not state 2); listed before → DENY', () => {
    const w = new World();
    w.onStat = () => {
      w.onStat = undefined;
      w.record(LOCAL_BIN_TOOL, 'agent-written');
      w.put(LOCAL_BIN_TOOL, ELF);
    };
    expect(isDoor(w.check(LOCAL_BIN_TOOL))).toBe(true);

    const stable = new World();
    stable.record(LOCAL_BIN_TOOL, 'agent-written');
    stable.put(LOCAL_BIN_TOOL, ELF);
    expect(isFloor(stable.check(LOCAL_BIN_TOOL), SIG_A)).toBe(true);
  });

  it('relist returns null with an otherwise complete history → row J', () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written');
    w.put(`${WORK}/helper`, ELF);
    w.relistOverride = () => null;
    expect(isDoor(w.check('./helper'))).toBe(true);
  });

  it('unrelated-path record published during the check → row J for that check; next check → normal verdict', () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written');
    w.put(`${WORK}/helper`, ELF);
    w.onStat = () => {
      w.onStat = undefined;
      w.record(`${WORK}/unrelated.txt`, 'agent-written');
    };
    expect(isDoor(w.check('./helper'))).toBe(true);
    expect(isFloor(w.check('./helper'), SIG_A)).toBe(true);
  });
});

// -- Benign controls (must not hit the floor) ---------------------------------

describe('#907 benign controls', () => {
  it('installed git/node/python running a pre-existing script, complete history → no native signal', () => {
    const w = new World();
    w.put('/usr/bin/git', ELF);
    w.put('/usr/bin/python3', ELF);
    w.put(`${WORK}/scripts/build.py`, TEXT);
    for (const c of ['/usr/bin/git status', 'python3 ./scripts/build.py', '/usr/bin/python3 ./scripts/build.py']) {
      expect(touchesNative(w.check(c))).toBe(false);
    }
  });

  it('node_modules/.bin/<tool> not written by the agent → current behaviour (state 2)', () => {
    const w = new World();
    w.put(INSTALL_TOOL, ELF);
    expect(touchesNative(w.check(INSTALL_TOOL))).toBe(false);
  });

  it('a data / script file written then run → outside the classifier (not a native image)', () => {
    const w = new World();
    w.record(`${WORK}/run.sh`, 'agent-written');
    w.put(`${WORK}/run.sh`, TEXT);
    const v = w.check('./run.sh');
    expect(v.signals).not.toContain(UMBRELLA);
    expect(v.signals).not.toContain(SIG_J);
  });

  it('a pre-existing project-local native binary with no record → row J (the priced cost, §4.2)', () => {
    const w = new World();
    w.put(`${WORK}/target/debug/app`, ELF);
    expect(isDoor(w.check('./target/debug/app'))).toBe(true);
  });

  it('missing inputs → the classifier does not run (adapter non-coverage, not an allow claim)', () => {
    const v = evaluateToolCall('Bash', { command: './helper' }, undefined, { cwd: WORK });
    expect(touchesNative(v)).toBe(false);
  });
});

// -- Captures (§3.4) ------------------------------------------------------------

describe('#907 capture targets', () => {
  it('a write-family tool with a path → agent-written, regardless of extension', () => {
    expect(nativeArtifactCaptures('Write', { file_path: '/w/x.txt', content: 'hi' })).toEqual([
      { token: '/w/x.txt', kind: 'agent-written' },
    ]);
  });

  it.each([
    ['cc helper.c -o helper', 'helper'],
    ['gcc -O2 -ohelper helper.c', 'helper'],
    ['/usr/bin/clang++ a.cc -o ./out/app', './out/app'],
    ['rustc main.rs -o bin/main', 'bin/main'],
  ])('supported compile `%s` → compiled-output %s', (cmd, out) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd })).toEqual([{ token: out, kind: 'compiled-output' }]);
  });

  it.each(['cc helper.c', 'go build -o app .', 'zig cc a.c -o a', 'make', 'cargo build'])(
    'unsupported output `%s` records nothing', (cmd) => {
      expect(nativeArtifactCaptures('Bash', { command: cmd })).toEqual([]);
    },
  );
});

describe('#907 canonicalTarget', () => {
  it('relative with no usable cwd is unresolvable (no process.cwd() fallback)', () => {
    expect(canonicalTarget('helper', undefined, HOME, (p) => p)).toBeNull();
    expect(canonicalTarget('helper', 'relative/cwd', HOME, (p) => p)).toBeNull();
    expect(canonicalTarget('a\0b', WORK, HOME, (p) => p)).toBeNull();
  });

  it('a symlinked parent resolves to the same string as the real path', () => {
    const realpath = (p: string) => (p === '/link' ? '/real' : p.startsWith('/link/') ? `/real${p.slice(5)}` : p);
    expect(canonicalTarget('/link/helper', WORK, HOME, realpath)).toBe('/real/helper');
    expect(canonicalTarget('/real/helper', WORK, HOME, realpath)).toBe('/real/helper');
  });
});

describe('#907 Rule P (pure)', () => {
  const id = (ino: number): ContentId => ({ dev: 1, ino, size: 8, mtimeMs: ino });
  it('unique newest differing candidate is the producer; same-preId different-kind is ambiguous', () => {
    expect(rulePProducer([{ kind: 'agent-written', preId: 'absent', at: 1 }], id(2))).toEqual({ kind: 'agent-written' });
    expect(rulePProducer([{ kind: 'agent-written', preId: id(2), at: 1 }], id(2))).toBe('no-producer');
    expect(rulePProducer([
      { kind: 'agent-written', preId: id(1), at: 1 },
      { kind: 'compiled-output', preId: id(1), at: 2 },
    ], id(2))).toBe('ambiguous');
  });
  it('the classifier never DENYs or relieves on incomplete history', () => {
    expect(classifyArtifactState({
      currentId: id(2), header: ELF, records: [{ kind: 'agent-written', preId: 'absent', at: 1 }],
      complete: false, installRoot: true,
    })).toBe('state-3-unknown');
  });
});

// -- The fs store against real files ------------------------------------------

describe('#907 fs store (real files under a test-owned dir)', () => {
  let dir: string;
  afterEach(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });
  const mk = () => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-907-store-'));
    const stateDir = path.join(dir, 'state');
    const work = path.join(dir, 'work');
    fs.mkdirSync(work, { recursive: true });
    return { stateDir, work: fs.realpathSync(work) };
  };
  const KEY = 'sc-0123456789abcdef';

  it('a record made by one call is visible to a later view; write → exec classifies as DENY', () => {
    const { stateDir, work } = mk();
    expect(recordArtifactCapture({ stateDir, sessionKey: KEY, token: './helper', cwd: work, kind: 'agent-written' }).held).toBe(false);
    fs.writeFileSync(path.join(work, 'helper'), Buffer.from(ELF));
    const v = evaluateToolCall('Bash', { command: './helper' }, undefined, {
      artifactView: buildArtifactView({ stateDir, sessionKey: KEY }),
      statPath: statContentId, readFileHeader: readArtifactHeader, cwd: work,
    });
    expect(isFloor(v, SIG_A)).toBe(true);
  });

  it('relative write target with no usable cwd → an unresolved.* record, not process.cwd()', () => {
    const { stateDir } = mk();
    expect(recordArtifactCapture({ stateDir, sessionKey: KEY, token: 'helper', cwd: undefined, kind: 'agent-written' }).held).toBe(false);
    const names = fs.readdirSync(path.join(stateDir, 'artifacts', KEY, 'rec'));
    expect(names).toHaveLength(1);
    expect(names[0]).toMatch(/^unresolved\./);
  });

  it('an unwritable store holds the call (never lets it through unrecorded)', () => {
    const { stateDir, work } = mk();
    fs.writeFileSync(stateDir, 'not a directory');
    expect(recordArtifactCapture({ stateDir, sessionKey: KEY, token: './helper', cwd: work, kind: 'agent-written' }).held).toBe(true);
  });

  it('a damaged record is reported to the core, never dropped', () => {
    const { stateDir, work } = mk();
    recordArtifactCapture({ stateDir, sessionKey: KEY, token: './helper', cwd: work, kind: 'agent-written' });
    const recDir = path.join(stateDir, 'artifacts', KEY, 'rec');
    const [name] = fs.readdirSync(recDir);
    fs.writeFileSync(path.join(recDir, name), '{"kind":'); // truncated body
    const view = buildArtifactView({ stateDir, sessionKey: KEY });
    expect(view.entries).toHaveLength(1);
    expect(view.entries[0].body).toBeNull();
  });

  it('statContentId: not-found is absent; a dangling symlink is null, never absent', () => {
    const { work } = mk();
    expect(statContentId(path.join(work, 'nope'))).toBe('absent');
    fs.symlinkSync(path.join(work, 'nope'), path.join(work, 'dangling'));
    expect(statContentId(path.join(work, 'dangling'))).toBeNull();
  });
});
