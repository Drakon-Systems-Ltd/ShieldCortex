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
import { spawnSync } from 'node:child_process';
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
  unkeyedArtifactView,
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

  it('an agent-written file with NUL bytes but no native magic → outside the floor (header magic only)', () => {
    const w = new World();
    w.record(`${WORK}/blob`, 'agent-written');
    w.put(`${WORK}/blob`, new Uint8Array([0x00, 0x01, 0x02, 0x00, 0x41, 0x42]));
    const v = w.check('./blob');
    expect(v.signals).not.toContain(UMBRELLA);
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

// == Review round 1 (Astra) regressions =======================================

/** Decision + sorted signals: what "the same verdict" means below. */
const shape = (v: { decision: string; severity: string; signals: string[] }) =>
  ({ decision: v.decision, severity: v.severity, signals: [...v.signals].sort() });
const NATIVE_SIGNALS = new Set([UMBRELLA, SIG_A, SIG_B, SIG_C, SIG_D, SIG_J]);
/** Decision + severity + the #907 signals only. The pre-existing script-file
 *  discovery (#4) folds only `./`-anchored command words, so `./bin/x` can
 *  carry its `opaque-script-invocation` audit row where `bin/x` does not;
 *  that is not this classifier's verdict. */
const nativeShape = (v: { decision: string; severity: string; signals: string[] }) =>
  ({ decision: v.decision, severity: v.severity, signals: v.signals.filter(s => NATIVE_SIGNALS.has(s)).sort() });

describe('#907 r1 B1 — a wrapper / interpreter NAME never exempts the file it addresses', () => {
  it.each([
    './python3',
    "./python3 -c 'print(1)'",
    './node ./x.js',
    './bash ./run.sh',
    './env ls',
    './timeout 5 ls',
    './sudo true',
    'sudo ./python3',
    'timeout 5 ./python3 -V',
    'env FOO=1 ./python3',
  ])('agent-written native image addressed as `%s` → DENY', (cmd) => {
    const w = new World();
    for (const name of ['python3', 'node', 'bash', 'env', 'timeout', 'sudo']) {
      w.record(`${WORK}/${name}`, 'agent-written');
      w.put(`${WORK}/${name}`, ELF);
    }
    expect(isFloor(w.check(cmd), SIG_A)).toBe(true);
  });

  it('the renamed image is classified exactly like the same bytes under a neutral name', () => {
    const w = new World();
    for (const name of ['helper', 'python3']) {
      w.record(`${WORK}/${name}`, 'agent-written');
      w.put(`${WORK}/${name}`, ELF);
    }
    expect(shape(w.check('./python3'))).toEqual(shape(w.check('./helper')));
  });

  it('unkeyed view: an interpreter / wrapper at an install root is the door, exactly like /usr/bin/ls', () => {
    const w = new World();
    w.keyed = false;
    for (const p of ['/usr/bin/ls', '/usr/bin/python3', '/usr/bin/env', '/usr/bin/bash']) w.put(p, ELF);
    const control = w.check('/usr/bin/ls');
    expect(isDoor(control)).toBe(true);
    for (const cmd of ['/usr/bin/python3', '/usr/bin/python3 ./x.py', '/usr/bin/env node x.js', '/usr/bin/bash -c true']) {
      expect(isDoor(w.check(cmd))).toBe(true);
    }
  });

  it('keyed, complete history: an installed interpreter / wrapper keeps current behaviour (state 2)', () => {
    const w = new World();
    for (const p of ['/usr/bin/python3', '/usr/bin/env', '/usr/bin/timeout']) w.put(p, ELF);
    for (const cmd of ['/usr/bin/python3 ./x.py', '/usr/bin/env node x.js', '/usr/bin/timeout 5 /usr/bin/python3 -V']) {
      expect(touchesNative(w.check(cmd))).toBe(false);
    }
  });

  it('downstream arguments stay separate: a native file handed to an interpreter as its script is not addressed', () => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written');
    w.put(`${WORK}/helper`, ELF);
    for (const cmd of ['python3 ./helper', 'bash ./helper', 'sh -e ./helper', 'node ./helper']) {
      const v = w.check(cmd);
      expect(v.signals).not.toContain(UMBRELLA);
      expect(v.signals).not.toContain(SIG_J);
    }
  });
});

describe('#907 r1 B2 — every path spelling of one target gets the same verdict', () => {
  const PAIRS: Array<[string, string, string]> = [
    ['bin/helper', './bin/helper', `${WORK}/bin/helper`],
    ['node_modules/.bin/tool', './node_modules/.bin/tool', INSTALL_TOOL],
    // r2 N3: the preload must reach an EXTERNAL program — `true` is a shell
    // builtin and loads nothing (pinned as a no-load control in r2 N3 below).
    ['LD_PRELOAD=lib/libx.so /bin/true', 'LD_PRELOAD=./lib/libx.so /bin/true', `${WORK}/lib/libx.so`],
    ['cd bin && ./helper', './bin/helper', `${WORK}/bin/helper`],
    ['$PWD/bin/helper', './bin/helper', `${WORK}/bin/helper`],
    [`${WORK}/bin/helper`, './bin/helper', `${WORK}/bin/helper`],
  ];
  const HISTORIES: Array<[string, (w: World, p: string) => void]> = [
    ['agent-written producer', (w, p) => { w.record(p, 'agent-written'); w.put(p, ELF); }],
    ['compiled-output producer', (w, p) => { w.record(p, 'compiled-output'); w.put(p, ELF); }],
    ['no record (unknown history)', (w, p) => { w.put(p, ELF); }],
  ];
  for (const [bare, dotted, target] of PAIRS) {
    for (const [label, setup] of HISTORIES) {
      it(`\`${bare}\` ≡ \`${dotted}\` — ${label}`, () => {
        const w = new World();
        setup(w, target);
        const a = w.check(bare);
        const b = w.check(dotted);
        expect(nativeShape(a)).toEqual(nativeShape(b));
        // and the classifier really ran on it (not two equal no-ops)
        if (label.startsWith('agent')) expect(a.signals).toContain(UMBRELLA);
        if (label.startsWith('compiled')) expect(a.signals).toContain(SIG_B);
      });
    }
  }

  it('a compile output captured under `cd` is the path a later spelt exec resolves to (row B, not J)', () => {
    expect(nativeArtifactCaptures('Bash', { command: 'cd out && cc ../a.c -o app' }))
      .toEqual([{ token: 'out/app', kind: 'compiled-output' }]);
    const w = new World();
    w.record(`${WORK}/out/app`, 'compiled-output');
    w.put(`${WORK}/out/app`, ELF);
    for (const cmd of ['./out/app', 'out/app', 'cd out && ./app']) {
      const v = w.check(cmd);
      expect(v.decision).toBe('allow');
      expect(v.signals).toContain(SIG_B);
    }
  });

  it('a compile whose output directory a computed `cd` hides is recorded as unresolvable, never at a guessed path', () => {
    expect(nativeArtifactCaptures('Bash', { command: 'cd "$OUT" && cc a.c -o app' }))
      .toEqual([{ token: '', kind: 'compiled-output' }]);
  });
});

describe('#907 r1 B3 — mentioning a native file is not running it (use vs mention)', () => {
  const READS = [
    "cat <<'EOF'\n./helper\nLD_PRELOAD=./helper ls\nEOF",
    'cat <<EOF\n./helper\nbin/helper --flag\nEOF',
    "tee notes.md <<'EOF' >/dev/null\n./helper\nEOF",
    'echo "first line\n./helper\nlast"',
    'git commit -m "fix helper\n\n./helper now built by make"',
    "printf '%s\\n' ./helper",
    'ls # ./helper',
    '# ./helper\nls',
    "grep -n './helper' notes.md",
    'command -v ./helper',
    'files=(./helper bin/helper); echo "${files[@]}"',
    'python3 - <<\'PY\'\nprint("./helper")\nPY',
  ];
  for (const [label, setup] of [
    ['agent-produced target', (w: World) => { w.record(`${WORK}/helper`, 'agent-written'); w.put(`${WORK}/helper`, ELF); w.record(`${WORK}/bin/helper`, 'agent-written'); w.put(`${WORK}/bin/helper`, ELF); }],
    ['unknown target', (w: World) => { w.put(`${WORK}/helper`, ELF); w.put(`${WORK}/bin/helper`, ELF); }],
  ] as const) {
    it.each(READS)(`${label}: read/print/mention %j mints no exec effect`, (cmd) => {
      const w = new World();
      setup(w);
      const v = w.check(cmd);
      expect(v.signals).not.toContain(UMBRELLA);
      expect(v.signals).not.toContain(SIG_J);
      expect(v.decision).not.toBe('block');
    });
  }

  it.each([
    'make && ./helper',
    'true; ./helper',
    'true\n./helper',
    '(./helper)',
    '{ ./helper; }',
    'echo $(./helper)',
    'echo "$(./helper)"',
    'echo `./helper`',
    'diff <(./helper) expected.txt',
    "bash -c './helper'",
    "sh -c 'cd bin && ./helper'",
    'eval ./helper',
    "bash <<'EOF'\n./helper\nEOF",
    "cat <<'EOF' | sh\n./helper\nEOF",
    'cat <<EOF\n$(./helper)\nEOF',
    '2>/dev/null ./helper',
    './helper > out.txt 2>&1',
    'nohup ./helper >/dev/null 2>&1 &',
    'if ./helper; then echo ok; fi',
    'while ./helper; do break; done',
    'X=1 ./helper',
    'export LD_PRELOAD=./helper; ls',
    "echo 'not this' # but\n./helper",
  ])('real execution in a compound command still hits the floor: %j', (cmd) => {
    const w = new World();
    w.record(`${WORK}/helper`, 'agent-written');
    w.put(`${WORK}/helper`, ELF);
    w.record(`${WORK}/bin/helper`, 'agent-written');
    w.put(`${WORK}/bin/helper`, ELF);
    const v = w.check(cmd);
    expect(v.decision).toBe('block');
    expect(v.signals).toContain(UMBRELLA);
  });

  it.each([
    'git commit -m "build\ncc helper.c -o helper"',
    "cat <<'EOF'\ncc helper.c -o helper\nEOF",
    "echo 'cc helper.c -o helper'",
    '# cc helper.c -o helper',
  ])('a compiler only MENTIONED in %j mints no compile capture', (cmd) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd })).toEqual([]);
  });

  it.each([
    ['make && cc helper.c -o helper', 'helper'],
    ["bash -c 'cc helper.c -o out/helper'", 'out/helper'],
    ['x=$(cc helper.c -o helper)', 'helper'],
  ])('a compiler actually run in %j is still captured', (cmd, out) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd })).toEqual([{ token: out, kind: 'compiled-output' }]);
  });
});

describe('#907 r1 B4 — row D needs an executable-memory OPERATION, not its vocabulary', () => {
  it.each([
    `node -e "console.log('mmap PROT_EXEC')"`,
    `python3 -c "print('mmap PROT_EXEC')"`,
    `python3 -c "print('ctypes.CFUNCTYPE docs')"`,
    `python3 -c "x = 1  # mmap PROT_EXEC via ctypes.CFUNCTYPE"`,
    "python3 - <<'PY'\nprint(\"\"\"mmap with PROT_EXEC and mprotect PROT_EXEC\"\"\")\nPY",
    "node - <<'JS'\n// mmap PROT_EXEC notes\nconsole.log('VirtualAlloc PAGE_EXECUTE_READWRITE')\nJS",
  ])('printing / commenting the terms is allowed: %j', (cmd) => {
    const v = evaluateToolCall('Bash', { command: cmd });
    expect(v.signals).not.toContain(SIG_D);
    expect(v.decision).not.toBe('block');
  });

  it('a folded script that only prints the terms is allowed; one that maps memory is denied', () => {
    const docs = 'HELP = """Uses mmap with PROT_EXEC; see ctypes.CFUNCTYPE."""\nprint(HELP)\n';
    const jit = 'import mmap\nm = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)\n';
    const run = (src: string) => evaluateToolCall('Bash', { command: 'python3 ./tool.py' }, undefined, {
      resolveScriptSource: (p: string) => (p.endsWith('tool.py') ? src : null),
    });
    expect(run(docs).signals).not.toContain(SIG_D);
    expect(isFloor(run(jit), SIG_D)).toBe(true);
  });

  it.each([
    "python3 -c 'import mmap; m = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC)'",
    "python3 -c 'import ctypes; f = ctypes.CFUNCTYPE(None)(ctypes.addressof(buf))'",
    `python3 -c "exec('import mmap; mmap.mmap(-1, 1, prot=mmap.PROT_EXEC)')"`,
    `node -e "eval('mmap(PROT_EXEC)')"`,
    "python3 - <<'PY'\nimport mmap\nbuf = mmap.mmap(-1, 4096, prot=mmap.PROT_EXEC)\nPY",
  ])('a real or string-evaluated mapping is still denied: %j', (cmd) => {
    expect(isFloor(evaluateToolCall('Bash', { command: cmd }), SIG_D)).toBe(true);
  });
});

describe('#907 r1 B5 — null artifactView is incomplete history, never classifier-off', () => {
  const run = (command: string, artifactView: AgentArtifactView | null | undefined, w: World) =>
    evaluateToolCall('Bash', { command }, undefined, {
      artifactView,
      statPath: (p) => w.files.get(p)?.id ?? 'absent',
      readFileHeader: (p) => w.files.get(p)?.header ?? null,
      cwd: WORK,
    });

  it.each(['/usr/bin/ls', './helper', '/usr/bin/python3 ./x.py'])(
    'null ≡ keyed:false for `%s` (install-root and project-local)', (cmd) => {
      const w = new World();
      w.put('/usr/bin/ls', ELF);
      w.put('/usr/bin/python3', ELF);
      w.record(`${WORK}/helper`, 'agent-written');
      w.put(`${WORK}/helper`, ELF);
      const viaNull = run(cmd, null, w);
      const viaUnkeyed = run(cmd, { ...w.view(), keyed: false, listable: false }, w);
      expect(isDoor(viaNull)).toBe(true);
      expect(shape(viaNull)).toEqual(shape(viaUnkeyed));
    });

  it('the fs store\'s unkeyed view classifies the same as null', () => {
    const w = new World();
    w.put('/usr/bin/ls', ELF);
    expect(shape(run('/usr/bin/ls', unkeyedArtifactView(HOME), w))).toEqual(shape(run('/usr/bin/ls', null, w)));
  });

  it('a wired value that is not a usable view is incomplete history too', () => {
    const w = new World();
    w.put('/usr/bin/ls', ELF);
    expect(isDoor(run('/usr/bin/ls', {} as unknown as AgentArtifactView, w))).toBe(true);
  });

  it('only undefined means "not wired": the classifier does not run', () => {
    const w = new World();
    w.put('/usr/bin/ls', ELF);
    expect(touchesNative(run('/usr/bin/ls', undefined, w))).toBe(false);
  });
});

describe('#907 r1 B6 — a structural store error is incomplete history, on both listings', () => {
  let dir: string;
  afterEach(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });
  const KEY = 'sc-0123456789abcdef';
  const mk = () => {
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-907-b6-')));
    const work = path.join(dir, 'work');
    const binDir = path.join(work, 'node_modules', '.bin');
    fs.mkdirSync(binDir, { recursive: true });
    const tool = path.join(binDir, 'tool'); // an install-root arm, never written this session
    fs.writeFileSync(tool, Buffer.from(ELF), { mode: 0o755 });
    return { work, tool };
  };
  const exec = (cmd: string, view: AgentArtifactView, work: string) =>
    evaluateToolCall('Bash', { command: cmd }, undefined, {
      artifactView: view, statPath: statContentId, readFileHeader: readArtifactHeader, cwd: work,
    });

  it('control: a genuinely absent session directory is complete and empty → install-root image keeps current behaviour', () => {
    const { work, tool } = mk();
    const view = buildArtifactView({ stateDir: path.join(dir, 'state'), sessionKey: KEY });
    expect(view.listable).toBe(true);
    expect(view.relist()).toEqual([]);
    expect(touchesNative(exec(tool, view, work))).toBe(false);
  });

  it('first listing ENOTDIR (the store path is a regular file) → listable:false, relist null → the door', () => {
    const { work, tool } = mk();
    const stateDir = path.join(dir, 'state-file');
    fs.writeFileSync(stateDir, 'not a directory');
    const view = buildArtifactView({ stateDir, sessionKey: KEY });
    expect(view.listable).toBe(false);
    expect(view.relist()).toBeNull();
    expect(isDoor(exec(tool, view, work))).toBe(true);
  });

  it('re-list ENOTDIR (the store breaks between listing and re-list) → the door for that check', () => {
    const { work, tool } = mk();
    const stateDir = path.join(dir, 'state');
    fs.mkdirSync(stateDir);
    const view = buildArtifactView({ stateDir, sessionKey: KEY });
    expect(view.listable).toBe(true); // ENOENT: absent, complete
    fs.writeFileSync(path.join(stateDir, 'artifacts'), 'now a file'); // structural break
    expect(isDoor(exec(tool, view, work))).toBe(true);
  });

  it('an unwritable store holds the write AND every later native exec in that session is the door', () => {
    const { work, tool } = mk();
    const stateDir = path.join(dir, 'state-file');
    fs.writeFileSync(stateDir, 'not a directory');
    const helper = path.join(work, 'helper');
    expect(recordArtifactCapture({ stateDir, sessionKey: KEY, token: helper, cwd: work, kind: 'agent-written' }).held).toBe(true);
    fs.writeFileSync(helper, Buffer.from(ELF), { mode: 0o755 }); // a held call released anyway
    const view = () => buildArtifactView({ stateDir, sessionKey: KEY });
    expect(isDoor(exec('./helper', view(), work))).toBe(true);
    expect(isDoor(exec(tool, view(), work))).toBe(true); // no install-root relief either
  });

  const fifoIt = process.platform === 'win32' ? it.skip : it;
  fifoIt('readArtifactHeader never blocks on a FIFO and never reads a non-regular file', () => {
    mk();
    const fifo = path.join(dir, 'pipe');
    const made = spawnSync('mkfifo', [fifo]);
    if (made.status !== 0) return; // no mkfifo on this host: nothing to pin
    expect(readArtifactHeader(fifo)).toBeNull();
    expect(readArtifactHeader(dir)).toBeNull();
  });
});

// -- review round 2 regressions -----------------------------------------------
//
// One family: the shell lexer / row-D text reader decides "executed vs
// mentioned" and "which directory". Every reproduction from both r2 reports is
// pinned with its positive control. Shell semantics of the directory and
// heredoc cases were checked against bash 5.2 and dash with harmless
// `echo` / `cat` probes (no native payload).

/** A world with an agent-written native image at each of `paths`. */
function agentNative(...paths: string[]): World {
  const w = new World();
  for (const p of paths) { w.record(p, 'agent-written'); w.put(p, ELF); }
  return w;
}

describe('#907 r2 N5 / B1 — directory uncertainty never drops or re-anchors a relative exec', () => {
  // Only ${WORK}/helper exists and is agent-produced. In every command the
  // shell runs ./helper in the call cwd (or may): the floor must fire.
  it.each([
    'false && cd sub; ./helper',                  // N5: the cd does not run
    'if false; then cd sub; fi; ./helper',        // N5
    'true && cd sub; ./helper',                   // the cd may fail
    'cd sub; ./helper',                           // the cd may fail
    'cd . || true; ./helper',                     // B1: cd . does not move
    'cd /no/such/dir || ./helper',                // B1: || runs where cd FAILED
    'pushd . && ./helper',                        // B1
    'popd; ./helper',                             // B1: no in-call pushd
    'timeout 1 cd /tmp && ./helper',              // B1: a child-only wrapper
    'sudo cd /tmp && ./helper',                   // B1 (sudo spelling)
    'env cd /tmp && ./helper',
    'nohup cd /tmp; ./helper',
    '(cd sub); ./helper',                         // a subshell does not leak
    'cd sub | cat; ./helper',                     // a pipeline member
    'cd sub & ./helper',                          // a background job
    'x=$(cd sub); ./helper',                      // a substitution
    'cd sub || exit 1; ./helper',                 // over-approximated: both
    'f() { cd sub; }; f; ./helper',               // an invoked function's cd
    'for d in a b; do cd sub; done; ./helper',
    'cd "$X" || true; ./helper',                  // unknown, but cwd still named
  ])('%j still hits the floor on ./helper in the call cwd', (cmd) => {
    const w = agentNative(`${WORK}/helper`);
    expect(isFloor(w.check(cmd), SIG_A)).toBe(true);
  });

  // `door`: no NAMED directory the shell could be in holds the image, so the
  // unnamed one takes the door. `floor`: the call cwd is still one of the
  // directories (`source` may not cd at all; a loop's first pass runs before
  // its cd), the image there is agent-produced, and a floor on a resolved
  // candidate outranks the door (DENY > HOLD, classifyLedgerNativeExec).
  it.each([
    ['cd - && ./helper', 'door'],
    ['cd "$(pwd)" && ./helper', 'door'],
    ['cd "$DIR" && ./helper', 'door'],
    ['cd ~bob && ./helper', 'door'],
    ['cd $(git rev-parse --show-toplevel) && ./helper', 'door'],
    ['source ./env.sh && ./helper', 'floor'],
    ['. ./env.sh && ./helper', 'floor'],
    ['pushd && ./helper', 'door'],
    ['while true; do ./helper; cd sub; done', 'floor'],
    ['CDPATH=/opt cd sub && ./helper', 'door'],
  ])('%j runs ./helper in a directory that cannot be named → %s, never a silent allow', (cmd, want) => {
    const v = agentNative(`${WORK}/helper`).check(cmd);
    expect(v.decision).not.toBe('allow');
    if (want === 'floor') expect(isFloor(v, SIG_A)).toBe(true);
    else expect(v.signals).toContain(SIG_J);
  });

  it.each([
    'cd - && ./helper',
    'cd "$(pwd)" && ./helper',
    'cd "$DIR" && ./helper',
    'cd ~bob && ./helper',
    'cd $(git rev-parse --show-toplevel) && ./helper',
    'source ./env.sh && ./helper',
    '. ./env.sh && ./helper',
    'pushd && ./helper',
    'while true; do ./helper; cd sub; done',
    'CDPATH=/opt cd sub && ./helper',
    'x() { cd "$1"; }; x foo; ./helper',
  ])('%j: every NAMED candidate is absent, the unnamed directory is not ruled out → the door (the token is never dropped)', (cmd) => {
    const v = new World().check(cmd);
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain(SIG_J);
  });

  it('positive controls: a successful cd re-anchors (only sub/helper exists)', () => {
    const w = agentNative(`${WORK}/sub/helper`);
    for (const cmd of [
      'cd sub && ./helper',
      'cd sub && make && ./helper',
      'command cd sub && ./helper',
      'builtin cd sub && ./helper',
      'time cd sub && ./helper',
      'test -d sub && cd sub; ./helper',
      'if true; then cd sub; fi; ./helper',
      'pushd sub && ./helper',
      'eval cd sub; ./helper',
      'cd sub\n./helper',
    ]) {
      expect([cmd, isFloor(w.check(cmd), SIG_A)]).toEqual([cmd, true]);
    }
    // and the plain control on the real target
    expect(isFloor(w.check('./sub/helper'), SIG_A)).toBe(true);
  });

  it('a pushd/popd pair returns to the named directory', () => {
    const w = agentNative(`${WORK}/helper`);
    const v = w.check('pushd sub && make && popd; ./helper');
    expect(isFloor(v, SIG_A)).toBe(true);
  });

  it('control: an unrelated exec under a named directory set keeps current behaviour', () => {
    const w = new World(); // nothing exists: every candidate is absent → outside the classifier
    for (const cmd of ['false && cd sub; ./helper', 'cd sub; ./helper', 'cd . || true; ./helper']) {
      expect(touchesNative(w.check(cmd))).toBe(false);
    }
  });

  it('capture uses the same rule: every directory the compiler could run in, unnamed → unresolved', () => {
    // A set of candidate directories: compare as sets ('' = unresolved).
    const cap = (command: string) => nativeArtifactCaptures('Bash', { command }).map((c) => c.token).sort();
    expect(cap('false && cd out; cc a.c -o app')).toEqual(['app', 'out/app']);
    expect(cap('if false; then cd out; fi; cc a.c -o app')).toEqual(['app', 'out/app']);
    expect(cap('cd out && cc a.c -o app')).toEqual(['out/app']);
    expect(cap('cd out; cc a.c -o app')).toEqual(['app', 'out/app']);
    expect(cap('timeout 1 cd out && cc a.c -o app')).toEqual(['app']);
    expect(cap('cd . || true; cc a.c -o app')).toEqual(['app']);
    expect(cap('cd "$OUT" || true; cc a.c -o app')).toEqual(['', 'app']);
    expect(cap('cd - && cc a.c -o app')).toEqual(['']);
    expect(cap('source ./env.sh && cc a.c -o app')).toEqual(['', 'app']);
    // positive control: a plain compile still captures
    expect(cap('cc a.c -o app')).toEqual(['app']);
  });
});

describe('#907 r2 N4 / B2 — a heredoc body ends at the EARLIEST line a shell could end it', () => {
  it.each([
    // N4: backslash-newline in an unquoted delimiter is a line continuation → `EOF`
    'cat <<EO\\\nF\nhi\nEOF\n./helper',
    // the same continuation inside double quotes
    'cat <<"EO\\\nF"\nhi\nEOF\n./helper',
    // B2: a delimiter holding an expansion cannot be proved → lines are commands
    'END=EOF\ncat << $END\nharmless\nEOF\n./helper',
    'cat <<"$END"\nharmless\nEOF\n./helper',
    "cat << ${END}\ndon't stop\n./helper\n${END}",
    // `$(cat <<EOF … EOF)`: bash and dash close body and substitution on that line
    'x=$(cat <<EOF\nhi\nEOF)\n./helper',
    // controls: the ordinary forms
    'cat <<EOF\nhi\nEOF\n./helper',
    "cat <<'EOF'\nhi\nEOF\n./helper",
    'cat <<-EOF\n\thi\n\tEOF\n./helper',
  ])('%j — the trailing ./helper is executed: floor', (cmd) => {
    expect(isFloor(agentNative(`${WORK}/helper`).check(cmd), SIG_A)).toBe(true);
  });

  it.each([
    // single quotes keep backslash-newline: that delimiter never matches, the rest is body
    "cat <<'EO\\\nF'\nhi\nEOF\n./helper",
    "cat <<'EOF'\n./helper\nEOF",
    'x=$(cat <<EOF\nfoo)\n./helper\nEOF\n)',
  ])('%j — ./helper is inert heredoc text: no native signal', (cmd) => {
    const v = agentNative(`${WORK}/helper`).check(cmd);
    expect(v.signals).not.toContain(UMBRELLA);
    expect(v.decision).not.toBe('block');
  });
});

describe('#907 r2 N3 — shell syntax roles: definitions, patterns, assignments and builtins run nothing', () => {
  const both = () => agentNative(`${WORK}/helper`, `${WORK}/lib.so`);

  it.each([
    'f() { ./helper; }\ncase x in\n./helper) echo hi;;\nesac', // N3 exact
    'f() { ./helper; }',
    'f() { ./helper; }; echo defined',
    'function g { ./helper; }',
    'function g() { ./helper; }; echo ok',
    'function g\n{ ./helper; }',
    'f() ( ./helper )',
    'f()\n{\n  ./helper\n}',
    'case x in ./helper) echo hi;; esac',
    'case "$1" in (./helper|bin/helper) echo hi;; *) echo no;; esac',
    'LD_PRELOAD=./lib.so echo hi',                // N3: builtin
    'LD_PRELOAD=./lib.so true',
    'LD_PRELOAD=./lib.so',                        // assignment only
    'LD_PRELOAD=./lib.so; ./other',               // not exported
    'export -n LD_PRELOAD=./lib.so',              // N3: -n removes the export
    'export -n LD_PRELOAD=./lib.so; ls',
    'declare LD_PRELOAD=./lib.so; ls',
    'export LD_PRELOAD=./lib.so; export -n LD_PRELOAD; ls',
    'export LD_PRELOAD=./lib.so; unset LD_PRELOAD; ls',
    'export LD_PRELOAD=./lib.so; echo done',
    'f() { ./helper; }; bash -c f',               // a child shell does not inherit f
    'f() { ./helper; }; sudo f',                  // sudo runs an external f
  ])('%j mints no exec/load effect', (cmd) => {
    const v = both().check(cmd);
    expect(v.signals).not.toContain(UMBRELLA);
    expect(v.decision).not.toBe('block');
  });

  it.each([
    ['f() { ./helper; }; f', SIG_A],
    ['f() { ./helper; }\nf', SIG_A],
    ['function g { ./helper; }; g', SIG_A],
    ['f() ( ./helper ); f', SIG_A],
    ['f() { ./helper; }; time f', SIG_A],
    ['f() { ./helper; }; echo $(f)', SIG_A],
    ['f() { ./helper; }; eval f', SIG_A],
    ['f() { ./helper; }; export -f f; bash -c f', SIG_A],
    ['f() { g; }; g() { ./helper; }; f', SIG_A],
    // every cd may fail, so ./helper may still run in the call cwd — the same
    // rule as `cd sub; ./helper` above (r2 N5 / B1): the floor
    ['f() { cd sub; ./helper; }; cd sub2; f', SIG_A],
    // with `&&` both cds must succeed: ./helper runs only in sub2/sub (absent)
    ['f() { cd sub && ./helper; }; cd sub2 && f', null],
    ['case x in x) ./helper;; esac', SIG_A],
    ['case x in\n  x)\n    ./helper\n    ;;\nesac', SIG_A],
    ['case $(./helper) in x) echo;; esac', SIG_A],
    ['LD_PRELOAD=./lib.so ls', SIG_C],
    ['LD_PRELOAD=./lib.so /bin/echo hi', SIG_C],
    ['LD_PRELOAD=./lib.so env echo hi', SIG_C],
    ['export LD_PRELOAD=./lib.so; ls', SIG_C],
    ['LD_PRELOAD=./lib.so; export LD_PRELOAD; ls', SIG_C],
    ['declare -x LD_PRELOAD=./lib.so; ls', SIG_C],
    ['set -a; LD_PRELOAD=./lib.so; ls', SIG_C],
    ['export LD_PRELOAD=./lib.so; cd sub && ls', null],
    ['./helper', SIG_A],
  ])('positive control %j keeps its coverage', (cmd, sig) => {
    const w = both();
    if (sig === null) {
      // `cd sub2 && f` → f's ./helper runs only in sub2/sub, which does not exist → nothing native
      // `cd sub && ls` → the preload resolves under sub, which holds no library
      expect(w.check(cmd).signals).not.toContain(UMBRELLA);
      return;
    }
    expect(isFloor(w.check(cmd), sig)).toBe(true);
  });

  it('a function body is lexed in the CALL-SITE directory: sub2/sub/helper under `cd sub2 && f`', () => {
    const w = agentNative(`${WORK}/sub2/sub/helper`);
    expect(isFloor(w.check('f() { cd sub && ./helper; }; cd sub2 && f'), SIG_A)).toBe(true);
    // defined but never called: nothing runs
    expect(w.check('f() { cd sub && ./helper; }; cd sub2').signals).not.toContain(UMBRELLA);
  });

  it('an export resolves where the program runs: sub/lib.so under `cd sub`', () => {
    const w = agentNative(`${WORK}/sub/lib.so`);
    expect(isFloor(w.check('export LD_PRELOAD=./lib.so; cd sub && ls'), SIG_C)).toBe(true);
  });

  it.each([
    'f() { cc x.c -o helper; }; echo defined', // N3 exact
    'f() { cc x.c -o helper; }',
    'case x in cc) echo;; esac',
    'case x in "cc x.c -o helper") echo;; esac',
  ])('a compiler only DEFINED or MATCHED in %j mints no compile capture', (cmd) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd })).toEqual([]);
  });

  it.each([
    ['f() { cc x.c -o helper; }; f', 'helper'],
    ['case x in x) cc x.c -o helper;; esac', 'helper'],
    ['cc x.c -o helper', 'helper'],
  ])('a compiler actually run in %j is still captured', (cmd, out) => {
    expect(nativeArtifactCaptures('Bash', { command: cmd })).toEqual([{ token: out, kind: 'compiled-output' }]);
  });

  it('runaway function expansion is bounded and holds (never allows unread)', () => {
    const defs = Array.from({ length: 12 }, (_, k) => `f${k}() { f${k + 1}; f${k + 1}; }`).join('; ');
    const v = agentNative(`${WORK}/helper`).check(`${defs}; f12() { ./x; }; f0`);
    expect(v.signals).toContain(SIG_J);
  });
});

describe('#907 r2 N1 / N2 — row D: no keyword reactivates unrelated text; executed interpolations stay code', () => {
  const fold = (cmd: string, body: string) => evaluateToolCall('Bash', { command: cmd }, undefined, {
    resolveScriptSource: () => body,
  });

  it.each([
    `python3 -c 'print("mmap PROT_EXEC")'`,
    `python3 -c 'print("mmap PROT_EXEC eval")'`,           // N1
    `python3 -c 'print("mmap PROT_EXEC importlib")'`,      // N1
    `node -e 'console.log("mmap PROT_EXEC vm")'`,          // N1
    "node -e 'console.log(`mmap PROT_EXEC`)'",             // an untagged template is text
    `python3 -c 'print(f"mmap PROT_EXEC {x}")'`,           // interpolation without the operation
    `python3 -c 'import re; re.compile(x); print("mmap PROT_EXEC")'`,
    `bash -c 'echo mmap PROT_EXEC'`,
  ])('inline %j prints the words: allowed', (cmd) => {
    const v = evaluateToolCall('Bash', { command: cmd });
    expect(v.signals).not.toContain(SIG_D);
    expect(v.decision).not.toBe('block');
  });

  it.each([
    ['bash ./x.sh', '#!/bin/sh\necho mmap PROT_EXEC\n'],                                   // N1
    ['node scripts/build.mjs', 'import("node:path"); console.log("mmap PROT_EXEC");\n'],   // N1
    ['python3 ./doc.py', 'import importlib\nimportlib.import_module("json")\nprint("mmap PROT_EXEC")\n'],
  ])('folded %j only prints the words: allowed', (cmd, body) => {
    const v = fold(cmd, body);
    expect(v.signals).not.toContain(SIG_D);
    expect(v.decision).not.toBe('block');
  });

  it.each([
    `python3 -c 'import mmap; print(f"{mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)}")'`,      // N2 exact
    `python3 -c 'import mmap; mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)'`,                 // direct control
    "node -e 'console.log(`${mmap(PROT_EXEC)}`)'",                                       // template interpolation
    `python3 -c "exec('import mmap; mmap.mmap(-1, 1, prot=mmap.PROT_EXEC)')"`,          // r1 control
    `python3 -c 's = "import mmap; mmap.mmap(-1, 1, prot=mmap.PROT_EXEC)"; exec(s)'`,   // string via a variable
    `python3 -c 'import mmap; mmap.mmap(-1, 4096, prot=getattr(mmap, "PROT_EXEC"))'`,  // a code-bearing literal
    `node -e "eval('mmap(PROT_EXEC)')"`,                                                  // r1 control
  ])('inline %j performs the mapping: floor', (cmd) => {
    expect(isFloor(evaluateToolCall('Bash', { command: cmd }), SIG_D)).toBe(true);
  });

  it.each([
    ['python3 ./fstr.py', 'import mmap\nprint(f"{mmap.mmap(-1,4096,prot=mmap.PROT_EXEC)}")\n'],                  // N2 exact
    ['python3 ./jit.py', 'import mmap\nm = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC)\n'],
    ['bash ./x.sh', "#!/bin/sh\npython3 -c 'import mmap; mmap.mmap(-1, 4096, prot=mmap.PROT_EXEC)'\n"],         // shell runs a program
    ['bash ./x.sh', "#!/bin/sh\npython3 - <<'PY'\nimport mmap\nmmap.mmap(-1, 4096, prot=mmap.PROT_EXEC)\nPY\n"],
  ])('folded %j performs the mapping: floor', (cmd, body) => {
    expect(isFloor(fold(cmd, body), SIG_D)).toBe(true);
  });
});
