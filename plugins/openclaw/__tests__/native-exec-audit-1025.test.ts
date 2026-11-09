/**
 * #1025 — the audit-only native-exec observation through the REAL OpenClaw
 * interceptor, the REAL guard and the REAL provenance store (under a
 * test-owned directory), wired through the plugin's own adapter
 * (`nativeProvenanceAdapter`).
 *
 * Invariant: wiring the store never changes what happens to a call — same
 * resolve/reject, same rows, same severity, same escalation — in a clean AND
 * in a tainted session (#233 escalateForTaint turns a `sensitive` allow into
 * an approval, so a signal that raised severity would have minted a HOLD;
 * this one is a separate field that nothing reads). The only difference is
 * the `nativeExec` field, and for a benign allow one extra row carrying it.
 *
 * The "native" fixture is a 64-byte ELF magic stub; nothing is executed.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../interceptor.js';
import { nativeProvenanceAdapter } from '../index.js';
import { createSessionTaintStore } from '../session-taint.js';
import { evaluateToolCall, nativeArtifactCaptures } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { createNativeArtifactProbe, createNativeProvenanceBudget, MAX_RESOLVE_COMPONENTS, MAX_RESOLVE_SYMLINKS, recordNativeArtifactCaptures } from '../../../src/defence/iron-dome/native-exec-provenance.js';

const ELF_STUB = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...new Array(56).fill(0)]);
const SESSION = 'agent-session';
const KEY = 'sc-0123456789abcdef';

/** #1025 r4: a deep `a` tree with a 39-link `a/../` chain planted at depth
 *  D-1 (a node that still has an `a` child, so every `a/..` is walkable).
 *  Depth and segment are scaled so each path and link target fits PATH_MAX
 *  (Linux 4096, macOS 1024); on Linux this is the D=2000 / 817-segment shape.
 *  Torn down iteratively (no recursive rm through 2000 levels). */
function plantLinkChain(work: string): { token: string; depth: number; teardown: () => void } {
  const pathMax = process.platform === 'darwin' ? 1024 : 4096;
  const depth = Math.min(2000, Math.floor((pathMax - work.length - 16) / 2));
  const seg = Math.min(817, Math.floor((pathMax - 8) / 5));
  const node = path.join(work, ...new Array(depth - 1).fill('a'));
  fs.mkdirSync(path.join(node, 'a'), { recursive: true });
  for (let i = 0; i < 39; i++) {
    fs.symlinkSync(`${'a/../'.repeat(seg)}${i < 38 ? `L${i + 1}` : '.'}`, path.join(node, `L${i}`));
  }
  return {
    token: `${'a/'.repeat(depth - 1)}L0/x`,
    depth,
    teardown: () => {
      for (let i = 0; i < 39; i++) fs.rmSync(path.join(node, `L${i}`), { force: true });
      for (let d = depth; d >= 1; d--) { try { fs.rmdirSync(path.join(work, ...new Array(d).fill('a'))); } catch { /* already gone */ } };
    },
  };
}

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

let root: string;
let work: string;
let stateDir: string;

beforeEach(() => {
  root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-oc-')));
  work = path.join(root, 'work');
  stateDir = path.join(root, 'state');
  fs.mkdirSync(work, { recursive: true });
});
afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

/** The defence module surface the adapter reads, bound to the test's dirs. */
function fakeDefence() {
  return {
    sessionKeyFor: (id: string | undefined) => (id === SESSION ? KEY : null),
    nativeArtifactCaptures,
    createNativeProvenanceBudget,
    createNativeArtifactProbe: (o: { sessionKey: string; cwd: string | undefined }) =>
      createNativeArtifactProbe({ ...o, stateDir, home: root }),
    recordNativeArtifactCaptures: (o: { sessionKey: string; captures: never; cwd: string | undefined }) =>
      recordNativeArtifactCaptures({ ...o, stateDir, home: root }),
  };
}

function run(opts: { wired: boolean; tainted: boolean }) {
  const captured: InterceptAuditEntry[] = [];
  const store = createSessionTaintStore();
  if (opts.tainted) store.mark(SESSION, { reason: 'conversation scan: HIGH (2 detections)' });
  const i = createInterceptor(
    { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
    okPipeline as never,
    {
      evaluateToolCall: evaluateToolCall as never,
      onAuditEntry: (e) => captured.push(e),
      sessionTaint: (sessionId) => {
        const rec = sessionId ? store.get(sessionId) : null;
        return rec ? { reason: rec.reason } : null;
      },
      ...(opts.wired ? { nativeProvenance: nativeProvenanceAdapter(fakeDefence()) } : {}),
    },
  );
  return { i, captured };
}

async function outcome(p: Promise<unknown>): Promise<string> {
  try {
    await p;
    return 'resolved';
  } catch (err) {
    return `rejected: ${err instanceof Error ? err.message : String(err)}`;
  }
}

/** Everything about a row that a decision could move. */
const decisionView = (rows: InterceptAuditEntry[]) => rows
  .filter(r => !String(r.preview).endsWith(':: native-exec'))
  .map(r => ({ tool: r.tool, action: r.action, outcome: r.outcome, severity: r.severity, threats: r.threats, escalated: r.escalated }));

/** Plant an agent-written native image: a Write the wired store records, then
 *  the bytes land. Returns nothing; both runs share the same filesystem. */
async function plant(i: ReturnType<typeof run>['i'], name: string): Promise<void> {
  await outcome(i.handleToolCall({ toolName: 'Write', arguments: { file_path: path.join(work, name), content: 'stub' }, sessionId: SESSION, cwd: work }));
  fs.writeFileSync(path.join(work, name), ELF_STUB, { mode: 0o755 });
}

describe('#1025 OpenClaw interceptor — audit-only nativeExec', () => {
  for (const tainted of [false, true]) {
    for (const command of ['./helper', './helper --version', 'LD_PRELOAD=./libx.so /bin/true', 'npm install left-pad && ./helper']) {
      it(`${tainted ? 'TAINTED' : 'clean'} session, ${JSON.stringify(command)}: decision and rows unchanged; nativeExec recorded`, async () => {
        const wired = run({ wired: true, tainted });
        await plant(wired.i, 'helper');
        await plant(wired.i, 'libx.so');
        wired.captured.length = 0;
        const wiredOutcome = await outcome(wired.i.handleToolCall({ toolName: 'Bash', arguments: { command }, sessionId: SESSION, cwd: work }));

        const plain = run({ wired: false, tainted });
        const plainOutcome = await outcome(plain.i.handleToolCall({ toolName: 'Bash', arguments: { command }, sessionId: SESSION, cwd: work }));

        expect(wiredOutcome).toBe(plainOutcome);
        expect(decisionView(wired.captured)).toEqual(decisionView(plain.captured));
        expect(plain.captured.some(r => r.nativeExec)).toBe(false);
        // the taint really applied: the non-benign calls were escalated on BOTH runs
        if (tainted && !command.startsWith('LD_PRELOAD')) {
          expect(plain.captured.some(r => r.escalated)).toBe(true);
          expect(wired.captured.some(r => r.escalated)).toBe(true);
        }

        const rows = wired.captured.filter(r => r.nativeExec);
        expect(rows.length).toBeGreaterThan(0);
        for (const r of rows) {
          expect(r.nativeExec!.uses.length).toBeGreaterThan(0);
          expect(JSON.stringify(r.nativeExec)).not.toMatch(/helper|libx|work/);
        }
      });
    }
  }

  it('a benign allow carrying the observation gets ONE name-only row; without it, none', async () => {
    const wired = run({ wired: true, tainted: false });
    await plant(wired.i, 'libx.so');
    wired.captured.length = 0;
    const plain = run({ wired: false, tainted: false });
    // `LD_PRELOAD=… /bin/true` is a benign allow today: no row at all.
    const cmd = { toolName: 'Bash', arguments: { command: 'LD_PRELOAD=./libx.so /bin/true' }, sessionId: SESSION, cwd: work };
    expect(await outcome(plain.i.handleToolCall(cmd))).toBe('resolved');
    expect(plain.captured).toHaveLength(0);
    expect(await outcome(wired.i.handleToolCall(cmd))).toBe('resolved');
    expect(wired.captured).toHaveLength(1);
    expect(wired.captured[0].preview).toBe('Bash :: native-exec');
    expect(wired.captured[0].action).toBe('allow');
    expect(wired.captured[0].severity).toBe('low');
    expect(wired.captured[0].nativeExec).toEqual({ uses: [{ action: 'load', provenance: 'agent-written' }] });
  });

  it('auditAllows:false opts the benign observation row out with the rest of the allow stream', async () => {
    const captured: InterceptAuditEntry[] = [];
    const i = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [], auditAllows: false } } as never,
      okPipeline as never,
      { evaluateToolCall: evaluateToolCall as never, onAuditEntry: (e) => captured.push(e), nativeProvenance: nativeProvenanceAdapter(fakeDefence()) },
    );
    await plant(i, 'libx.so');
    captured.length = 0;
    expect(await outcome(i.handleToolCall({ toolName: 'Bash', arguments: { command: 'LD_PRELOAD=./libx.so /bin/true' }, sessionId: SESSION, cwd: work }))).toBe('resolved');
    expect(captured).toHaveLength(0);
  });

  it('a session with no key records nothing and observes nothing (current behaviour)', async () => {
    const wired = run({ wired: true, tainted: false });
    await outcome(wired.i.handleToolCall({ toolName: 'Write', arguments: { file_path: path.join(work, 'helper'), content: 'x' }, sessionId: 'unkeyed', cwd: work }));
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 });
    await outcome(wired.i.handleToolCall({ toolName: 'Bash', arguments: { command: './helper' }, sessionId: 'unkeyed', cwd: work }));
    expect(wired.captured.some(r => r.nativeExec)).toBe(false);
    expect(fs.existsSync(path.join(stateDir, KEY))).toBe(false);
  });

  it('a store that throws is swallowed: same outcome as unwired', async () => {
    const throwing = {
      probe: () => { throw new Error('probe boom'); },
      record: () => { throw new Error('record boom'); },
    };
    const captured: InterceptAuditEntry[] = [];
    const i = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
      okPipeline as never,
      { evaluateToolCall: evaluateToolCall as never, onAuditEntry: (e) => captured.push(e), nativeProvenance: throwing },
    );
    const plain = run({ wired: false, tainted: false });
    const cmd = { toolName: 'Bash', arguments: { command: 'cc a.c -o helper && ./helper' }, sessionId: SESSION, cwd: work };
    expect(await outcome(i.handleToolCall(cmd))).toBe(await outcome(plain.i.handleToolCall(cmd)));
    expect(decisionView(captured)).toEqual(decisionView(plain.captured));
  });

  describe('fold r3 — one budget per call; a block records nothing', () => {
    function spyRun(tainted: boolean) {
      const calls: Array<{ op: string; budget: unknown }> = [];
      let made = 0;
      const store = createSessionTaintStore();
      if (tainted) store.mark(SESSION, { reason: 'conversation scan: HIGH (2 detections)' });
      const captured: InterceptAuditEntry[] = [];
      const i = createInterceptor(
        { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
        okPipeline as never,
        {
          evaluateToolCall: evaluateToolCall as never,
          onAuditEntry: (e) => captured.push(e),
          sessionTaint: (sessionId) => {
            const rec = sessionId ? store.get(sessionId) : null;
            return rec ? { reason: rec.reason } : null;
          },
          nativeProvenance: {
            budget: () => ({ id: ++made, expired: () => false }),
            probe: (_s, _c, budget) => { calls.push({ op: 'probe', budget }); return () => null; },
            record: (_t, _a, _s, _c, budget) => { calls.push({ op: 'record', budget }); },
          },
        },
      );
      return { i, calls, captured };
    }

    it('allow: probe and record get the SAME per-call budget; each call gets its own', async () => {
      const r = spyRun(false);
      const w = (n: string) => ({ toolName: 'Write', arguments: { file_path: path.join(work, n), content: 'x' }, sessionId: SESSION, cwd: work });
      await Promise.all([outcome(r.i.handleToolCall(w('a'))), outcome(r.i.handleToolCall(w('b')))]);
      const probes = r.calls.filter(c => c.op === 'probe');
      const records = r.calls.filter(c => c.op === 'record');
      expect(probes).toHaveLength(2);
      expect(records).toHaveLength(2);
      expect(new Set(probes.map(c => c.budget)).size).toBe(2); // concurrent calls never share
      for (const rec of records) expect(probes.some(p => p.budget === rec.budget)).toBe(true);
    });

    it('a catastrophic block records nothing; the decision is the same as unwired', async () => {
      const r = spyRun(false);
      const plain = run({ wired: false, tainted: false });
      const cmd = { toolName: 'Bash', arguments: { command: `${['rm', '-rf', '~'].join(' ')} ; echo hi > ./y` }, sessionId: SESSION, cwd: work };
      const got = await outcome(r.i.handleToolCall(cmd));
      expect(got).toMatch(/^rejected/);
      expect(got).toBe(await outcome(plain.i.handleToolCall(cmd)));
      expect(r.calls.filter(c => c.op === 'record')).toHaveLength(0);
    });

    it('taint that rewrites the verdict to block records nothing (asserted: the block happened)', async () => {
      const r = spyRun(true);
      // dangerous → block under taint
      await outcome(r.i.handleToolCall({ toolName: 'Bash', arguments: { command: 'git push --force origin main > ./out.txt' }, sessionId: SESSION, cwd: work }));
      expect(r.captured.some(e => e.escalated?.to === 'block')).toBe(true);
      expect(r.calls.filter(c => c.op === 'record')).toHaveLength(0);
    });

    it('taint that rewrites an allow to require_approval still records, with the probe\'s budget', async () => {
      const r = spyRun(true);
      await outcome(r.i.handleToolCall({ toolName: 'Bash', arguments: { command: 'npm install left-pad > ./out.txt' }, sessionId: SESSION, cwd: work }));
      expect(r.captured.some(e => e.escalated?.to === 'require_approval')).toBe(true);
      const records = r.calls.filter(c => c.op === 'record');
      expect(records).toHaveLength(1);
      expect(r.calls.find(c => c.op === 'probe')!.budget).toBe(records[0].budget);
    });
  });

  it('r4: deep tree + 39-link a/../ chain naming .../L0/x — catastrophic and require_approval are fast and decision-identical; realpath(3) never runs', async () => {
    const chain = plantLinkChain(work);
    try {
      if (process.platform === 'linux') expect(chain.depth).toBe(2000);
      const native = jest.spyOn(fs.realpathSync, 'native');
      const readlink = jest.spyOn(fs, 'readlinkSync');
      const lstats = jest.spyOn(fs, 'lstatSync');
      const wired = run({ wired: true, tainted: false });
      await plant(wired.i, 'seed'); // a non-empty session store
      const cases: Array<[string, RegExp, boolean]> = [
        [`${['rm', '-rf', '~'].join(' ')} ; ./${chain.token}`, /^rejected/, false],
        [`${['rm', '-rf', '~'].join(' ')} ; echo hi > ${chain.token}`, /^rejected/, false],
        [`git push --force origin main > ${chain.token}`, /^rejected/, true],
      ];
      for (const [command, want, resolves] of cases) {
        wired.captured.length = 0;
        readlink.mockClear();
        lstats.mockClear();
        const cmd = { toolName: 'Bash', arguments: { command }, sessionId: SESSION, cwd: work };
        const started = Date.now();
        const got = await outcome(wired.i.handleToolCall(cmd));
        const ms = Date.now() - started;
        const plain = run({ wired: false, tainted: false });
        expect(got).toMatch(want);
        expect(got).toBe(await outcome(plain.i.handleToolCall(cmd)));
        expect(decisionView(wired.captured)).toEqual(decisionView(plain.captured));
        expect(ms).toBeLessThan(3000); // unbounded realpath(3) stalled ~11 s here
        const walked = lstats.mock.calls.filter(([q]) => String(q).startsWith(work)).length;
        if (resolves) {
          // The ask tier still resolves (probe + record share one memoised walk).
          expect(walked).toBeGreaterThan(0);
          expect(walked).toBeLessThanOrEqual(2 * MAX_RESOLVE_COMPONENTS);
          expect(readlink.mock.calls.length).toBeLessThanOrEqual(2 * MAX_RESOLVE_SYMLINKS);
        } else {
          // A catastrophic block is terminal: no store work on its path.
          expect(walked).toBe(0);
        }
      }
      const askRow = wired.captured.find((r) => r.action === 'require_approval');
      expect(askRow).toBeDefined();
      expect(native).not.toHaveBeenCalled();
    } finally {
      jest.restoreAllMocks();
      chain.teardown();
    }
  }, 120_000);

  it('the adapter is undefined on an older dist without the exports', () => {
    expect(nativeProvenanceAdapter({ sessionKeyFor: () => KEY })).toBeUndefined();
    expect(nativeProvenanceAdapter(null)).toBeUndefined();
  });
});
