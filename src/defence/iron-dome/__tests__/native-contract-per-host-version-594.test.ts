/**
 * #594 — ADR-002 §5C: the `openclaw.sessions_spawn` contract is judged PER
 * HOST VERSION, ordinary coordinator dispatch is quiet at the pinned release,
 * and unknown-field reporting survives every selection. Each part FAILS with
 * its fix removed:
 *
 *   1. the record     — the revisions in `tool-input-schema.ts` equal the
 *                       measurement record in `scripts/native-contracts/`,
 *                       ascending, at least two; a hand-widened table with no
 *                       measurement landing in the record turns this red.
 *   2. the measurer   — the Node-core parser reads a bundle in the host's
 *                       shape (gated blocks, a named spread, nested values) to
 *                       the declared field set, and refuses an unresolved
 *                       spread rather than recording a partial set.
 *   3. the selection  — exact / floor / beyond / below / unknown-host, each
 *                       named; a prerelease sorts below its release; an
 *                       unparseable or absent version is `unknown-host`, never
 *                       a guess; host-supplied text is neutralised and bounded.
 *   4. quiet dispatch — the ordinary coordinator spawn at the pinned release
 *                       drops ZERO keys and observes no drift; the same call
 *                       judged by the older revision reports
 *                       `expectsCompletionMessage` WITH the reason.
 *   5. reporting kept — a field no measured host declares is reported at every
 *                       selection; a field the host REMOVED is reported at the
 *                       release that removed it; an evidence key is fail-closed
 *                       at every selection; nothing in any revision is an
 *                       evidence key.
 *   6. the wire       — the interceptor's one-line warning names the judging
 *                       revision and the reason, still one physical line, and
 *                       the audit row carries the revision.
 */
import { afterEach, describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import {
  enforceToolInput,
  contractDriftFor,
  compareHostVersions,
  resolveOpenClawSpawnContract,
  currentOpenClawSpawnContract,
  measuredOpenClawSpawnRevisions,
  setNativeHostVersion,
  nativeHostVersion,
  GUARD_EVIDENCE_KEYS,
} from '../tool-input-schema.js';
import type { ContractRevisionSelection } from '../tool-input-schema.js';
import { evaluateToolCall } from '../tool-action-guard.js';
import { createInterceptor, DEFAULT_CONFIG, describeDriftRevision } from '../../../../plugins/openclaw/interceptor.js';
import {
  measureSessionsSpawnSource,
  declaredTopLevelKeys,
  // @ts-expect-error — plain ESM, no types
} from '../../../../scripts/lib/native-contract-measure.mjs';

const RECORD_PATH = path.resolve(process.cwd(), 'scripts', 'native-contracts', 'openclaw-sessions-spawn.json');
const record = JSON.parse(readFileSync(RECORD_PATH, 'utf8')) as {
  contract: string;
  revisions: { hostVersion: string; fields: string[]; evidence: { kind: string }; measuredOn: string }[];
};
const revisions = measuredOpenClawSpawnRevisions();
const OLDEST = revisions[0]!.hostVersion;
const NEWEST = revisions[revisions.length - 1]!.hostVersion;

/** The spawn an ordinary coordinator sends. Measured from live dispatch, not invented. */
const ORDINARY_DISPATCH: Record<string, unknown> = {
  task: 'review the failing suite and report',
  label: 'review',
  runtime: 'subagent',
  mode: 'run',
  cleanup: 'keep',
  context: 'isolated',
  lightContext: false,
  expectsCompletionMessage: true,
};

/** Every field the current release declares beyond the older revision. */
const DECLARED_SINCE_OLDEST = {
  expectsCompletionMessage: true,
  completionTarget: 'parent',
  group: 'Reviews',
  projectId: 'proj-1',
  projectGitUrl: 'https://github.com/example/example',
  placement: { kind: 'local' },
};

const ALL_SELECTIONS: { host: string | null; selection: ContractRevisionSelection }[] = [
  { host: NEWEST, selection: 'exact' },
  { host: OLDEST, selection: 'exact' },
  { host: '2026.9.5', selection: 'floor' },
  { host: '2027.1.1', selection: 'beyond' },
  { host: '2026.7.30', selection: 'below' },
  { host: null, selection: 'unknown-host' },
];

afterEach(() => setNativeHostVersion('openclaw', null));

describe('1. the table is pinned to the measurement record', () => {
  it('names the contract and carries at least two revisions, ascending', () => {
    expect(record.contract).toBe('openclaw.sessions_spawn');
    expect(record.revisions.length).toBeGreaterThanOrEqual(2);
    for (let i = 1; i < record.revisions.length; i++) {
      expect(compareHostVersions(record.revisions[i - 1]!.hostVersion, record.revisions[i]!.hostVersion)).toBe(-1);
    }
  });

  it('every revision in code equals the record, version for version, field for field', () => {
    expect(revisions.map((r) => r.hostVersion)).toEqual(record.revisions.map((r) => r.hostVersion));
    for (const r of revisions) {
      const rec = record.revisions.find((x) => x.hostVersion === r.hostVersion)!;
      expect(r.keys).toEqual([...rec.fields].sort());
      expect(rec.evidence.kind).toMatch(/^(dist-schema|source-read)$/);
      expect(rec.measuredOn).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    }
  });

  it('the current release was measured from the shipped dist, not transcribed', () => {
    const newest = record.revisions[record.revisions.length - 1]!;
    expect(newest.evidence.kind).toBe('dist-schema');
    expect(newest.fields).toEqual(expect.arrayContaining(Object.keys(DECLARED_SINCE_OLDEST)));
    expect(newest.fields).not.toContain('category');
  });
});

describe('2. the measurer reads the host bundle shape', () => {
  const BUNDLE = [
    'const OTHER = { a: 1 };',
    'const VISIBLE_SESSIONS_SPAWN_SCHEMA = {',
    '\tplacement: Type.Optional({ ...Placement, description: "x: y" }),',
    '\tvisible: Type.Optional(Type.Boolean({ description: "not a field: {nope: 1}" })),',
    '\tworktree: Type.Optional(Type.Boolean()),',
    '};',
    'function createSessionsSpawnToolSchema(params) {',
    '\tconst schema = {',
    '\t\ttask: Type.String(),',
    '\t\t// comment: { fake: 1 },',
    '\t\tlabel: Type.Optional(Type.String({ description: `tmpl ${"z"}: {a:1}` })),',
    '\t\t...params.threadAvailable ? { thread: Type.Optional(Type.Boolean()) } : {},',
    '\t\tmode: optionalStringEnum(["run", "session"], { description: "a, b" }),',
    '\t\t...params.swarmEnabled ? {',
    '\t\t\tcollect: Type.Optional(Type.Boolean()),',
    '\t\t\toutputSchema: Type.Optional(Type.Record(Type.String(), Type.Unknown()))',
    '\t\t} : {},',
    '\t\t...VISIBLE_SESSIONS_SPAWN_SCHEMA,',
    '\t\tattachments: Type.Optional(Type.Array(Type.Object({ name: Type.String(), content: Type.String() }))),',
    '\t\t...params.acpAvailable ? { streamTo: Type.Optional(Type.String()) } : { legacyOnly: Type.Optional(Type.String()) }',
    '\t};',
    '\treturn Type.Object(schema);',
    '}',
  ].join('\n');

  it('collects base, gated (both branches), spread-named and array-valued fields; nothing nested', () => {
    const { fields, unresolved } = measureSessionsSpawnSource(BUNDLE);
    expect(unresolved).toEqual([]);
    expect(fields).toEqual([
      'attachments', 'collect', 'label', 'legacyOnly', 'mode', 'outputSchema', 'placement',
      'streamTo', 'task', 'thread', 'visible', 'worktree',
    ].sort());
    // nested names never surface as declared fields
    for (const nested of ['name', 'content', 'description', 'fake', 'nope', 'a']) expect(fields).not.toContain(nested);
  });

  it('refuses a spread it cannot resolve rather than recording a partial set', () => {
    const src = BUNDLE.replace('...VISIBLE_SESSIONS_SPAWN_SCHEMA,', '...IMPORTED_ELSEWHERE,');
    const { unresolved } = measureSessionsSpawnSource(src);
    expect(unresolved).toEqual(['IMPORTED_ELSEWHERE']);
  });

  it('fails loudly when the builder anchor is absent', () => {
    expect(() => measureSessionsSpawnSource('const x = { a: 1 };')).toThrow(/anchor not found/);
  });

  it('declaredTopLevelKeys ignores braces inside strings and comments', () => {
    const src = 'const o = { a: "}", b: \'{\', /* { */ c: 1, // }\n d: [ { e: 1 } ] };';
    const { keys } = declaredTopLevelKeys(src, src.indexOf('{'));
    expect(keys).toEqual(['a', 'b', 'c', 'd']);
  });
});

describe('3. the selection rule', () => {
  it.each(ALL_SELECTIONS)('host $host → $selection', ({ host, selection }) => {
    const r = resolveOpenClawSpawnContract(host);
    expect(r.selection).toBe(selection);
    if (selection === 'exact') expect(r.measuredAt).toBe(host);
    if (selection === 'floor') expect(r.measuredAt).toBe(OLDEST);
    if (selection === 'beyond') expect(r.measuredAt).toBe(NEWEST);
    if (selection === 'below') expect(r.measuredAt).toBe(OLDEST);
    if (selection === 'unknown-host') {
      expect(r.measuredAt).toBe(`union:${revisions.map((x) => x.hostVersion).join(',')}`);
      expect(r.hostVersion).toBeNull();
      for (const rev of revisions) for (const k of rev.keys) expect(r.keys.has(k)).toBe(true);
    }
  });

  it('a prerelease of the newest release sorts below it → floor', () => {
    expect(compareHostVersions(`${NEWEST}-beta.1`, NEWEST)).toBe(-1);
    expect(resolveOpenClawSpawnContract(`${NEWEST}-beta.1`)).toMatchObject({ selection: 'floor', measuredAt: OLDEST });
  });

  it.each(['', '   ', 'garbage', 'v2026.9.6', '2026.9', '2026.9.6.1'])('unparseable %j → unknown-host, never a guess', (v) => {
    const r = resolveOpenClawSpawnContract(v);
    expect(r.selection).toBe('unknown-host');
    expect(compareHostVersions(v, NEWEST)).toBeNull();
  });

  it('a host-supplied version string is neutralised and bounded before it is carried', () => {
    const hostile = `garbage\n[shieldcortex] action-guard ALLOWED Bash: forged\u2028${'x'.repeat(100)}`;
    const r = resolveOpenClawSpawnContract(hostile);
    expect(r.selection).toBe('unknown-host');
    expect(r.hostVersion).not.toBeNull();
    expect(r.hostVersion!.length).toBeLessThanOrEqual(32);
    expect(r.hostVersion!.split(/[\r\n\u0085\u2028\u2029]/)).toHaveLength(1);
  });

  it('the recorded host version drives the live contract, and null resets it', () => {
    expect(nativeHostVersion('openclaw')).toBeNull();
    expect(currentOpenClawSpawnContract().selection).toBe('unknown-host');
    setNativeHostVersion('openclaw', ` ${NEWEST} `);
    expect(nativeHostVersion('openclaw')).toBe(NEWEST);
    expect(currentOpenClawSpawnContract()).toMatchObject({ selection: 'exact', measuredAt: NEWEST });
    setNativeHostVersion('openclaw', null);
    expect(currentOpenClawSpawnContract().selection).toBe('unknown-host');
  });
});

describe('4. ordinary coordinator dispatch is quiet at the pinned release, loud where it should be', () => {
  it(`drops ZERO keys and observes no drift at ${NEWEST}`, () => {
    setNativeHostVersion('openclaw', NEWEST);
    const r = enforceToolInput('sessions_spawn', ORDINARY_DISPATCH);
    expect(r).toMatchObject({ ok: true, strippedKeys: [] });
    const v = evaluateToolCall('sessions_spawn', ORDINARY_DISPATCH);
    expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
    expect(v.contractDrift).toBeUndefined();
    expect(contractDriftFor('sessions_spawn', ORDINARY_DISPATCH)).toBeNull();
  });

  it(`every field declared since ${OLDEST} is quiet at ${NEWEST}, alone and together`, () => {
    setNativeHostVersion('openclaw', NEWEST);
    for (const [k, val] of Object.entries(DECLARED_SINCE_OLDEST)) {
      expect(enforceToolInput('sessions_spawn', { task: 'work', [k]: val })).toMatchObject({ ok: true, strippedKeys: [] });
    }
    const all = { ...ORDINARY_DISPATCH, ...DECLARED_SINCE_OLDEST };
    expect(enforceToolInput('sessions_spawn', all)).toMatchObject({ ok: true, strippedKeys: [] });
    expect(evaluateToolCall('sessions_spawn', all).contractDrift).toBeUndefined();
  });

  it(`the same dispatch judged by ${OLDEST} reports expectsCompletionMessage WITH the reason (exact)`, () => {
    setNativeHostVersion('openclaw', OLDEST);
    const v = evaluateToolCall('sessions_spawn', ORDINARY_DISPATCH);
    expect(v).toMatchObject({ decision: 'allow' });
    expect(v.contractDrift).toEqual({
      contract: 'openclaw.sessions_spawn',
      droppedKeys: ['expectsCompletionMessage'],
      revision: { measuredAt: OLDEST, hostVersion: OLDEST, selection: 'exact' },
    });
  });

  it('a host between measurements is judged by the floor and says so', () => {
    setNativeHostVersion('openclaw', '2026.9.5');
    const d = contractDriftFor('sessions_spawn', ORDINARY_DISPATCH);
    expect(d).toEqual({
      contract: 'openclaw.sessions_spawn',
      droppedKeys: ['expectsCompletionMessage'],
      revision: { measuredAt: OLDEST, hostVersion: '2026.9.5', selection: 'floor' },
    });
  });

  it('a host newer than every measurement is judged by the newest and says "beyond"', () => {
    setNativeHostVersion('openclaw', '2027.1.1');
    expect(contractDriftFor('sessions_spawn', ORDINARY_DISPATCH)).toBeNull();
    const d = contractDriftFor('sessions_spawn', { ...ORDINARY_DISPATCH, fieldShippedNextYear: 1 });
    expect(d).toEqual({
      contract: 'openclaw.sessions_spawn',
      droppedKeys: ['fieldShippedNextYear'],
      revision: { measuredAt: NEWEST, hostVersion: '2027.1.1', selection: 'beyond' },
    });
  });

  it('an unknown host is judged by the union: no measured field is reported', () => {
    expect(nativeHostVersion('openclaw')).toBeNull();
    const all = { ...ORDINARY_DISPATCH, ...DECLARED_SINCE_OLDEST, category: 'Review', timeoutSeconds: 5 };
    expect(enforceToolInput('sessions_spawn', all)).toMatchObject({ ok: true, strippedKeys: [] });
    expect(contractDriftFor('sessions_spawn', all)).toBeNull();
  });
});

describe('5. unknown-field reporting is preserved at every selection', () => {
  it.each(ALL_SELECTIONS)('host $host ($selection): a never-declared field is dropped and reported, never denied', ({ host, selection }) => {
    setNativeHostVersion('openclaw', host);
    const args = { task: 'work', hostFieldShippedNextMonth: 'sk-NOT-A-SECRET-BUT-STILL-A-VALUE' };
    const r = enforceToolInput('sessions_spawn', args);
    expect(r).toMatchObject({ ok: true, strippedKeys: ['hostFieldShippedNextMonth'] });
    if (r.ok) expect(r.args).not.toHaveProperty('hostFieldShippedNextMonth');
    const d = contractDriftFor('sessions_spawn', args);
    expect(d?.droppedKeys).toEqual(['hostFieldShippedNextMonth']);
    expect(d?.revision?.selection).toBe(selection);
    expect(JSON.stringify(d)).not.toContain('sk-NOT-A-SECRET');
    expect(evaluateToolCall('sessions_spawn', args)).toMatchObject({ decision: 'allow' });
  });

  it(`a field the host REMOVED (category) is reported at ${NEWEST} — a dropped field never keeps semantics`, () => {
    setNativeHostVersion('openclaw', NEWEST);
    const d = contractDriftFor('sessions_spawn', { task: 'work', category: 'Review' });
    expect(d?.droppedKeys).toEqual(['category']);
    expect(d?.revision).toMatchObject({ measuredAt: NEWEST, selection: 'exact' });
    setNativeHostVersion('openclaw', OLDEST);
    expect(contractDriftFor('sessions_spawn', { task: 'work', category: 'Review' })).toBeNull();
  });

  it.each(ALL_SELECTIONS)('host $host ($selection): an evidence key stays fail-closed', ({ host }) => {
    setNativeHostVersion('openclaw', host);
    for (const key of ['command', 'argv', 'cmd']) {
      expect(GUARD_EVIDENCE_KEYS.has(key)).toBe(true);
      const r = enforceToolInput('sessions_spawn', { task: 'work', [key]: 'echo hi' });
      expect(r).toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    }
  });

  it('no revision, and not the union, declares an evidence key', () => {
    for (const r of revisions) for (const k of r.keys) expect(GUARD_EVIDENCE_KEYS.has(k)).toBe(false);
    for (const k of resolveOpenClawSpawnContract(null).keys) expect(GUARD_EVIDENCE_KEYS.has(k)).toBe(false);
  });
});

describe('6. the interceptor names the judging revision on one physical line', () => {
  function harness() {
    const lines: string[] = [];
    const audits: any[] = [];
    const interceptor = createInterceptor(
      {
        ...DEFAULT_CONFIG,
        actionGuard: { enabled: true, enforce: true, autoApprove: [] },
        logger: { info: () => {}, warn: (m: string) => { lines.push(String(m)); } },
      } as never,
      (() => ({
        allowed: true,
        firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [], anomalyScore: 0, blockedPatterns: [] },
        trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
      })) as never,
      { evaluateToolCall: evaluateToolCall as never, onAuditEntry: (e: unknown) => { audits.push(e); } } as never,
    );
    return { interceptor, lines, audits };
  }

  it('describeDriftRevision: one clause per selection, re-measure only where the measurement is older than the host', () => {
    expect(describeDriftRevision(undefined)).toBe('');
    expect(describeDriftRevision({ measuredAt: NEWEST, hostVersion: NEWEST, selection: 'exact' })).not.toMatch(/re-measure/);
    expect(describeDriftRevision({ measuredAt: OLDEST, hostVersion: '2026.9.5', selection: 'floor' })).toMatch(/re-measure/);
    expect(describeDriftRevision({ measuredAt: NEWEST, hostVersion: '2027.1.1', selection: 'beyond' })).toMatch(/re-measure/);
    expect(describeDriftRevision({ measuredAt: OLDEST, hostVersion: '2026.7.30', selection: 'below' })).not.toMatch(/re-measure/);
    expect(describeDriftRevision({ measuredAt: 'union:a,b', hostVersion: null, selection: 'unknown-host' })).toMatch(/host version unknown/);
  });

  it('beyond: the warning says which revision judged the call and to re-measure; still one line; audit row carries it', async () => {
    setNativeHostVersion('openclaw', '2027.1.1');
    const h = harness();
    await expect(h.interceptor.handleToolCall({
      toolName: 'sessions_spawn',
      arguments: { ...ORDINARY_DISPATCH, fieldShippedNextYear: 'v' },
    })).resolves.toBeUndefined();
    const drift = h.lines.filter((l) => l.includes('CONTRACT DRIFT'));
    expect(drift).toHaveLength(1);
    expect(drift[0]!.startsWith('[shieldcortex] action-guard CONTRACT DRIFT sessions_spawn (openclaw.sessions_spawn; judged by revision ')).toBe(true);
    expect(drift[0]).toContain(`judged by revision ${NEWEST}, older than host 2027.1.1 — re-measure the host`);
    expect(drift[0]!.indexOf('dropped unread field(s) fieldShippedNextYear')).toBeGreaterThan(drift[0]!.indexOf('re-measure'));
    for (const line of h.lines) expect(line.split(/[\r\n\u0085\u2028\u2029]/)).toHaveLength(1);
    expect(h.audits.some((a) => a?.contractDrift?.revision?.selection === 'beyond' && a?.contractDrift?.revision?.measuredAt === NEWEST)).toBe(true);
  });

  it(`exact at ${NEWEST}: ordinary dispatch writes NO drift line at all`, async () => {
    setNativeHostVersion('openclaw', NEWEST);
    const h = harness();
    await expect(h.interceptor.handleToolCall({ toolName: 'sessions_spawn', arguments: ORDINARY_DISPATCH })).resolves.toBeUndefined();
    expect(h.lines.filter((l) => l.includes('CONTRACT DRIFT'))).toHaveLength(0);
  });
});
