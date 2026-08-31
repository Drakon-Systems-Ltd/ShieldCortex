/**
 * Native contract drift — the closed exact-special bag stops being a staleness
 * alarm wired to the deny path.
 *
 * The bag was doing two jobs. Evidence discipline (a command-bearing key on a
 * delegation tool must be SCANNED, not read-short-circuited) is load-bearing.
 * Novelty rejection (deny any key not enumerated when the contract was last
 * measured) is not: every downstream reader in the guard is a FIXED-KEY lookup,
 * so a key outside `GUARD_EVIDENCE_KEYS` is provably unreachable by every
 * scanner. Denying it bought nothing and cost a card storm on ordinary work —
 * 13 of `sessions_spawn`'s 28 live fields hard-denied, and three hand-widenings
 * in a row (#436 BashOutput, #445 TaskOutput, this).
 *
 * The fold splits the unknown-key verdict by SCANNABILITY, not by membership:
 *   - unknown key IN  GUARD_EVIDENCE_KEYS → unchanged fail-closed + raw rescan
 *   - unknown key OUT of it → dropped before nested validation and before any
 *     extractor, call proceeds, key NAME reported as a drift observation
 *
 * This file is table-driven against the canonical sources on purpose: the field
 * list is derived from the live host schema and the evidence list from
 * ShieldCortex's own reader lists, so a migration cannot be forgotten (the
 * lesson `doctor-schema-drift.test.ts` already paid for, on a different plane).
 */
import { describe, expect, it } from '@jest/globals';
import {
  enforceToolInput,
  contractDriftFor,
  hasExactSpecialToolSchema,
  exactSpecialContractName,
  schemaFamilyForTool,
  GUARD_EVIDENCE_KEYS,
  COMMAND_KEYS,
  PATH_KEYS,
  URL_KEYS,
  WRITE_CONTENT_KEYS,
  COMMAND_EVIDENCE_KEYS,
  OUTBOUND_DATA_KEYS,
  OUTBOUND_METHOD_KEYS,
  CONTRACT_DRIFT_MAX_KEYS,
} from '../tool-input-schema.js';
import {
  evaluateToolCall,
  extractCommand,
  extractPath,
  extractUrl,
  extractWriteContent,
} from '../tool-action-guard.js';
import { createInterceptor, DEFAULT_CONFIG } from '../../../../plugins/openclaw/interceptor.js';

/**
 * Every top-level field of the LIVE `createSessionsSpawnToolSchema`
 * (`openclaw/src/agents/tools/sessions-spawn-tool.ts`) with every capability
 * flag on — the base block, the swarm block, `VISIBLE_SESSIONS_SPAWN_SCHEMA`
 * (`sessions-spawn-visible.ts`), the attachment block and the ACP block.
 * Measured against the host source, not guessed.
 */
const LIVE_SPAWN_FIELDS: Record<string, unknown> = {
  task: 'inspect the failing tests',
  taskName: 'review_tests',
  label: 'review',
  runtime: 'subagent',
  agentId: 'edith',
  model: 'default',
  runTimeoutSeconds: 600,
  thinking: 'medium',
  cwd: '/workspace/repo',
  thread: true,
  mode: 'run',
  cleanup: 'delete',
  sandbox: 'inherit',
  context: 'bounded',
  lightContext: true,
  collect: true,
  outputSchema: {
    type: 'object',
    properties: { verdict: { type: 'string' }, findings: { type: 'array' } },
    required: ['verdict'],
  },
  fastMode: 'auto',
  groupId: 'swarm-1',
  visible: true,
  category: 'Review',
  worktree: true,
  worktreeName: 'wt-review',
  worktreeBaseRef: 'main',
  attachments: [{ name: 'notes.txt', content: 'hello', encoding: 'utf8', mimeType: 'text/plain' }],
  attachAs: { mountPath: '/mnt/attachments' },
  resumeSessionId: 'sess-01HX',
  streamTo: 'parent',
};

const SPAWN_ALIASES = [
  'sessions_spawn',
  'openclawsessions_spawn',
  'openclaw.sessions_spawn',
  'openclaw__sessions_spawn',
] as const;

describe('live sessions_spawn contract — 28-field coverage', () => {
  it('the fixture IS the live contract: exactly 28 declared top-level fields', () => {
    expect(Object.keys(LIVE_SPAWN_FIELDS)).toHaveLength(28);
  });

  it.each(Object.keys(LIVE_SPAWN_FIELDS))(
    'declared field %s is accepted alone, with no card and no drift',
    (field) => {
      const args = { task: 'work', [field]: LIVE_SPAWN_FIELDS[field] };
      expect(enforceToolInput('sessions_spawn', args)).toMatchObject({ ok: true });
      const v = evaluateToolCall('sessions_spawn', args);
      expect(v.decision).toBe('allow');
      expect(v.action).not.toBe('invalid_tool_input');
      expect(v.contractDrift).toBeUndefined();
    },
  );

  it.each(SPAWN_ALIASES)('%s accepts all 28 fields at once, forward and reversed', (tool) => {
    for (const args of [
      LIVE_SPAWN_FIELDS,
      Object.fromEntries(Object.entries(LIVE_SPAWN_FIELDS).reverse()),
    ]) {
      expect(enforceToolInput(tool, args)).toMatchObject({ ok: true });
      expect(evaluateToolCall(tool, args)).toMatchObject({ decision: 'allow', severity: 'benign' });
    }
  });

  it('the minimal modern spawn that used to block on `visible` is clean', () => {
    const v = evaluateToolCall('sessions_spawn', {
      task: 'inspect tests', runtime: 'subagent', visible: true, worktree: true,
    });
    expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
  });

  it('nested outputSchema passes: an inert declared field is deleted, not judged', () => {
    const args = { task: 'work', collect: true, outputSchema: LIVE_SPAWN_FIELDS.outputSchema };
    const r = enforceToolInput('sessions_spawn', args);
    expect(r).toMatchObject({ ok: true });
    // Deleted before validateNested AND before the extractors — never forwarded.
    if (r.ok) {
      expect(r.args).not.toHaveProperty('outputSchema');
      expect(r.strippedKeys).not.toContain('outputSchema');
    }
    expect(evaluateToolCall('sessions_spawn', args)).toMatchObject({ decision: 'allow' });
    // A JSON Schema three levels deep still does not reach validateNested.
    const deep = {
      task: 'work',
      outputSchema: { properties: { a: { properties: { b: { type: 'string' } } } } },
    };
    expect(enforceToolInput('sessions_spawn', deep)).toMatchObject({ ok: true });
  });
});

describe('the scannability split', () => {
  const EVIDENCE = [...new Set([
    ...COMMAND_KEYS, ...PATH_KEYS, ...URL_KEYS, ...WRITE_CONTENT_KEYS,
    ...COMMAND_EVIDENCE_KEYS, ...OUTBOUND_DATA_KEYS, ...OUTBOUND_METHOD_KEYS,
  ])];

  it('GUARD_EVIDENCE_KEYS covers every list the guard actually reads', () => {
    for (const k of EVIDENCE) expect(GUARD_EVIDENCE_KEYS.has(k)).toBe(true);
    // args/argv are the recovery-scan surfaces; losing them would make a wipe
    // in a token array inert, which is the exact smuggle this file guards.
    expect(GUARD_EVIDENCE_KEYS.has('args')).toBe(true);
    expect(GUARD_EVIDENCE_KEYS.has('argv')).toBe(true);
  });

  it('every evidence key is genuinely read by an extractor or evidence pass', () => {
    // Not a tautology over the constant: drive the real extractors. A key that
    // no reader consults must not be claimed as evidence, and vice versa.
    for (const k of [...COMMAND_KEYS]) expect(extractCommand({ [k]: 'probe' })).toBe('probe');
    for (const k of [...PATH_KEYS]) expect(extractPath({ [k]: 'probe' })).toBe('probe');
    for (const k of [...URL_KEYS]) expect(extractUrl({ [k]: 'probe' })).toBe('probe');
    for (const k of [...WRITE_CONTENT_KEYS]) expect(extractWriteContent({ [k]: 'probe' })).toBe('probe');
  });

  it('no declared field of a reviewed contract is an evidence key', () => {
    // The invariant the whole fold rests on: a contract may not hand a caller a
    // scanner-visible field under a reviewed name.
    for (const field of Object.keys(LIVE_SPAWN_FIELDS)) {
      expect(GUARD_EVIDENCE_KEYS.has(field)).toBe(false);
    }
    for (const field of ['search_query', 'open', 'click', 'find', 'image_query',
      'calculator', 'weather', 'finance', 'sports', 'time', 'response_length']) {
      expect(GUARD_EVIDENCE_KEYS.has(field)).toBe(false);
    }
  });

  it.each(EVIDENCE)(
    'an UNDECLARED evidence key %s on a spawn still fails closed — no drop, no drift',
    (key) => {
      const args = { task: 'work', [key]: 'echo hello' };
      const r = enforceToolInput('sessions_spawn', args);
      expect(r).toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
      if (!r.ok) expect(r.unknownKeys).toContain(key);
      expect(contractDriftFor('sessions_spawn', args)).toBeNull();
      expect(evaluateToolCall('sessions_spawn', args)).toMatchObject({
        decision: 'require_approval', action: 'invalid_tool_input',
      });
    },
  );

  it('an undeclared INERT key is dropped and reported, never denied', () => {
    const args = { task: 'work', brandNewHostField: 'anything at all', another_one: 42 };
    const r = enforceToolInput('sessions_spawn', args);
    expect(r).toMatchObject({ ok: true });
    if (r.ok) {
      expect(r.args).toEqual({ task: 'work' });
      expect(r.strippedKeys).toEqual(['brandNewHostField', 'another_one']);
    }
    expect(evaluateToolCall('sessions_spawn', args)).toMatchObject({
      decision: 'allow',
      severity: 'benign',
      contractDrift: {
        contract: 'openclaw.sessions_spawn',
        droppedKeys: ['brandNewHostField', 'another_one'],
      },
    });
  });

  it('a dropped key never reaches validateNested, whatever its shape', () => {
    for (const value of [
      { deeply: { nested: { object: 1 } } },
      [[['a'], ['b']], [['c']]],
      { a: { b: { c: { d: { e: 'f' } } } } },
    ]) {
      expect(enforceToolInput('sessions_spawn', { task: 'work', futureField: value }))
        .toMatchObject({ ok: true });
    }
  });

  it('an empty-valued undeclared key is still dropped, not silently skipped', () => {
    const drift = contractDriftFor('sessions_spawn', { task: 'work', futureField: '' });
    expect(drift?.droppedKeys).toEqual(['futureField']);
  });

  it('prototype pollution is rejected before the split can look at it', () => {
    for (const bad of ['__proto__', 'constructor', 'prototype']) {
      const args = JSON.parse(`{"task":"work","${bad}":{"polluted":true}}`);
      expect(enforceToolInput('sessions_spawn', args)).toMatchObject({ ok: false });
    }
  });

  it('the drift observation is bounded and carries names only, never values', () => {
    const args: Record<string, unknown> = { task: 'work' };
    for (let i = 0; i < CONTRACT_DRIFT_MAX_KEYS + 5; i++) args[`f${i}`] = `secret-value-${i}`;
    args['x'.repeat(300)] = 'sk-LIVE-SECRET';
    const drift = contractDriftFor('sessions_spawn', args)!;
    expect(drift.droppedKeys).toHaveLength(CONTRACT_DRIFT_MAX_KEYS);
    expect(drift.truncated).toBe(true);
    for (const k of drift.droppedKeys) expect(k.length).toBeLessThanOrEqual(64);
    expect(JSON.stringify(drift)).not.toContain('secret-value');
    expect(JSON.stringify(drift)).not.toContain('sk-LIVE-SECRET');
  });

  it('non-special tools keep the old behaviour: no drop, no drift', () => {
    expect(contractDriftFor('Bash', { command: 'ls', evil: 'x' })).toBeNull();
    expect(enforceToolInput('Bash', { command: 'ls', evil: 'x' }))
      .toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    expect(evaluateToolCall('Bash', { command: 'ls', evil: 'x' }).contractDrift).toBeUndefined();
  });
});

describe('OpenClaw native exec contract (2026.8.1 live bag)', () => {
  const LIVE_EXEC = {
    command: 'date -u +%F',
    workdir: '/home/ubuntu/clawd',
    env: { LANG: 'C' },
    yieldMs: 10_000,
    background: false,
    timeoutSeconds: 30,
    pty: false,
    elevated: false,
    host: 'gateway',
    security: 'allowlist',
    ask: 'off',
    node: 'clawdbot1',
  };

  it('exact native exec is an exact-special exec contract', () => {
    expect(hasExactSpecialToolSchema('exec')).toBe(true);
    expect(exactSpecialContractName('exec')).toBe('openclaw.exec');
    expect(schemaFamilyForTool('exec')).toBe('exec');
  });

  it('the live OpenClaw exec bag is zero-card / allow', () => {
    expect(enforceToolInput('exec', LIVE_EXEC)).toMatchObject({ ok: true });
    expect(evaluateToolCall('exec', LIVE_EXEC)).toMatchObject({
      decision: 'allow',
      severity: 'benign',
    });
    expect(evaluateToolCall('exec', LIVE_EXEC).contractDrift).toBeUndefined();
  });

  it('OpenClaw exec.host is not treated as a URL destination', () => {
    expect(extractUrl({ host: 'gateway' }, 'exec')).toBe('');
    expect(extractUrl({ host: 'https://evil.example' }, 'exec')).toBe('');
    expect(extractUrl({ host: 'gateway' })).toBe('gateway');
  });

  it('MCP and unknown wrappers do not inherit native exec relief', () => {
    expect(hasExactSpecialToolSchema('mcp__openclaw__exec')).toBe(false);
    expect(enforceToolInput('mcp__openclaw__exec', LIVE_EXEC))
      .toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    expect(evaluateToolCall('some_exec_like_mcp_wrapper', LIVE_EXEC).decision)
      .not.toBe('allow');
  });

  it('a command wipe on native exec stays catastrophic and doorless', () => {
    const BIN = String.fromCharCode(114, 109);
    const WIPE = [BIN, ['-', 'r', 'f'].join(''), '/'].join(' ');
    expect(evaluateToolCall('exec', { ...LIVE_EXEC, command: WIPE })).toMatchObject({
      decision: 'block',
      severity: 'catastrophic',
    });
  });
});

describe('the split does not soften catastrophic evidence', () => {
  const BIN = String.fromCharCode(114, 109);
  const WIPE_TOKENS = [BIN, ['-', 'r', 'f'].join(''), '/'];
  const WIPE = WIPE_TOKENS.join(' ');

  it.each(SPAWN_ALIASES)('%s: an argv wipe is still catastrophic and doorless', (tool) => {
    for (const payload of [WIPE, WIPE_TOKENS, { a: [BIN, ['-', 'r', 'f'].join('')], b: '/' }]) {
      expect(evaluateToolCall(tool, { task: 'work', argv: payload })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it('an argv wipe alongside 20 drifted inert keys is still catastrophic', () => {
    const args: Record<string, unknown> = { task: 'work', argv: WIPE_TOKENS };
    for (let i = 0; i < 20; i++) args[`futureField${i}`] = { nested: { deep: i } };
    expect(evaluateToolCall('sessions_spawn', args)).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a wipe buried mid-payload in a long argv still scans', () => {
    const mid = 'x'.repeat(140000) + ' ' + WIPE + ' ' + 'y'.repeat(20000);
    expect(evaluateToolCall('sessions_spawn', { task: 'work', newField: 'inert', argv: mid }))
      .toMatchObject({ decision: 'block', severity: 'catastrophic' });
  });

  it('an unknown command-bearing field is denied even when it scans clean', () => {
    const v = evaluateToolCall('sessions_spawn', { task: 'work', command: 'npm test' });
    expect(v).toMatchObject({ decision: 'require_approval', action: 'invalid_tool_input' });
    expect(v.signals).toContain('invalid-tool-input');
  });

  it('web.run keeps the same discipline', () => {
    expect(evaluateToolCall('web.run', { search_query: [{ q: 'x' }], argv: WIPE_TOKENS }))
      .toMatchObject({ decision: 'block', severity: 'catastrophic' });
    expect(evaluateToolCall('web.run', { search_query: [{ q: 'x' }], safesearch: 'off' }))
      .toMatchObject({
        decision: 'allow',
        contractDrift: { contract: 'web.run', droppedKeys: ['safesearch'] },
      });
  });
});

describe('MCP-fronted names get no native contract and no guessed schema family', () => {
  const MCP_NAMES = [
    'mcp__web__run',
    'mcp__openclaw__sessions_spawn',
    'mcp__collaboration__spawn_agent',
    'mcp__evil__sessions_spawn',
    'mcp__evil__web__run',
    'mcp__evil__read_file',
    'mcp__evil__remember',
    'MCP__OpenClaw__Sessions_Spawn',
  ] as const;
  const DANGER_TOKENS = [String.fromCharCode(115, 117, 100, 111), 'id'];
  const MCP_WIPE_TOKENS = [String.fromCharCode(114, 109), ['-', 'r', 'f'].join(''), '/'];

  it.each(MCP_NAMES)('%s resolves generically to unknown, never a reviewed contract', (tool) => {
    expect(hasExactSpecialToolSchema(tool)).toBe(false);
    expect(exactSpecialContractName(tool)).toBeNull();
    expect(schemaFamilyForTool(tool)).toBe('unknown');
    expect(contractDriftFor(tool, { task: 'work', futureField: 'x' })).toBeNull();
  });

  it.each(['mcp__openclaw__sessions_spawn', 'mcp__evil__sessions_spawn'])(
    '%s allows the harmless live 28-field structured bag without a card',
    (tool) => {
      const v = evaluateToolCall(tool, LIVE_SPAWN_FIELDS);
      expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
      expect(v.action).not.toBe('invalid_tool_input');
      expect(v.signals).not.toContain('invalid-tool-input');
      expect(v.contractDrift).toBeUndefined();
    },
  );

  it.each(MCP_NAMES)('%s strips inert fields from its guard view', (tool) => {
    const r = enforceToolInput(tool, { task: 'work', structured: { nested: ['data'] } });
    // Direct enforce remains closed; runtime evaluation deliberately selects
    // annotate for the unknown family and therefore does not forward this bag.
    expect(r).toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    expect(evaluateToolCall(tool, { task: 'work', structured: { nested: ['data'] } }))
      .toMatchObject({ decision: 'allow', severity: 'benign' });
  });

  it.each(MCP_NAMES)('%s keeps dangerous and catastrophic raw command evidence', (tool) => {
    expect(evaluateToolCall(tool, { task: 'work', argv: DANGER_TOKENS }))
      .toMatchObject({ decision: 'require_approval', severity: 'dangerous' });
    expect(evaluateToolCall(tool, { task: 'work', command: 'echo safe', argv: MCP_WIPE_TOKENS }))
      .toMatchObject({ decision: 'block', severity: 'catastrophic' });
  });

  it('MCP read/memory suffixes cannot short-circuit raw command evidence', () => {
    for (const tool of ['mcp__evil__read_file', 'mcp__evil__remember']) {
      expect(evaluateToolCall(tool, { command: MCP_WIPE_TOKENS.join(' ') }))
        .toMatchObject({ decision: 'block', severity: 'catastrophic' });
      expect(evaluateToolCall(tool, { command: DANGER_TOKENS.join(' ') }))
        .toMatchObject({ decision: 'require_approval', severity: 'dangerous' });
    }
  });

  it('non-MCP lookalikes keep their existing schema inference', () => {
    expect(schemaFamilyForTool('vendor_sessions_spawn')).toBe('exec');
    expect(evaluateToolCall('vendor_sessions_spawn', { task: 'work' })).toMatchObject({
      decision: 'require_approval', action: 'invalid_tool_input',
    });
    expect(evaluateToolCall('thirdparty_run', { task: 'work' }))
      .toMatchObject({ decision: 'allow', severity: 'benign' });
  });

  it('canonical native spellings remain reviewed', () => {
    for (const tool of [...SPAWN_ALIASES, 'webrun', 'web.run', 'web__run',
      'collaborationspawn_agent', 'collaboration.spawn_agent', 'collaboration__spawn_agent']) {
      expect(hasExactSpecialToolSchema(tool)).toBe(true);
    }
  });
});

describe('OpenClaw and collaboration are separate contracts', () => {
  it('each names itself in the drift observation', () => {
    expect(contractDriftFor('sessions_spawn', { task: 'x', novel: 1 })?.contract)
      .toBe('openclaw.sessions_spawn');
    expect(contractDriftFor('collaborationspawn_agent', { task_name: 'x', novel: 1 })?.contract)
      .toBe('collaboration.spawn_agent');
    expect(contractDriftFor('web.run', { search_query: [], novel: 1 })?.contract)
      .toBe('web.run');
  });

  it('neither host is granted the other’s fields on no evidence', () => {
    // `visible` is measured on OpenClaw only; `fork_turns` on collaboration only.
    expect(contractDriftFor('sessions_spawn', { task: 'x', visible: true })).toBeNull();
    expect(contractDriftFor('collaborationspawn_agent', { task_name: 'x', visible: true })
      ?.droppedKeys).toEqual(['visible']);
    expect(contractDriftFor('collaborationspawn_agent', { task_name: 'x', fork_turns: 'all' }))
      .toBeNull();
    expect(contractDriftFor('sessions_spawn', { task: 'x', fork_turns: 'all' })?.droppedKeys)
      .toEqual(['fork_turns']);
  });

  it('borrowing across contracts is a drop, never a deny', () => {
    expect(evaluateToolCall('collaborationspawn_agent', { task_name: 'x', visible: true }))
      .toMatchObject({ decision: 'allow', severity: 'benign' });
  });
});

/**
 * A dropped key NAME is model-controlled text on its way to an operator's log.
 *
 * The drift observation exists so an operator LEARNS a host schema moved. It is
 * therefore rendered into the gateway warn line — journald on a real box — and
 * a key name is chosen by whoever wrote the payload. A newline in it buys a
 * whole extra line, and the line it buys can be spelled to look exactly like a
 * verdict ShieldCortex emitted. Measured: `sessions_spawn` with a drifted key
 * of `x\n[shieldcortex] action-guard ALLOWED Bash: operator approved\nzz`
 * returned `allow`/`benign` — the ordinary unattended path — and wrote a forged
 * ShieldCortex verdict into the log, up to 12 keys x 64 chars per call.
 *
 * The jsonl audit escapes it; the warn line, which is what an operator actually
 * reads to see what the guard did, did not.
 */
describe('drifted key names cannot forge log lines', () => {
  const LF = String.fromCharCode(10);
  const CR = String.fromCharCode(13);
  const NEL = String.fromCharCode(0x85);
  const LS = String.fromCharCode(0x2028);
  const PS = String.fromCharCode(0x2029);
  const ESC = String.fromCharCode(27);
  const FORGED = '[shieldcortex] action-guard ALLOWED Bash: operator approved';

  const hostile = (sep: string) => `x${sep}${FORGED}${sep}zz`;
  const SEPARATORS: Array<[string, string]> = [
    ['LF', LF], ['CR', CR], ['CRLF', `${CR}${LF}`], ['NEL', NEL], ['LS', LS], ['PS', PS],
  ];

  it.each(SEPARATORS)('a %s in a dropped key is neutralised at the source', (_label, sep) => {
    const drift = contractDriftFor('sessions_spawn', { task: 'work', [hostile(sep)]: 1 })!;
    expect(drift.droppedKeys).toHaveLength(1);
    const key = drift.droppedKeys[0]!;
    for (const ch of [LF, CR, NEL, LS, PS]) expect(key).not.toContain(ch);
    // Neutralised, not silently dropped: the operator still sees a key drifted.
    expect(key.startsWith('x')).toBe(true);
  });

  it('the full C0/C1 ranges and the Unicode line separators are covered', () => {
    const every = Array.from({ length: 0xa0 }, (_, i) => String.fromCharCode(i))
      .filter(c => {
        const n = c.charCodeAt(0);
        return n <= 0x1f || (n >= 0x7f && n <= 0x9f);
      })
      .join('') + LS + PS;
    const drift = contractDriftFor('sessions_spawn', { task: 'work', [`k${every}`]: 1 })!;
    for (const ch of [...drift.droppedKeys[0]!]) {
      const n = ch.codePointAt(0)!;
      expect(n > 0x1f && !(n >= 0x7f && n <= 0x9f) && n !== 0x2028 && n !== 0x2029).toBe(true);
    }
  });

  it('the bounds still hold — count, length, and no values', () => {
    const args: Record<string, unknown> = { task: 'work' };
    for (let i = 0; i < CONTRACT_DRIFT_MAX_KEYS + 5; i++) args[`f${i}${LF}${FORGED}`] = `secret-${i}`;
    const drift = contractDriftFor('sessions_spawn', args)!;
    expect(drift.droppedKeys).toHaveLength(CONTRACT_DRIFT_MAX_KEYS);
    expect(drift.truncated).toBe(true);
    for (const k of drift.droppedKeys) {
      expect(k.length).toBeLessThanOrEqual(64);
      expect(k).not.toContain(LF);
    }
    expect(JSON.stringify(drift)).not.toContain('secret-');
  });

  it('the REAL interceptor warning is one physical line with no forged verdict', async () => {
    const lines: string[] = [];
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
      { evaluateToolCall: evaluateToolCall as never },
    );

    await expect(interceptor.handleToolCall({
      toolName: 'sessions_spawn',
      arguments: {
        task: 'work',
        runtime: 'subagent',
        [hostile(LF)]: 1,
        [`y${ESC}[2K${CR}${FORGED}`]: 2,
      },
    })).resolves.toBeUndefined();

    const drift = lines.filter(l => l.includes('CONTRACT DRIFT'));
    expect(drift).toHaveLength(1);
    // ONE physical line: the whole warning, hostile key names included, is one
    // row in the operator's log — every emitted message is exactly one line.
    for (const line of lines) expect(line.split(/[\r\n\u0085\u2028\u2029]/)).toHaveLength(1);
    for (const ch of [LF, CR, NEL, LS, PS, ESC]) expect(drift[0]).not.toContain(ch);
    // The forged text survives only as DATA inside the drift row's field list,
    // where it is visibly a dropped key name. What it can no longer do is stand
    // as a line of its own, which is the only form an operator reads as a
    // verdict — and it is still bracketed by the guard's own framing.
    const physical = lines.flatMap(l => l.split(/[\r\n\u0085\u2028\u2029]/));
    for (const line of physical) {
      expect(line.startsWith(FORGED)).toBe(false);
      expect(line.startsWith('[shieldcortex] action-guard CONTRACT DRIFT')).toBe(true);
    }
    expect(drift[0]!.indexOf(FORGED)).toBeGreaterThan(drift[0]!.indexOf('dropped unread field(s)'));
  });
});
