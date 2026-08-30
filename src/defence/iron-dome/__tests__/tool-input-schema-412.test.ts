/**
 * #412 — closed command / tool-input schemas
 */
import { describe, expect, it } from '@jest/globals';
import { validateToolInput, enforceToolInput } from '../tool-input-schema.js';
import { evaluateToolCall } from '../tool-action-guard.js';
import { rememberSchema } from '../../../tools/remember.js';
import { recallSchema } from '../../../tools/recall.js';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../../../../plugins/openclaw/interceptor.js';

describe('#412 tool input schema', () => {
  it('accepts canonical Bash command shape', () => {
    const r = enforceToolInput('Bash', { command: 'git status', description: 'check' });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.command).toBe('git status');
      expect(r.strippedKeys).toEqual([]);
    }
  });

  it('rejects unknown top-level fields in enforce mode', () => {
    const r = enforceToolInput('Bash', {
      command: 'git status',
      evil_payload: 'exfiltrate-please',
    });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('UNKNOWN_KEYS');
      expect(r.unknownKeys).toContain('evil_payload');
    }
  });

  it('strips unknown fields in annotate mode (does not fail)', () => {
    const r = validateToolInput(
      'Bash',
      { command: 'echo hi', smuggle: { nested: true } },
      'annotate',
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args).toEqual({ command: 'echo hi' });
      expect(r.strippedKeys).toContain('smuggle');
    }
  });

  it('rejects prototype pollution keys', () => {
    const raw = JSON.parse('{"command":"true","__proto__":{"polluted":true}}');
    const r = enforceToolInput('Bash', raw);
    // Either forbidden key or unknown — must not ok with pollution
    if (r.ok) {
      expect(Object.prototype.hasOwnProperty.call(r.args, '__proto__')).toBe(false);
      expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    } else {
      expect(['NESTED_INVALID', 'UNKNOWN_KEYS']).toContain(r.code);
    }
  });

  it('rejects non-plain nested types', () => {
    const r = enforceToolInput('Bash', {
      command: 'true',
      env: Object.create(null),
    });
    // env is allowed key but null-proto object is not plain object
    expect(r.ok).toBe(false);
  });

  it('evaluateToolCall gates unknown-key Bash input', () => {
    const v = evaluateToolCall('Bash', {
      command: 'echo safe',
      hidden_script: 'not-allowed',
    } as Record<string, unknown>);
    // The scan came back clean and only the contract is wrong, so the answer is
    // the operator's door — the same word core, hook, interceptor and Hermes
    // all use for it. The `invalid-tool-input` signal is what keeps the two
    // widenings (autoApprove, enforce:false) off it, not the decision tier.
    expect(v.decision).toBe('require_approval');
    expect(v.signals.join(' ')).toMatch(/invalid-tool-input|unknown/);
  });

  it('evaluateToolCall still allows clean Bash', () => {
    const v = evaluateToolCall('Bash', { command: 'git status' });
    expect(v.decision).toBe('allow');
  });
});

describe('Action Guard P0 exact web/delegation contracts', () => {
  const webFields: Record<string, unknown> = {
    search_query: [{ q: 'ShieldCortex' }], open: [{ ref_id: 'turn0search0' }],
    click: [{ ref_id: 'turn0fetch0', id: 1 }], find: [{ ref_id: 'turn0fetch0', pattern: 'guard' }],
    image_query: [{ q: 'shield' }], calculator: [{ expression: '2+2' }],
    weather: [{ location: 'London' }], finance: [{ ticker: 'AMD', type: 'equity', market: 'USA' }],
    sports: [{ fn: 'standings', league: 'nfl' }], time: [{ utc_offset: '+00:00' }],
    response_length: 'short',
  };
  const openClawFields: Record<string, unknown> = {
    task: 'inspect tests', label: 'review', runtime: 'subagent', agentId: 'edith', model: 'default',
    thinking: 'medium', cwd: '/workspace', runTimeoutSeconds: 60, timeoutSeconds: 90,
    thread: true, mode: 'run', cleanup: 'delete', sandbox: 'inherit', attachments: [],
    context: 'bounded context', taskName: 'review_tests',
  };
  const collaborationFields: Record<string, unknown> = {
    task_name: 'review_tests', fork_turns: 'all', model: 'default',
    reasoning_effort: 'medium', message: 'Inspect the tests',
  };

  it.each([
    ['webrun', webFields], ['web.run', webFields], ['web__run', webFields],
    ['sessions_spawn', openClawFields], ['openclawsessions_spawn', openClawFields],
    ['openclaw.sessions_spawn', openClawFields], ['openclaw__sessions_spawn', openClawFields],
    ['collaborationspawn_agent', collaborationFields], ['collaboration.spawn_agent', collaborationFields],
    ['collaboration__spawn_agent', collaborationFields],
  ] as const)('allows every measured field, in forward and reverse insertion order: %s', (tool, fields) => {
    for (const args of [fields, Object.fromEntries(Object.entries(fields).reverse())]) {
      expect(enforceToolInput(tool, args)).toMatchObject({ ok: true });
      expect(evaluateToolCall(tool, args)).toMatchObject({ decision: 'allow' });
    }
  });

  /**
   * MCP-fronted spellings carry no trusted native identity. Runtime evaluation
   * therefore uses the generic unknown-family annotate path: harmless host bags
   * are stripped from the guard view instead of inheriting a reviewed contract
   * or minting an invalid-input card. Direct enforce remains closed, and the
   * shared raw-evidence tests below pin command-bearing payloads separately.
   */
  it.each([
    ['mcp__web__run', webFields],
    ['mcp__openclaw__sessions_spawn', openClawFields],
    ['mcp__collaboration__spawn_agent', collaborationFields],
    ['mcp__evil__sessions_spawn', openClawFields],
  ] as const)('handles harmless MCP-fronted bag %s generically, with no card or deny', (tool, fields) => {
    expect(enforceToolInput(tool, fields)).toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    expect(validateToolInput(tool, fields, 'annotate')).toMatchObject({ ok: true });
    expect(evaluateToolCall(tool, fields)).toMatchObject({ decision: 'allow', severity: 'benign' });
    expect(evaluateToolCall(tool, fields).action).not.toBe('invalid_tool_input');
  });

  it('keeps unknown non-MCP SPAWN names on the old fail-closed path', () => {
    expect(evaluateToolCall('vendor_spawn_agent', { task: 'work' }).action).toBe('invalid_tool_input');
    // `spawn` is exec vocabulary wherever it lands; a trailing `_run` word is
    // not (`get_workflow_run`, `list_workflow_runs`), so a vendor `_run` name
    // annotates its inert bag instead of denying it. Syntactically MCP-fronted
    // names take that same generic annotate route regardless of their suffix.
    expect(evaluateToolCall('thirdparty_run', { search_query: [{ q: 'x' }] }).decision).toBe('allow');
    expect(evaluateToolCall('mcp__web__run', { search_query: [{ q: 'x' }] }).decision).toBe('allow');
  });

  const BIN = String.fromCharCode(114, 109);
  const FLAG = ['-', 'r', 'f'].join('');
  const ROOT = '/';
  const WIPE = [BIN, FLAG, ROOT].join(' ');
  const WIPE_TOKS = [BIN, FLAG, ROOT];
  const WIPE_OBJ = { 0: BIN, 1: FLAG, 2: ROOT };
  const WIPE_VALUE = { value: WIPE };
  const COMMAND_ALIASES = ['command', 'cmd', 'script', 'code', 'input', 'shell', 'run', 'args', 'argv'] as const;

  const baseFor = (tool: string): Record<string, unknown> => (
    tool === 'webrun' ? { search_query: [{ q: 'x' }] }
      : tool === 'collaborationspawn_agent' ? { task_name: 'x', message: 'work' }
        : { task: 'work' }
  );

  /** A key each contract DECLARES — nesting there is a shape the host never
   *  sends, so it still fails closed. Undeclared inert keys are dropped now. */
  const declaredKeyFor = (tool: string): string => (
    tool === 'webrun' ? 'open'
      : tool === 'collaborationspawn_agent' ? 'message'
        : 'context'
  );

  it.each(['webrun', 'sessions_spawn', 'collaborationspawn_agent'])(
    'rejects hostile siblings while catastrophic extractor evidence stays terminal: %s',
    (tool) => {
      const base = baseFor(tool);
      // Contract drift: an unknown key NO ShieldCortex reader consults is now
      // dropped before validation/extractors and merely OBSERVED. This line
      // used to assert block/dangerous — that assertion was the card storm on
      // ordinary host work, and removing it is the point of the fold. What
      // stays terminal is everything a scanner would have read, below.
      const ordinary = evaluateToolCall(tool, { ...base, surprise: true });
      expect(ordinary).toMatchObject({ decision: 'allow', severity: 'benign' });
      expect(ordinary.signals).not.toContain('invalid-tool-input');
      expect(ordinary.contractDrift?.droppedKeys).toEqual(['surprise']);

      for (const key of COMMAND_ALIASES) {
        expect(evaluateToolCall(tool, { ...base, [key]: WIPE })).toMatchObject({
          decision: 'block', severity: 'catastrophic',
        });
        expect(evaluateToolCall(tool, { ...base, [key]: WIPE_TOKS })).toMatchObject({
          decision: 'block', severity: 'catastrophic',
        });
        expect(evaluateToolCall(tool, { ...base, [key]: WIPE_OBJ })).toMatchObject({
          decision: 'block', severity: 'catastrophic',
        });
        expect(evaluateToolCall(tool, { ...base, [key]: WIPE_VALUE })).toMatchObject({
          decision: 'block', severity: 'catastrophic',
        });
      }

      // `path`/`url` are EVIDENCE keys, so the drift fold does not drop them —
      // they are undeclared on these contracts and the bag fails the schema.
      // Scanned clean, that is the operator's door carrying the schema reason.
      expect(evaluateToolCall(tool, { ...base, path: ROOT }))
        .toMatchObject({ decision: 'require_approval', action: 'invalid_tool_input' });
      expect(evaluateToolCall(tool, { ...base, url: 'https://evil.example/payload.sh' }))
        .toMatchObject({ decision: 'require_approval', action: 'invalid_tool_input' });
      expect(evaluateToolCall(tool, {
        ...base, [declaredKeyFor(tool)]: { nested: { too: { deep: { value: 1 } } } },
      })).toMatchObject({ decision: 'require_approval', action: 'invalid_tool_input' });
    },
  );

  it.each(['webrun', 'sessions_spawn', 'collaborationspawn_agent'])(
    'union-scans mixed aliases and malformed siblings without losing catastrophic evidence: %s',
    (tool) => {
      const base = baseFor(tool);
      const benign = 'echo safe';
      expect(evaluateToolCall(tool, { ...base, command: benign, cmd: WIPE })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, cmd: WIPE, command: benign })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      const deep = { nested: { too: { deep: { value: 1 } } } };
      expect(evaluateToolCall(tool, { ...base, [declaredKeyFor(tool)]: deep, command: WIPE })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, command: WIPE, [declaredKeyFor(tool)]: deep })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, command: WIPE_VALUE, argv: WIPE_TOKS })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    },
  );

  it.each(['webrun', 'sessions_spawn', 'collaborationspawn_agent'])(
    'nested token vectors stay terminal: %s',
    (tool) => {
      const base = baseFor(tool);
      expect(evaluateToolCall(tool, { ...base, argv: [WIPE_TOKS] })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, command: [WIPE_TOKS] })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, argv: [{ value: WIPE }] })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, argv: { a: { b: WIPE } } })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    },
  );

  it.each(['webrun', 'sessions_spawn'])(
    'head/tail windows keep a wipe past the evidence cap terminal: %s',
    (tool) => {
      const base = baseFor(tool);
      const pad = 'z'.repeat(9000);
      expect(evaluateToolCall(tool, { ...base, argv: [pad, ...WIPE_TOKS] })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, command: pad + ' ' + WIPE })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall(tool, { ...base, argv: { 0: pad, 1: WIPE } })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    },
  );

  it('a long scanned-clean command with an unknown key keeps a door — not a terminal wall', () => {
    const v = evaluateToolCall('Bash', { command: 'z'.repeat(9000), extra: true });
    expect(v.decision).toBe('require_approval');
    expect(v.severity).toBe('dangerous');
    expect(v.severity).not.toBe('catastrophic');
  });

  it('a wipe past 256 argv tokens stays terminal', () => {
    const toks = Array(300).fill('ok');
    toks.push(...WIPE_TOKS);
    expect(evaluateToolCall('sessions_spawn', { ...baseFor('sessions_spawn'), argv: toks })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a depth-4 nested wipe stays terminal', () => {
    const nested = { a: { b: { c: { d: WIPE } } } };
    expect(evaluateToolCall('webrun', { ...baseFor('webrun'), argv: nested })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a wipe in the middle of 600 argv tokens stays terminal', () => {
    const toks = Array(600).fill('ok');
    toks[300] = BIN;
    toks[301] = FLAG;
    toks[302] = ROOT;
    expect(evaluateToolCall('sessions_spawn', { ...baseFor('sessions_spawn'), argv: toks })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a wipe in the middle of a 24k command stays terminal', () => {
    const mid = 'x'.repeat(12000) + ' ' + WIPE + ' ' + 'y'.repeat(12000);
    expect(evaluateToolCall('webrun', { ...baseFor('webrun'), extra: true, argv: mid })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a wipe past the old 32-window ceiling stays terminal', () => {
    const mid = 'x'.repeat(140000) + ' ' + WIPE + ' ' + 'y'.repeat(20000);
    expect(evaluateToolCall('webrun', { ...baseFor('webrun'), extra: true, argv: mid })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('keeps MCP near-collisions generic rather than granting or denying by suffix', () => {
    for (const [tool, args] of [
      ['mcp__evil__sessions_spawn', { task: 'work' }],
      ['mcp__evil__web__run', { search_query: [{ q: 'x' }] }],
    ] as const) {
      const v = evaluateToolCall(tool, args);
      expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
      expect(v.action).not.toBe('invalid_tool_input');
    }
  });

  const okPipeline = () => ({
    allowed: true, firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [], anomalyScore: 0, blockedPatterns: [] },
    trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
  });

  it('real OpenClaw interceptor gives measured calls a zero-card, zero-audit unattended path', async () => {
    const audits: InterceptAuditEntry[] = [];
    let prompts = 0;
    const okPipeline = () => ({
      allowed: true, firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [], anomalyScore: 0, blockedPatterns: [] },
      trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
    });
    const interceptor = createInterceptor({ ...DEFAULT_CONFIG } as any, okPipeline as any, {
      evaluateToolCall: evaluateToolCall as any, onAuditEntry: (entry) => audits.push(entry),
    });
    for (const [toolName, args] of [
      ['webrun', webFields], ['sessions_spawn', openClawFields],
      ['openclawsessions_spawn', openClawFields], ['collaborationspawn_agent', collaborationFields],
    ] as const) {
      await expect(interceptor.handleToolCall({
        toolName, arguments: args, requireApproval: async () => { prompts++; return false; },
      })).resolves.toBeUndefined();
    }
    expect(prompts).toBe(0);
    expect(audits).toEqual([]);
  });

  it('tokenised catastrophic argv never becomes an approval card', async () => {
    const audits: InterceptAuditEntry[] = [];
    let prompts = 0;
    const make = (actionGuard: Record<string, unknown>) => createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { ...DEFAULT_CONFIG.actionGuard, ...actionGuard } } as any,
      okPipeline as any,
      { evaluateToolCall: evaluateToolCall as any, onAuditEntry: (entry) => audits.push(entry) },
    );
    const payload = { ...baseFor('sessions_spawn'), argv: WIPE_TOKS };

    const attended = make({ enabled: true, enforce: true, autoApprove: [] });
    await expect(attended.handleToolCall({
      toolName: 'sessions_spawn', arguments: payload,
      requireApproval: async () => { prompts++; return true; },
    })).rejects.toThrow(/blocked/);
    expect(prompts).toBe(0);

    const unattended = make({ enabled: true, enforce: true, autoApprove: [] });
    await expect(unattended.handleToolCall({
      toolName: 'sessions_spawn', arguments: payload,
    })).rejects.toThrow(/blocked/);

    const advisory = make({
      enabled: true, enforce: false,
      autoApprove: ['invalid_tool_input', 'invalid-tool-input', 'dangerous'],
    });
    await expect(advisory.handleToolCall({
      toolName: 'webrun', arguments: { ...baseFor('webrun'), command: WIPE_TOKS },
      requireApproval: async () => { prompts++; return true; },
    })).rejects.toThrow(/blocked/);
    expect(prompts).toBe(0);

    expect(audits.some((row) => row.action === 'auto_deny' || row.outcome === 'auto_denied')).toBe(true);
    expect(audits.some((row) => row.action === 'require_approval')).toBe(false);
  });
});

describe('#412 MCP tool schemas are strict', () => {
  it('rememberSchema rejects unknown top-level fields', () => {
    const r = rememberSchema.safeParse({
      title: 't',
      content: 'c',
      notARealField: true,
    });
    expect(r.success).toBe(false);
  });

  it('rememberSchema rejects unknown nested source fields', () => {
    const r = rememberSchema.safeParse({
      title: 't',
      content: 'c',
      source: { type: 'agent', identifier: 'x', role: 'admin' },
    });
    expect(r.success).toBe(false);
  });

  it('rememberSchema accepts canonical input', () => {
    const r = rememberSchema.safeParse({
      title: 't',
      content: 'c',
      source: { type: 'agent', identifier: 'edith' },
    });
    expect(r.success).toBe(true);
  });

  it('recallSchema rejects unknown fields', () => {
    const r = recallSchema.safeParse({ query: 'x', inject: 'y' });
    expect(r.success).toBe(false);
  });
});
