/**
 * Round-5 blocker — the LIVE native `TaskOutput` contract.
 *
 * The host ships `TaskOutput` as
 *   {"task_id": string, "block": boolean, "timeout": number}
 * with all three REQUIRED and `additionalProperties: false`.
 *
 * #445 mapped `TaskOutput` onto the `BashOutput` bag (`bash_id | task_id |
 * agentId | filter`, all strings). `block` and `timeout` were therefore
 * UNKNOWN_KEYS on the enforcement path, so every real TaskOutput call — the
 * host's own background-read path, one of the highest-frequency tools an
 * unattended operator runs — hard-blocked as `invalid_tool_input`.
 *
 * The fold is the live contract, not a wider bag: the schema stays CLOSED,
 * carries no exec key, still demands a handle, and now types every field it
 * accepts (`block` boolean, `timeout` number, the rest strings). `BashOutput`
 * keeps its legacy string-only bag and `TaskStop` is not widened at all.
 */
import { describe, expect, it } from '@jest/globals';
import { enforceToolInput, validateToolInput } from '../tool-input-schema.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const LIVE = { task_id: 'task_1', block: true, timeout: 30_000 };

function expectHardBlock(tool: string, args: Record<string, unknown>): void {
  const v = evaluateToolCall(tool, args);
  expect(v.decision).toBe('block');
  expect(v.severity).toBe('dangerous');
  expect(v.action).toBe('invalid_tool_input');
}

describe('TaskOutput live contract — the measured call is not denied', () => {
  const ACCEPTED: Array<Record<string, unknown>> = [
    LIVE,
    // block/timeout are falsy-but-present: they must survive, not be dropped.
    { task_id: 'task_1', block: false, timeout: 0 },
    { task_id: 'task_1', block: false, timeout: 600_000 },
    // Partial shapes: the host defaults block/timeout, older hosts omit both.
    { task_id: 'task_1', block: true },
    { task_id: 'task_1', timeout: 30_000 },
    { task_id: 'task_1' },
    // Legacy 2.1.233 shapes stay accepted for hosts that still send them.
    { bash_id: 'bash_1', filter: 'ready' },
    { agentId: 'agent_1' },
  ];

  it.each(ACCEPTED)('enforce keeps TaskOutput %j intact', (args) => {
    const r = enforceToolInput('TaskOutput', args);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args).toEqual(args);
      expect(r.strippedKeys).toEqual([]);
    }
  });

  it.each(ACCEPTED)('annotate keeps TaskOutput %j intact', (args) => {
    const r = validateToolInput('TaskOutput', args, 'annotate');
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.args).toEqual(args);
  });

  it.each(ACCEPTED)('evaluateToolCall does not hard-block TaskOutput %j', (args) => {
    const v = evaluateToolCall('TaskOutput', args);
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.decision).not.toBe('block');
    expect(v.signals).not.toContain('invalid-tool-input');
  });
});

describe('TaskOutput live contract — the bag stays CLOSED', () => {
  it('rejects an unknown field beside the full live shape', () => {
    const r = enforceToolInput('TaskOutput', { ...LIVE, evil_payload: 'x' });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('UNKNOWN_KEYS');
      expect(r.unknownKeys).toContain('evil_payload');
    }
    const v = evaluateToolCall('TaskOutput', { ...LIVE, evil_payload: 'x' });
    expect(v.decision).toBe('block');
    expect(v.signals).toEqual(expect.arrayContaining(['invalid-tool-input', 'unknown-keys']));
  });

  it.each(['command', 'cmd', 'script', 'code', 'run', 'shell', 'input', 'env', 'stdin', 'args'])(
    'cannot smuggle exec key %s through the widened bag',
    (key) => {
      const r = enforceToolInput('TaskOutput', { ...LIVE, [key]: 'x' });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('UNKNOWN_KEYS');
    },
  );

  it('still demands a handle when only block/timeout are present', () => {
    const r = enforceToolInput('TaskOutput', { block: true, timeout: 30_000 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('MISSING_HANDLE');
    expectHardBlock('TaskOutput', { block: true, timeout: 30_000 });
  });

  it('still rejects prototype pollution on the live shape', () => {
    const raw = JSON.parse('{"task_id":"task_1","block":true,"timeout":1,"__proto__":{"polluted":true}}') as Record<string, unknown>;
    const r = enforceToolInput('TaskOutput', raw);
    expect(r.ok).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('does not leak the widened bag to a namespaced look-alike', () => {
    const r = enforceToolInput('mcp__thirdparty__TaskOutput', LIVE);
    expect(r.ok).toBe(false);
  });
});

describe('TaskOutput live contract — arrays/objects/coercions fail closed', () => {
  const BAD: Array<[string, Record<string, unknown>, string]> = [
    ['block as string', { task_id: 't', block: 'true' }, 'TYPE_COERCION'],
    ['block as number', { task_id: 't', block: 1 }, 'TYPE_COERCION'],
    ['block as object', { task_id: 't', block: { $ne: null } }, 'NESTED_INVALID'],
    ['block as array', { task_id: 't', block: [true] }, 'NESTED_INVALID'],
    ['timeout as string', { task_id: 't', timeout: '30000' }, 'TYPE_COERCION'],
    ['timeout as boolean', { task_id: 't', timeout: true }, 'TYPE_COERCION'],
    ['timeout as object', { task_id: 't', timeout: { valueOf: 1 } }, 'NESTED_INVALID'],
    ['timeout as array', { task_id: 't', timeout: [1] }, 'NESTED_INVALID'],
    ['timeout as NaN', { task_id: 't', timeout: Number.NaN }, 'TYPE_COERCION'],
    ['timeout as Infinity', { task_id: 't', timeout: Number.POSITIVE_INFINITY }, 'TYPE_COERCION'],
    ['handle as boolean', { task_id: true, block: true, timeout: 1 }, 'TYPE_COERCION'],
    ['handle as array', { task_id: ['t'], block: true, timeout: 1 }, 'NESTED_INVALID'],
    ['filter as object', { task_id: 't', filter: { re: 'x' }, block: true }, 'NESTED_INVALID'],
  ];

  it.each(BAD)('%s fails closed with %s', (_label, args, code) => {
    const r = enforceToolInput('TaskOutput', args);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe(code);
    expectHardBlock('TaskOutput', args);
  });

  it('a rejected TaskOutput field never reaches the extractors as a value', () => {
    const v = evaluateToolCall('TaskOutput', { task_id: 't', timeout: { toString: 'x' } });
    expect(v.action).toBe('invalid_tool_input');
    expect(v.reason).not.toContain('toString');
  });
});

describe('TaskOutput live contract — siblings are untouched', () => {
  it.each(['block', 'timeout'])('BashOutput does not inherit %s', (key) => {
    const r = enforceToolInput('BashOutput', { bash_id: 'bash_1', [key]: key === 'block' ? true : 1 });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('UNKNOWN_KEYS');
      expect(r.unknownKeys).toContain(key);
    }
  });

  it('BashOutput legacy fields still pass', () => {
    const r = enforceToolInput('BashOutput', { bash_id: 'bash_1', filter: 'ready' });
    expect(r.ok).toBe(true);
    const v = evaluateToolCall('BashOutput', { bash_id: 'bash_1', filter: 'ready' });
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.decision).not.toBe('block');
  });

  it.each([
    ['block', { task_id: 'task_1', block: true }],
    ['timeout', { task_id: 'task_1', timeout: 30_000 }],
    ['filter', { task_id: 'task_1', filter: 'ready' }],
    ['agentId', { task_id: 'task_1', agentId: 'agent_1' }],
  ])('TaskStop is not widened by %s', (key, args) => {
    const r = enforceToolInput('TaskStop', args);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('UNKNOWN_KEYS');
      expect(r.unknownKeys).toContain(key);
    }
    expectHardBlock('TaskStop', args);
  });

  it('TaskStop live shape still passes', () => {
    for (const args of [{ task_id: 'task_1' }, { shell_id: 'shell_1' }]) {
      const r = enforceToolInput('TaskStop', args);
      expect(r.ok).toBe(true);
      expect(evaluateToolCall('TaskStop', args).action).not.toBe('invalid_tool_input');
    }
  });

  it('real Bash enforcement is unchanged by the typed control fields', () => {
    expect(evaluateToolCall('Bash', { command: 'printf ok' }).decision).toBe('allow');
    const v = evaluateToolCall('Bash', { command: 'printf ok', block: true });
    expect(v.decision).toBe('block');
    expect(v.action).toBe('invalid_tool_input');
  });
});

describe('TaskOutput live contract — catastrophic dominance is preserved', () => {
  const WIPE = ['r', 'm', ' ', '-', 'r', 'f', ' ', '/'].join('');

  it('a wipe smuggled beside the live shape stays catastrophic, not invalid_tool_input', () => {
    const v = evaluateToolCall('TaskOutput', { ...LIVE, command: WIPE });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.action).not.toBe('invalid_tool_input');
  });

  it('a wipe smuggled through a bad-typed control field stays catastrophic', () => {
    const v = evaluateToolCall('TaskOutput', { task_id: 't', timeout: 'x', command: WIPE });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  it('catastrophic Bash is still terminal', () => {
    const v = evaluateToolCall('Bash', { command: WIPE });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.action).not.toBe('invalid_tool_input');
  });
});
