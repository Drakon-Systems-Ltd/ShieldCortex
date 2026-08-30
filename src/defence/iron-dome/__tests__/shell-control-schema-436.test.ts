/**
 * #436 — Claude Code background-shell control plane vs the #412 closed schema.
 *
 * BashOutput / KillShell / KillBash substring-matched as exec, then inherited
 * EXEC_KEYS which omitted their only legitimate fields. Closed-schema enforce
 * hard-blocked every live control call. These tools do not start an OS process;
 * they get a NARROWER closed bag, not extra EXEC_KEYS.
 */
import { describe, expect, it } from '@jest/globals';
import { enforceToolInput } from '../tool-input-schema.js';
import { evaluateToolCall } from '../tool-action-guard.js';

describe('#436 acceptance 1 — live control shapes are not invalid-tool-input', () => {
  const LIVE: Array<[string, Record<string, unknown>]> = [
    ['BashOutput', { bash_id: 'bash_1', filter: 'ready' }],
    ['BashOutput', { bash_id: 'bash_1' }],
    ['BashOutput', { task_id: 'task_1' }],
    ['BashOutput', { agentId: 'agent_1' }],
    ['KillShell', { shell_id: 'shell_1' }],
    ['KillShell', { task_id: 'task_1' }],
    ['KillBash', { shell_id: 'shell_1' }],
    ['KillBash', { task_id: 'task_1' }],
    // #439 — same closed bags, exact native names not previously mapped
    ['TaskOutput', { task_id: 'task_1' }],
    ['TaskOutput', { bash_id: 'bash_1', filter: 'ready' }],
    ['TaskOutput', { agentId: 'agent_1' }],
    ['TaskStop', { task_id: 'task_1' }],
    ['TaskStop', { shell_id: 'shell_1' }],
  ];

  it.each(LIVE)('%s %j is not an invalid-tool-input hard block', (tool, args) => {
    const v = evaluateToolCall(tool, args);
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.decision).not.toBe('block');
    expect(v.signals).not.toContain('invalid-tool-input');
  });

  it.each(LIVE)('%s %j survives closed-schema enforcement', (tool, args) => {
    const r = enforceToolInput(tool, args);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.args).toEqual(args);
  });
});

describe('#436 acceptance 2 — schema stays CLOSED', () => {
  it('rejects an unknown field on BashOutput', () => {
    const r = enforceToolInput('BashOutput', { bash_id: 'bash_1', evil_payload: 'x' });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.code).toBe('UNKNOWN_KEYS');
      expect(r.unknownKeys).toContain('evil_payload');
    }
  });

  it.each([
    ['KillShell', { shell_id: 'shell_1', evil_payload: 'x' }],
    ['KillBash', { shell_id: 'shell_1', evil_payload: 'x' }],
  ])('rejects an unknown field on %s via evaluateToolCall', (tool, args) => {
    const v = evaluateToolCall(tool, args);
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
    expect(v.signals).toEqual(expect.arrayContaining(['invalid-tool-input', 'unknown-keys']));
  });

  it('is narrower than EXEC_KEYS — a control tool cannot smuggle a command', () => {
    for (const key of ['command', 'cmd', 'script', 'code', 'run', 'shell', 'input', 'env', 'stdin']) {
      const r = enforceToolInput('BashOutput', { bash_id: 'bash_1', [key]: 'x' });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('UNKNOWN_KEYS');
    }
  });

  it('still rejects prototype pollution', () => {
    const raw = JSON.parse('{"bash_id":"bash_1","__proto__":{"polluted":true}}') as Record<string, unknown>;
    const r = enforceToolInput('BashOutput', raw);
    expect(r.ok).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it('does not leak the narrow schema to a namespaced look-alike', () => {
    const r = enforceToolInput('mcp__thirdparty__BashOutput', { bash_id: 'bash_1' });
    expect(r.ok).toBe(false);
  });

  it('real Bash unknown-field enforcement is unchanged', () => {
    expect(evaluateToolCall('Bash', { command: 'printf ok' }).decision).toBe('allow');
    const v = evaluateToolCall('Bash', { command: 'printf ok', evil_payload: 'x' });
    expect(v.decision).toBe('block');
    expect(v.action).toBe('invalid_tool_input');
  });

  it('empty control input fails closed (no handle)', () => {
    const r = enforceToolInput('BashOutput', {});
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('MISSING_HANDLE');
    const v = evaluateToolCall('BashOutput', {});
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
  });

  it('filter-only BashOutput fails closed (no handle)', () => {
    const r = enforceToolInput('BashOutput', { filter: 'ready' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('MISSING_HANDLE');
    const v = evaluateToolCall('BashOutput', { filter: 'ready' });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
  });

  it('non-string handle fails closed without throwing', () => {
    const v = evaluateToolCall('BashOutput', { bash_id: 1 });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
  });

  it('filter must be a string', () => {
    const r = enforceToolInput('BashOutput', { bash_id: 'bash_1', filter: 1 });
    expect(r.ok).toBe(false);
  });

  it('whitespace-only handle fails closed', () => {
    const r = enforceToolInput('BashOutput', { bash_id: '   ' });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('MISSING_HANDLE');
  });

  it('unknown extra key cannot demote a catastrophic Bash command', () => {
    const wipe = ['r', 'm', ' ', '-', 'r', 'f', ' ', '/'].join('');
    const v = evaluateToolCall('Bash', { command: wipe, evil_payload: 'x' });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
    expect(v.action).not.toBe('invalid_tool_input');
  });
});

describe('#439 — TaskOutput/TaskStop use the native control schemas', () => {
  it.each(['TaskOutput', 'TaskStop'] as const)(
    'empty %s fails closed via evaluateToolCall (never throws)',
    (tool) => {
      const r = enforceToolInput(tool, {});
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.code).toBe('MISSING_HANDLE');
      const v = evaluateToolCall(tool, {});
      expect(v.decision).toBe('block');
      expect(v.severity).toBe('dangerous');
      expect(v.action).toBe('invalid_tool_input');
    },
  );

  it('filter-only TaskOutput fails closed (no handle)', () => {
    const v = evaluateToolCall('TaskOutput', { filter: 'ready' });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
  });

  it('non-string TaskOutput handle fails closed without throwing', () => {
    const v = evaluateToolCall('TaskOutput', { task_id: 1 });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
  });

  it.each([
    ['TaskOutput', { task_id: 'task_1', evil_payload: 'x' }],
    ['TaskStop', { shell_id: 'shell_1', evil_payload: 'x' }],
  ])('rejects an unknown field on %s via evaluateToolCall', (tool, args) => {
    const v = evaluateToolCall(tool, args);
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
    expect(v.signals).toEqual(expect.arrayContaining(['invalid-tool-input', 'unknown-keys']));
  });

  it('non-string TaskStop handle fails closed without throwing', () => {
    const v = evaluateToolCall('TaskStop', { shell_id: 1 });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('dangerous');
    expect(v.action).toBe('invalid_tool_input');
  });

  it('does not leak the narrow schema to a namespaced TaskOutput look-alike', () => {
    const r = enforceToolInput('mcp__thirdparty__TaskOutput', { task_id: 'task_1' });
    expect(r.ok).toBe(false);
    // If the native control bag leaked, evil_payload would be invalid_tool_input.
    // Unknown-family annotate strips it and allows — that is the intended split.
    const v = evaluateToolCall('mcp__thirdparty__TaskOutput', { task_id: 'task_1', evil_payload: 'x' });
    expect(v.action).not.toBe('invalid_tool_input');
  });

  it('does not leak the narrow schema to a namespaced TaskStop look-alike', () => {
    const r = enforceToolInput('mcp__thirdparty__TaskStop', { shell_id: 'shell_1' });
    expect(r.ok).toBe(false);
    const v = evaluateToolCall('mcp__thirdparty__TaskStop', { shell_id: 'shell_1', evil_payload: 'x' });
    expect(v.action).not.toBe('invalid_tool_input');
  });
});
