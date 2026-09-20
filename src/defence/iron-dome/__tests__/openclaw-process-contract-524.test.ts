/**
 * #524 — OpenClaw native process contract.
 *
 * Live host bag: openclaw/src/agents/bash-tools.process.ts processSchema.
 * Before this contract, process was an EXEC_WORD, so {action:'list'} hit
 * EXEC_KEYS as UNKNOWN_KEYS and carded every ordinary inspect call.
 */
import { describe, expect, it } from '@jest/globals';
import {
  enforceToolInput,
  contractDriftFor,
  hasExactSpecialToolSchema,
  exactSpecialContractName,
  schemaFamilyForTool,
} from '../tool-input-schema.js';
import { evaluateToolCall, classifyFamily } from '../tool-action-guard.js';

const BIN = String.fromCharCode(114, 109);
const WIPE = [BIN, ['-', 'r', 'f'].join(''), '/'].join(' ');
const STOP = ['k', 'i', 'l', 'l'].join('');

describe('#524 OpenClaw native process contract', () => {
  it('exact native process is an exact-special read contract', () => {
    expect(hasExactSpecialToolSchema('process')).toBe(true);
    expect(exactSpecialContractName('process')).toBe('openclaw.process');
    expect(schemaFamilyForTool('process')).toBe('read');
    expect(classifyFamily('process')).toBe('read');
  });

  it('MCP wrappers do not inherit the native contract', () => {
    expect(hasExactSpecialToolSchema('mcp__openclaw__process')).toBe(false);
    expect(exactSpecialContractName('mcp__openclaw__process')).toBeNull();
  });

  it.each([
    [{ action: 'list' }, 'list'],
    [{ action: 'poll', sessionId: 's1' }, 'poll'],
    [{ action: 'log', sessionId: 's1', offset: 0, limit: 50 }, 'log'],
    [{ action: 'LIST' }, 'list'],
  ])('inspect %j allows', (bag, verb) => {
    expect(enforceToolInput('process', bag)).toMatchObject({ ok: true });
    expect(evaluateToolCall('process', bag)).toMatchObject({
      decision: 'allow',
      severity: 'benign',
      family: 'read',
    });
    expect(evaluateToolCall('process', bag).reason).toContain(`OpenClaw process inspect (${verb})`);
    expect(evaluateToolCall('process', bag).signals).toContain('openclaw-process-inspect');
  });

  it.each([
    [{ action: STOP, sessionId: 's1' }, STOP],
    [{ action: 'write', sessionId: 's1', data: 'x' }, 'write'],
    [{ action: 'send-keys', sessionId: 's1', keys: ['a'] }, 'send-keys'],
    [{ action: 'send_keys', sessionId: 's1', keys: ['a'] }, 'send-keys'],
    [{ action: 'paste', sessionId: 's1', text: 'hi' }, 'paste'],
    [{ action: 'submit', sessionId: 's1' }, 'submit'],
    [{ action: 'clear', sessionId: 's1' }, 'clear'],
    [{ action: 'remove', sessionId: 's1' }, 'remove'],
  ])('mutate %j cards, never allows', (bag, verb) => {
    expect(enforceToolInput('process', bag)).toMatchObject({ ok: true });
    const v = evaluateToolCall('process', bag);
    expect(v).toMatchObject({
      decision: 'require_approval',
      severity: 'dangerous',
      family: 'exec',
    });
    expect(v.reason).toContain(`OpenClaw process ${verb}`);
    expect(v.signals).toContain('openclaw-process-mutate');
    expect(v.signals).not.toContain('invalid-tool-input');
  });

  it('a wipe in write data stays catastrophic and doorless', () => {
    expect(evaluateToolCall('process', { action: 'write', sessionId: 's1', data: WIPE })).toMatchObject({
      decision: 'block',
      severity: 'catastrophic',
    });
  });

  it('an undeclared host field that is not evidence is drift, inspect still allows', () => {
    const bag = { action: 'list', extraHostFlag: true };
    expect(enforceToolInput('process', bag)).toMatchObject({ ok: true });
    expect(evaluateToolCall('process', bag)).toMatchObject({
      decision: 'allow',
      severity: 'benign',
    });
    expect(contractDriftFor('process', bag)?.droppedKeys).toContain('extraHostFlag');
  });

  it('a command-bearing unknown key on native process stays fail-closed', () => {
    const bag = { action: 'list', command: WIPE };
    expect(enforceToolInput('process', bag)).toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    expect(evaluateToolCall('process', bag)).toMatchObject({
      decision: 'block',
      severity: 'catastrophic',
    });
  });

  it('missing or unreviewed action is non-widenable schema-invalid, not an allow', () => {
    expect(evaluateToolCall('process', { sessionId: 's1' })).toMatchObject({
      decision: 'require_approval',
      severity: 'dangerous',
      action: 'invalid_tool_input',
    });
    expect(evaluateToolCall('process', { sessionId: 's1' }).signals).toContain('invalid-tool-input');
    expect(evaluateToolCall('process', { action: 'explode', sessionId: 's1' })).toMatchObject({
      decision: 'require_approval',
      severity: 'dangerous',
      action: 'invalid_tool_input',
    });
    expect(evaluateToolCall('process', { action: 'explode', sessionId: 's1' }).reason)
      .not.toMatch(/explode/);
  });

  it('typed fields reject the wrong primitive', () => {
    expect(enforceToolInput('process', { action: 'poll', sessionId: 's1', timeout: 'soon' }))
      .toMatchObject({ ok: false, code: 'TYPE_COERCION' });
    expect(enforceToolInput('process', { action: 'paste', sessionId: 's1', bracketed: 'yes' }))
      .toMatchObject({ ok: false, code: 'TYPE_COERCION' });
  });
});
