/**
 * internal #87 — Codex native hooks glue the `openclaw` namespace onto
 * OpenClaw dynamic tools with no delimiter (codex-rs `impl Display for
 * ToolName` writes `{namespace}{name}`), and OpenClaw's native-hook relay
 * hands that spelling to `before_tool_call` unchanged. Observed on a live
 * host: `tool = "openclawgateway_exec"`, UNKNOWN_KEYS on every declared exec
 * field, card cancelled. The projection itself is the native `exec` bag minus
 * `host`/`security`/`ask`/`node` (`pinExecToolTarget`, host=gateway).
 *
 * The fix is exact alias membership for both the bare projection names and the
 * glued spellings. It is deliberately NOT a prefix rule.
 */
import { describe, expect, it } from '@jest/globals';
import {
  canonicalExactSpecialAlias,
  contractDriftFor,
  enforceToolInput,
  exactSpecialContractName,
  hasExactSpecialToolSchema,
  schemaFamilyForTool,
  validateToolInput,
} from '../tool-input-schema.js';
import { classifyFamily, evaluateToolCall, normaliseToolName } from '../tool-action-guard.js';

const BIN = String.fromCharCode(114, 109);
const WIPE = [BIN, ['-', 'r', 'f'].join(''), '/'].join(' ');

describe('#87 Codex glued-namespace projections resolve to the native contracts', () => {
  it.each([
    ['gateway_exec', 'openclaw.exec', 'exec'],
    ['openclawgateway_exec', 'openclaw.exec', 'exec'],
    ['OpenClawGateway_Exec', 'openclaw.exec', 'exec'],
    ['gateway_process', 'openclaw.process', 'read'],
    ['openclawgateway_process', 'openclaw.process', 'read'],
  ])('%s is an exact-special %s contract (family %s)', (name, contract, family) => {
    expect(hasExactSpecialToolSchema(name)).toBe(true);
    expect(exactSpecialContractName(name)).toBe(contract);
    expect(schemaFamilyForTool(name)).toBe(family);
    expect(classifyFamily(name)).toBe(family);
  });

  it('declared exec fields on the glued spelling are accepted, not UNKNOWN_KEYS', () => {
    const r = validateToolInput('openclawgateway_exec', {
      command: 'ls -la /tmp', workdir: '/tmp', timeoutSeconds: 30, background: false,
    });
    expect(r.ok).toBe(true);
  });

  it('an undeclared field on the glued spelling is dropped as contract drift, exactly as on bare exec', () => {
    // Exact-special contracts drop fields no reader consults and RECORD the name
    // (validateToolInput enforce path); they do not hard-deny on them. The glued
    // spelling must behave identically to `exec`, not fall back to the generic
    // EXEC_KEYS bag where every native field is an UNKNOWN_KEY.
    for (const name of ['exec', 'gateway_exec', 'openclawgateway_exec']) {
      const r = validateToolInput(name, { command: 'ls', title: 'List things' });
      expect(r.ok).toBe(true);
      if (r.ok) expect(r.strippedKeys).toEqual(['title']);
      const drift = contractDriftFor(name, { command: 'ls', title: 'List things' });
      expect(drift?.contract).toBe('openclaw.exec');
      expect(drift?.droppedKeys).toEqual(['title']);
    }
  });

  it.each(['cmd', 'script', 'code', 'input'])(
    'a catastrophic payload in declared command key %s is blocked on the glued spelling',
    (key) => {
      // Every COMMAND_KEYS member is declared on the exec contract, so none is
      // dropped as drift; the scanner reads them all and the verdict is terminal.
      const bag: Record<string, unknown> = { command: 'ls', [key]: WIPE };
      const r = validateToolInput('openclawgateway_exec', bag);
      expect(r.ok).toBe(true);
      const v = evaluateToolCall('openclawgateway_exec', bag);
      expect(v.decision).toBe('block');
      expect(v.severity).toBe('catastrophic');
    },
  );

  it('process inspect verbs on the glued spelling allow', () => {
    const r = enforceToolInput('openclawgateway_process', { action: 'list' });
    expect(r.ok).toBe(true);
    const v = evaluateToolCall('openclawgateway_process', { action: 'poll', sessionId: 's1' });
    expect(v.decision).toBe('allow');
  });

  it('a benign command through the glued projection is not interrupted', () => {
    const v = evaluateToolCall('openclawgateway_exec', { command: 'git status', workdir: '/tmp' });
    expect(v.decision).toBe('allow');
  });

  it('a catastrophic command through the glued projection is still blocked', () => {
    const v = evaluateToolCall('openclawgateway_exec', { command: WIPE });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  it('a dangerous command through the glued projection still requires approval', () => {
    const v = evaluateToolCall('openclawgateway_exec', { command: 'sudo systemctl restart nginx' });
    expect(v.decision).toBe('require_approval');
  });
});

describe('#87 the alias is exact membership, never a prefix rule', () => {
  it.each([
    'openclawrm',
    'openclawexec',          // namespace + bare `exec` is not a projection name
    'openclawprocess',
    'openclaw_gateway_exec',
    'openclaw__gateway_exec', // toolsAllow spelling; split leaves `gateway_exec` for normalise only
    'gatewayexec',
    'xopenclawgateway_exec',
  ])('%s grants no exact-special contract', (name) => {
    expect(hasExactSpecialToolSchema(name)).toBe(false);
    expect(exactSpecialContractName(name)).toBeNull();
  });

  it('MCP-fronted look-alikes borrow nothing', () => {
    for (const name of ['mcp__openclaw__gateway_exec', 'mcp__evil__openclawgateway_exec']) {
      expect(hasExactSpecialToolSchema(name)).toBe(false);
      expect(schemaFamilyForTool(name)).toBe('unknown');
    }
  });

  it('an unknown glued name with a mutation payload fails closed to approval, not allow', () => {
    const v = evaluateToolCall('openclawrm', { command: 'rm -r /tmp/x' });
    expect(v.decision).not.toBe('allow');
  });
});

describe('#87 normaliseToolName canonicalises only recognised glued aliases', () => {
  it.each([
    ['openclawgateway_exec', 'gateway_exec'],
    ['openclawgateway_process', 'gateway_process'],
    ['gateway_exec', 'gateway_exec'],
    ['exec', 'exec'],
    ['openclawrm', 'openclawrm'],
    ['mcp__memory__remember', 'remember'],
    ['Bash', 'bash'],
  ])('%s → %s', (input, expected) => {
    expect(normaliseToolName(input)).toBe(expected);
    expect(canonicalExactSpecialAlias(normaliseToolName(input))).toBe(expected);
  });
});
