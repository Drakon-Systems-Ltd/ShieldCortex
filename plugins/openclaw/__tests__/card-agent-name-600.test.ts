/**
 * #600: the OpenClaw approval card said "Jarvis wants to use …" on every host,
 * whatever the agent was called — including customer installs. The subject is
 * now the neutral AGENT_SUBJECT, and no card branch names a fleet agent.
 */
import { describe, it, expect } from '@jest/globals';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateToolCall } from '../../../src/defence/iron-dome/tool-action-guard.js';
import { AGENT_SUBJECT, formatActionGuardPrompt } from '../interceptor.js';

// Our own fleet's agent names. None of them may appear in text a customer sees.
const FLEET_NAMES = /\b(Jarvis|TARS|Friday|Veronica|Vision|Case|Athena|Edith|Hera)\b/;

const HERE = path.dirname(fileURLToPath(import.meta.url));

describe('#600 approval card never names a specific agent', () => {
  const dangerous = {
    decision: 'require_approval' as const,
    severity: 'dangerous' as const,
    family: 'write',
    action: 'edit_file',
    reason: 'memory-write payload is a dangerous command',
    signals: ['write-content-dangerous', 'privilege-escalation'],
  };

  it('generic branch (the card in the report): leads with the neutral subject', () => {
    const text = formatActionGuardPrompt('edit', dangerous, { action: 'edit_file' });
    expect(text).toContain(`${AGENT_SUBJECT} wants to use edit, and ShieldCortex rated this call dangerous.`);
    expect(text).not.toMatch(FLEET_NAMES);
  });

  it('native-process branch: neutral subject', () => {
    const args = { action: 'write', sessionId: 's1', data: 'x' };
    const text = formatActionGuardPrompt('process', evaluateToolCall('process', args), args);
    expect(text).toContain(`${AGENT_SUBJECT} wants to type into a running command (write)`);
    expect(text).not.toMatch(FLEET_NAMES);
  });

  it('schema-invalid branch: neutral subject', () => {
    const v = { ...dangerous, action: 'invalid_tool_input', signals: ['invalid-tool-input', 'unknown-keys'] };
    const text = formatActionGuardPrompt('mystery', v, { action: 'list' });
    expect(text).toContain(`${AGENT_SUBJECT} used mystery, which ShieldCortex does not fully recognise yet`);
    expect(text).not.toMatch(FLEET_NAMES);
  });

  it('the subject itself is not a fleet name', () => {
    expect(AGENT_SUBJECT).not.toMatch(FLEET_NAMES);
    expect(AGENT_SUBJECT.trim().length).toBeGreaterThan(0);
  });

  it('no string or template literal in the interceptor names a fleet agent', () => {
    // Comments may mention hosts for history; operator-facing literals may not.
    const src = fs.readFileSync(path.join(HERE, '..', 'interceptor.ts'), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/(^|[^:])\/\/.*$/gm, '$1');
    const literals = src.match(/`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"/g) ?? [];
    const offenders = literals.filter((l) => FLEET_NAMES.test(l));
    expect(offenders).toEqual([]);
  });
});
