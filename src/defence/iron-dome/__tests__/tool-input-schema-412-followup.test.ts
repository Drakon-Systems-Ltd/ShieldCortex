/**
 * #412 follow-up cases (Grok holes)
 */
import { describe, expect, it } from '@jest/globals';
import { enforceToolInput } from '../tool-input-schema.js';
import { evaluateToolCall } from '../tool-action-guard.js';

describe('#412 follow-up family alignment', () => {
  it('run_command is exec family — unknown keys blocked', () => {
    const r = enforceToolInput('run_command', {
      command: 'echo safe',
      hidden_script: 'not-allowed-key',
    });
    expect(r.ok).toBe(false);
  });

  it('web_fetch allows url; rejects unknown keys', () => {
    expect(enforceToolInput('web_fetch', { url: 'https://example.com/path' }).ok).toBe(true);
    expect(enforceToolInput('web_fetch', { url: 'https://example.com', evil: 1 }).ok).toBe(false);
  });

  it('nested env may only be string map — no nested objects', () => {
    expect(enforceToolInput('Bash', { command: 'true', env: { PATH: '/bin' } }).ok).toBe(true);
    expect(enforceToolInput('Bash', { command: 'true', env: { nested: { x: 1 } } }).ok).toBe(false);
  });

  it('stdin is an allowed exec surface', () => {
    const r = enforceToolInput('Bash', { command: 'cat', stdin: 'hello' });
    expect(r.ok).toBe(true);
  });

  it('evaluateToolCall still allows clean Bash', () => {
    const v = evaluateToolCall('Bash', { command: 'git status' });
    expect(v.decision).toBe('allow');
  });
});
