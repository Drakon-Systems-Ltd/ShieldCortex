import { describe, expect, it } from '@jest/globals';
import { evaluateAction, evaluateToolCall } from '../enforce.js';

describe('shieldcortex/enforce', () => {
  it('evaluateToolCall hard-blocks a catastrophic rm', () => {
    const v = evaluateToolCall('Bash', { command: 'rm -rf /' });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });

  it('evaluateAction returns a guard verdict and a lease slot', () => {
    const result = evaluateAction('Bash', { command: 'echo hello' }, { skipLease: true });
    expect(result.verdict.decision).toBe('allow');
    expect(result.lease).toBeNull();
  });

  it('allows a benign read', () => {
    const v = evaluateToolCall('Read', { path: 'README.md' });
    expect(v.decision).toBe('allow');
  });
});
