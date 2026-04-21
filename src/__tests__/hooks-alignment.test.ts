import { describe, it, expect } from '@jest/globals';
import { REQUIRED_HOOK_NAMES } from '../setup/settings-hooks.js';

describe('Claude Code hooks — doctor/install alignment (guards against #23)', () => {
  it('exposes the canonical hook list', () => {
    expect(Array.isArray(REQUIRED_HOOK_NAMES)).toBe(true);
    expect(REQUIRED_HOOK_NAMES.length).toBeGreaterThan(0);
  });

  it('does not include SessionEnd — that hook crashes OpenClaw agents and was removed from defaults', () => {
    expect(REQUIRED_HOOK_NAMES).not.toContain('SessionEnd');
  });

  it('includes PreCompact, SessionStart, UserPromptSubmit — the three hooks install configures', () => {
    expect(REQUIRED_HOOK_NAMES).toEqual(
      expect.arrayContaining(['PreCompact', 'SessionStart', 'UserPromptSubmit']),
    );
  });

  it('is immutable (cannot be mutated by callers at runtime)', () => {
    expect(() => {
      (REQUIRED_HOOK_NAMES as string[]).push('SessionEnd');
    }).toThrow();
  });
});
