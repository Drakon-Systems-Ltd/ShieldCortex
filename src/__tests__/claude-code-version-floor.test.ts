/**
 * Claude Code enforcement floor — doctor reports the harness version it depends on.
 *
 * Motivating incident (2026-07-30, aiquant): Claude Code 2.1.76 discarded the
 * Action Guard's `"ask"` verdict under `bypassPermissions` and ran a global npm
 * install. The guard was correct, the audit row recorded it, and nothing was
 * stopped — because the harness that honours our verdicts is versioned
 * independently of us and nobody was tracking it across two install channels.
 *
 * These tests pin the reporting: below the floor is a FAIL (the dangerous tier
 * is decorative on that box), an unreadable version is a WARN (unproven, not
 * assumed fine), and no Claude Code at all is INFO (the floor does not apply).
 */
import path from 'path';
import { describe, expect, it } from '@jest/globals';
import {
  CLAUDE_CODE_ENFORCEMENT_FLOOR,
  classifyClaudeCodeChannel,
  detectClaudeCode,
  parseClaudeCodeVersion,
  upgradeCommandFor,
  type DetectClaudeCodeDeps,
} from '../integrations/claude-code-version.js';
import { checkClaudeCodeVersion } from '../cli/doctor.js';

const HOME = '/home/tester';

/** A detector wired to fixture values instead of the host's real install. */
function deps(overrides: {
  bin?: string | null;
  real?: string | null;
  versionOutput?: string;
  versionThrows?: string;
}): DetectClaudeCodeDeps {
  return {
    which: () => (overrides.bin === undefined ? '/home/tester/.local/bin/claude' : overrides.bin),
    realpath: () => (overrides.real === undefined ? '/home/tester/.local/share/claude/versions/2.1.220' : overrides.real),
    runVersion: () => {
      if (overrides.versionThrows) throw new Error(overrides.versionThrows);
      return overrides.versionOutput ?? '2.1.220 (Claude Code)';
    },
    homedir: () => HOME,
  };
}

describe('parseClaudeCodeVersion', () => {
  it('reads the version out of the real output shape', () => {
    expect(parseClaudeCodeVersion('2.1.220 (Claude Code)')).toBe('2.1.220');
  });

  it('tolerates surrounding noise', () => {
    expect(parseClaudeCodeVersion('  claude version 2.1.76 \n')).toBe('2.1.76');
  });

  it('returns null when there is no version to read', () => {
    expect(parseClaudeCodeVersion('command not found')).toBeNull();
    expect(parseClaudeCodeVersion('')).toBeNull();
  });
});

describe('classifyClaudeCodeChannel', () => {
  it('names the native installer layout', () => {
    expect(classifyClaudeCodeChannel(path.join(HOME, '.local/share/claude/versions/2.1.220'), HOME)).toBe('native');
  });

  it('names an npm global', () => {
    expect(
      classifyClaudeCodeChannel('/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js', HOME),
    ).toBe('npm');
  });

  it('refuses to guess an unrecognised layout', () => {
    expect(classifyClaudeCodeChannel('/opt/weird/claude', HOME)).toBe('unknown');
    expect(classifyClaudeCodeChannel(null, HOME)).toBe('unknown');
  });

  it('does not mistake another user home for this one', () => {
    expect(classifyClaudeCodeChannel('/home/someone-else/.local/share/claude/versions/2.1.220', HOME)).toBe(
      'unknown',
    );
  });
});

describe('detectClaudeCode', () => {
  it('returns null when claude is not on PATH', () => {
    expect(detectClaudeCode(deps({ bin: null }))).toBeNull();
  });

  it('reports version, channel and paths for a healthy install', () => {
    const install = detectClaudeCode(deps({}));
    expect(install).toMatchObject({
      version: '2.1.220',
      rawVersion: '2.1.220 (Claude Code)',
      channel: 'native',
      binPath: '/home/tester/.local/bin/claude',
    });
    expect(install?.error).toBeUndefined();
  });

  it('records the failure instead of throwing when --version cannot run', () => {
    const install = detectClaudeCode(deps({ versionThrows: 'ETIMEDOUT' }));
    expect(install?.version).toBeNull();
    expect(install?.error).toContain('ETIMEDOUT');
  });
});

describe('upgradeCommandFor', () => {
  it('gives the channel-correct instruction', () => {
    expect(upgradeCommandFor('npm')).toContain('npm i -g @anthropic-ai/claude-code@latest');
    expect(upgradeCommandFor('native')).toContain('claude update');
  });

  it('offers both when the channel is unknown, rather than guessing one', () => {
    const fix = upgradeCommandFor('unknown');
    expect(fix).toContain('claude update');
    expect(fix).toContain('npm i -g @anthropic-ai/claude-code@latest');
  });
});

describe('doctor check — Claude Code version', () => {
  it('FAILS below the floor and names the actual exposure', async () => {
    const result = await checkClaudeCodeVersion(
      deps({ versionOutput: '2.1.76 (Claude Code)', real: '/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js' }),
    );
    expect(result.status).toBe('fail');
    expect(result.message).toContain('2.1.76');
    expect(result.message).toContain(CLAUDE_CODE_ENFORCEMENT_FLOOR);
    expect(result.message).toContain('npm channel');
    // The operator must learn that the audit log is misleading on this box —
    // that is the whole reason the incident went unnoticed for 144 versions.
    expect(result.message).toContain('audit log');
    expect(result.fix).toContain('npm i -g @anthropic-ai/claude-code@latest');
  });

  it('PASSES at the floor exactly — the floor is the lowest build proven good', async () => {
    const result = await checkClaudeCodeVersion(deps({ versionOutput: `${CLAUDE_CODE_ENFORCEMENT_FLOOR} (Claude Code)` }));
    expect(result.status).toBe('pass');
    expect(result.message).toContain(CLAUDE_CODE_ENFORCEMENT_FLOOR);
  });

  it('PASSES above the floor and states the channel', async () => {
    const result = await checkClaudeCodeVersion(deps({}));
    expect(result.status).toBe('pass');
    expect(result.message).toContain('2.1.220');
    expect(result.message).toContain('native channel');
  });

  it('WARNS rather than passing when the version cannot be read', async () => {
    const result = await checkClaudeCodeVersion(deps({ versionThrows: 'spawn ETIMEDOUT' }));
    expect(result.status).toBe('warn');
    expect(result.message).toContain('cannot confirm');
    expect(result.fix).toBeDefined();
  });

  it('WARNS when --version prints something unparseable', async () => {
    const result = await checkClaudeCodeVersion(deps({ versionOutput: 'not a version' }));
    expect(result.status).toBe('warn');
  });

  it('is INFO, not a fault, on a box with no Claude Code', async () => {
    const result = await checkClaudeCodeVersion(deps({ bin: null }));
    expect(result.status).toBe('info');
    expect(result.message).toContain('not detected');
  });

  it('still reports the version when the channel cannot be named', async () => {
    const result = await checkClaudeCodeVersion(deps({ real: '/opt/somewhere/claude' }));
    expect(result.status).toBe('pass');
    expect(result.message).toContain('unknown channel');
  });
});
