import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

describe('CLAUDE.md ghost-tool block refresh (guards against #27)', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let previousExitCode: string | number | null | undefined;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-claude-md-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    previousExitCode = process.exitCode;
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    logSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    process.exitCode = previousExitCode;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  async function loadClaudeMdModule() {
    return import('../setup/claude-md.js');
  }

  function claudeMdPath(): string {
    return path.join(tempHome, '.claude', 'CLAUDE.md');
  }

  it('replaces an old ghost-tool block with the current content', async () => {
    fs.mkdirSync(path.join(tempHome, '.claude'), { recursive: true });
    const staleBlock = [
      '# Some project-specific notes',
      '',
      'Stay focused.',
      '',
      '# ShieldCortex — Memory System',
      '',
      "You have access to a persistent memory system via MCP tools (`remember`, `recall`, `get_context`, `forget`).",
      '',
      '**MUST use `remember` immediately when any of these occur:**',
      '- A decision is made',
      '',
      'Call `remember` right after the event happens.',
      '',
    ].join('\n');
    fs.writeFileSync(claudeMdPath(), staleBlock, 'utf-8');

    const mod = await loadClaudeMdModule() as unknown as { setupClaudeMd?: (opts?: unknown) => Promise<void> };
    // setupClaudeMd orchestrates more than just CLAUDE.md. We only want the
    // Claude Code step here. Dynamically re-import and call via the internal
    // flow by using the exported orchestrator up to the Claude Code phase —
    // the simplest signal is the file contents after the orchestrator runs.
    // We cannot easily stub the other phases without a bigger refactor, so
    // instead we run the export and let the other phases try and fail quietly
    // (they write into tempHome as well, which is isolated per test).
    try {
      await mod.setupClaudeMd?.();
    } catch {
      // Other phases (MCP config, hooks) are best-effort in this test and can
      // fail harmlessly; we only assert the CLAUDE.md result.
    }

    const after = fs.readFileSync(claudeMdPath(), 'utf-8');

    // Original content before the marker is preserved.
    expect(after).toContain('Some project-specific notes');
    expect(after).toContain('Stay focused.');

    // The marker still appears.
    expect(after).toContain('# ShieldCortex — Memory System');

    // Old ghost-tool imperative is gone.
    expect(after).not.toContain('**MUST use `remember` immediately');

    // New content is in place (signature line).
    expect(after).toContain('**Automatic capture** — no tool calls required.');
    // And the anti-nag line (may span a newline in source, so match a shorter contiguous part).
    expect(after).toContain('Do not nag yourself');

    // Only one marker after the refresh (no duplicate blocks).
    const markerMatches = after.match(/# ShieldCortex — Memory System/g) || [];
    expect(markerMatches).toHaveLength(1);
  });

  it('is idempotent when current content is already installed', async () => {
    fs.mkdirSync(path.join(tempHome, '.claude'), { recursive: true });
    const mod = await loadClaudeMdModule() as unknown as { setupClaudeMd?: (opts?: unknown) => Promise<void> };
    try { await mod.setupClaudeMd?.(); } catch { /* see note in test above */ }
    const firstPass = fs.readFileSync(claudeMdPath(), 'utf-8');

    try { await mod.setupClaudeMd?.(); } catch { /* see note in test above */ }
    const secondPass = fs.readFileSync(claudeMdPath(), 'utf-8');

    expect(secondPass).toEqual(firstPass);
  });
});
