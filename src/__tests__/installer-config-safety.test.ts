import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * Phase 5 hardening — installers must NEVER overwrite a user's config when a
 * JSON file is momentarily unparseable (trailing comma, JSONC `// comments`,
 * or a partial concurrent write by Claude Code itself). Three install paths
 * previously read with `catch { return {} }` and then unconditionally wrote
 * the mutated object back, replacing the user's ENTIRE config with only
 * ShieldCortex's entries.
 *
 * The uninstall path already gets this right (uninstall.ts: "aborting to
 * avoid corruption"). These tests pin the same discipline on the install
 * side via two shared helpers and the three installers that adopt them.
 */
describe('installer config safety — never wipe on parse failure, back up before mutate', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;
  let tempHome: string;
  let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let warnSpy: jest.SpiedFunction<typeof console.warn>;
  let errorSpy: jest.SpiedFunction<typeof console.error>;

  beforeEach(() => {
    jest.resetModules();
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-installer-safety-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    homedirSpy.mockRestore();
    logSpy.mockRestore();
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalUserProfile === undefined) delete process.env.USERPROFILE;
    else process.env.USERPROFILE = originalUserProfile;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  // ── Shared helpers: readJsonConfigOrAbort / writeJsonConfigWithBackup ──

  describe('readJsonConfigOrAbort', () => {
    it('returns {} for a non-existent file (fresh install is fine)', async () => {
      const { readJsonConfigOrAbort } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'does-not-exist.json');
      expect(readJsonConfigOrAbort(p)).toEqual({});
    });

    it('parses a valid existing file', async () => {
      const { readJsonConfigOrAbort } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'valid.json');
      fs.writeFileSync(p, JSON.stringify({ a: 1, nested: { b: 2 } }));
      expect(readJsonConfigOrAbort(p)).toEqual({ a: 1, nested: { b: 2 } });
    });

    it('THROWS (does not return {}) for an existing-but-unparseable file', async () => {
      const { readJsonConfigOrAbort } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'broken.json');
      const original = '{\n  // a JSONC comment VS Code allows\n  "a": 1,\n}\n';
      fs.writeFileSync(p, original);
      expect(() => readJsonConfigOrAbort(p)).toThrow();
      // The file must be left exactly as it was.
      expect(fs.readFileSync(p, 'utf-8')).toBe(original);
    });

    it('error message names the path and mentions JSONC/comments not being supported', async () => {
      const { readJsonConfigOrAbort } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'jsonc.json');
      fs.writeFileSync(p, '{ "a": 1, } // trailing comma + comment\n');
      let message = '';
      try {
        readJsonConfigOrAbort(p);
      } catch (err: any) {
        message = String(err.message);
      }
      expect(message).toContain(p);
      expect(message.toLowerCase()).toMatch(/comment|jsonc/);
    });
  });

  describe('writeJsonConfigWithBackup', () => {
    it('writes a backup of the ORIGINAL content before mutating, live file gets new content', async () => {
      const { writeJsonConfigWithBackup } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'config.json');
      const original = JSON.stringify({ keep: true, value: 'old' }, null, 2) + '\n';
      fs.writeFileSync(p, original);

      writeJsonConfigWithBackup(p, { keep: true, value: 'new' });

      const backupPath = `${p}.bak-shieldcortex`;
      expect(fs.existsSync(backupPath)).toBe(true);
      // Backup is byte-for-byte the original.
      expect(fs.readFileSync(backupPath, 'utf-8')).toBe(original);
      // Live file has the new content.
      expect(JSON.parse(fs.readFileSync(p, 'utf-8'))).toEqual({ keep: true, value: 'new' });
    });

    it('fresh install: no backup written for a non-existent file, and the file is created', async () => {
      const { writeJsonConfigWithBackup } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'sub', 'fresh.json');
      expect(() => writeJsonConfigWithBackup(p, { created: true })).not.toThrow();
      expect(fs.existsSync(`${p}.bak-shieldcortex`)).toBe(false);
      expect(JSON.parse(fs.readFileSync(p, 'utf-8'))).toEqual({ created: true });
    });

    it('uses 2-space indentation and a trailing newline (matches existing writers)', async () => {
      const { writeJsonConfigWithBackup } = await import('../setup/json-config.js');
      const p = path.join(tempHome, 'indent.json');
      writeJsonConfigWithBackup(p, { a: { b: 1 } });
      const raw = fs.readFileSync(p, 'utf-8');
      expect(raw).toBe('{\n  "a": {\n    "b": 1\n  }\n}\n');
    });
  });

  // ── settings-hooks.ts: parse failure must abort, not wipe ──

  describe('setupHooks — settings.json', () => {
    function settingsPath(): string {
      return path.join(tempHome, '.claude', 'settings.json');
    }

    it('ABORTS and leaves the file UNCHANGED when settings.json is unparseable (JSONC)', async () => {
      fs.mkdirSync(path.join(tempHome, '.claude'), { recursive: true });
      // JSONC + trailing comma — what VS Code / a half-written file looks like.
      const original = '{\n  // user comment\n  "model": "opus",\n  "permissions": { "allow": ["Bash"] },\n}\n';
      fs.writeFileSync(settingsPath(), original);

      const { setupHooks } = await import('../setup/settings-hooks.js');
      expect(() => setupHooks()).toThrow();
      // The original config MUST be intact — not replaced with hooks-only.
      expect(fs.readFileSync(settingsPath(), 'utf-8')).toBe(original);
    });

    it('preserves unrelated sibling keys (permissions/env/model) when adding hooks', async () => {
      fs.mkdirSync(path.join(tempHome, '.claude'), { recursive: true });
      fs.writeFileSync(
        settingsPath(),
        JSON.stringify(
          { model: 'opus', permissions: { allow: ['Bash'] }, env: { FOO: 'bar' } },
          null,
          2,
        ),
      );

      const { setupHooks } = await import('../setup/settings-hooks.js');
      setupHooks();

      const after = JSON.parse(fs.readFileSync(settingsPath(), 'utf-8'));
      expect(after.model).toBe('opus');
      expect(after.permissions).toEqual({ allow: ['Bash'] });
      expect(after.env).toEqual({ FOO: 'bar' });
      // And the hooks were actually added.
      expect(after.hooks.PreCompact).toBeDefined();
      expect(after.hooks.SessionStart).toBeDefined();
      expect(after.hooks.UserPromptSubmit).toBeDefined();
    });

    it('backs up the existing settings.json before writing hooks', async () => {
      fs.mkdirSync(path.join(tempHome, '.claude'), { recursive: true });
      const original = JSON.stringify({ model: 'opus' }, null, 2) + '\n';
      fs.writeFileSync(settingsPath(), original);

      const { setupHooks } = await import('../setup/settings-hooks.js');
      setupHooks();

      expect(fs.readFileSync(`${settingsPath()}.bak-shieldcortex`, 'utf-8')).toBe(original);
    });
  });

  // ── claude-md.ts setupGlobalMcp — parse failure aborts + ownership guard ──

  describe('setupGlobalMcp — ~/.claude.json', () => {
    function claudeJsonPath(): string {
      return path.join(tempHome, '.claude.json');
    }

    it('ABORTS and leaves ~/.claude.json UNCHANGED when it is unparseable', async () => {
      const original = '{\n  // claude code primary state\n  "mcpServers": {},\n}\n';
      fs.writeFileSync(claudeJsonPath(), original);

      const { setupGlobalMcp } = await import('../setup/claude-md.js');
      expect(() => setupGlobalMcp()).toThrow();
      expect(fs.readFileSync(claudeJsonPath(), 'utf-8')).toBe(original);
    });

    it('preserves unrelated top-level keys and other mcpServers when adding memory', async () => {
      fs.writeFileSync(
        claudeJsonPath(),
        JSON.stringify(
          {
            numStartups: 42,
            mcpServers: { other: { command: 'node', args: ['/opt/other.js'] } },
          },
          null,
          2,
        ),
      );

      const { setupGlobalMcp } = await import('../setup/claude-md.js');
      setupGlobalMcp();

      const after = JSON.parse(fs.readFileSync(claudeJsonPath(), 'utf-8'));
      expect(after.numStartups).toBe(42);
      expect(after.mcpServers.other).toBeDefined();
      expect(after.mcpServers.memory).toBeDefined();
    });

    it('does NOT clobber a differently-owned mcpServers.memory entry (ownership guard)', async () => {
      // Upstream @modelcontextprotocol/server-memory registers under the same key.
      fs.writeFileSync(
        claudeJsonPath(),
        JSON.stringify(
          {
            mcpServers: {
              memory: { type: 'stdio', command: 'npx', args: ['-y', '@modelcontextprotocol/server-memory'] },
            },
          },
          null,
          2,
        ),
      );

      const { setupGlobalMcp } = await import('../setup/claude-md.js');
      setupGlobalMcp();

      const after = JSON.parse(fs.readFileSync(claudeJsonPath(), 'utf-8'));
      // The foreign entry must be left intact.
      expect(after.mcpServers.memory.args).toContain('@modelcontextprotocol/server-memory');
    });

    it('backs up ~/.claude.json before mutating it', async () => {
      const original = JSON.stringify({ mcpServers: {} }, null, 2) + '\n';
      fs.writeFileSync(claudeJsonPath(), original);

      const { setupGlobalMcp } = await import('../setup/claude-md.js');
      setupGlobalMcp();

      expect(fs.readFileSync(`${claudeJsonPath()}.bak-shieldcortex`, 'utf-8')).toBe(original);
    });
  });
});
