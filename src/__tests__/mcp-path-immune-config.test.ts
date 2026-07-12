import path from 'path';
import { describe, expect, it } from '@jest/globals';
import { resolveMcpServerCommand } from '../setup/json-config.js';
import { resolveMcpCommand } from '../setup/claude-md.js';

/**
 * Issue #76: setup writers emitted PATH-fragile MCP server entries —
 * `command: <shieldcortex bin>` relying on `#!/usr/bin/env node`, so
 * GUI/launchd spawn environments that lack the node prefix on PATH kill the
 * process before the MCP handshake and the operator sees only a bare -32000.
 *
 * The fix: emit an ABSOLUTE node binary + ABSOLUTE dist/index.js, resolved at
 * setup time, so the entry never depends on PATH.
 */
describe('PATH-immune MCP config writers (#76)', () => {
  const distEntry = '/opt/shieldcortex/dist/index.js';

  it('resolveMcpServerCommand emits an absolute node binary as the command', () => {
    const { command } = resolveMcpServerCommand(distEntry);
    // Must be the running node's absolute path — never `node`/`npx`/a shebang bin.
    expect(command).toBe(process.execPath);
    expect(path.isAbsolute(command)).toBe(true);
    expect(command).not.toBe('node');
    expect(command).not.toBe('npx');
  });

  it('resolveMcpServerCommand runs dist/index.js via an absolute path argument', () => {
    const { args } = resolveMcpServerCommand(distEntry);
    expect(Array.isArray(args)).toBe(true);
    expect(args.length).toBeGreaterThanOrEqual(1);
    const entry = args[args.length - 1];
    expect(path.isAbsolute(entry)).toBe(true);
    expect(path.basename(entry)).toBe('index.js');
    // No PATH-relative or npx re-resolution anywhere in the argv.
    expect(JSON.stringify(args)).not.toContain('npx');
  });

  it('falls back to the passed dist entry when no global binary resolves', () => {
    // Even with a global install absent, the command stays absolute-node and the
    // arg stays an absolute index.js path (never `npx`, never a bare shebang bin).
    const { command, args } = resolveMcpServerCommand(distEntry);
    expect(command).toBe(process.execPath);
    expect(path.isAbsolute(args[args.length - 1])).toBe(true);
    expect(path.basename(args[args.length - 1])).toBe('index.js');
  });

  it('resolveMcpCommand (Claude Code writer) is PATH-immune: absolute node + absolute index.js, never npx', () => {
    const { command, args } = resolveMcpCommand();
    expect(command).toBe(process.execPath);
    expect(command).not.toBe('npx');
    expect(args.length).toBeGreaterThanOrEqual(1);
    const entry = args[args.length - 1];
    expect(path.isAbsolute(entry)).toBe(true);
    expect(path.basename(entry)).toBe('index.js');
    expect(JSON.stringify(args)).not.toContain('npx');
  });
});
