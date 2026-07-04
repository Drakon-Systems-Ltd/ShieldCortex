import { describe, expect, it } from '@jest/globals';
import { shouldShowInteractiveBanner } from '../index.js';

/**
 * D3 regression: the stats banner must show for
 * normal interactive CLI commands (status, scan, doctor, audit, …) but NOT for
 * the MCP stdio server path or the per-prompt hook path.
 *
 * The old guard `argv[2] && mode !== 'mcp'` excluded every normal subcommand
 * because parseArgs() defaults `mode` to 'mcp' for everything except the
 * explicit server modes.
 *
 * `argv` here mirrors process.argv: [node, script, <cmd>, ...].
 */
function argv(...rest: string[]): string[] {
  return ['node', '/usr/local/bin/shieldcortex', ...rest];
}

describe('shouldShowInteractiveBanner (D3 banner guard)', () => {
  it('SHOWS for normal interactive subcommands that parse to mode "mcp"', () => {
    // These all keep the default mode 'mcp' in parseArgs but are CLI commands
    // that return before the stdio server starts — the regressed cases.
    for (const cmd of ['status', 'scan', 'doctor', 'audit', 'setup', 'install', 'license', 'xray']) {
      expect(shouldShowInteractiveBanner(argv(cmd), 'mcp')).toBe(true);
    }
  });

  it('SHOWS for the positional `mcp` scanner subcommand (not the stdio server)', () => {
    // `shieldcortex mcp ...` is the MCP-config scanner — interactive, prints
    // normal stdout, parses to mode 'mcp' but is NOT the stdio server.
    expect(shouldShowInteractiveBanner(argv('mcp', 'scan'), 'mcp')).toBe(true);
  });

  it('SHOWS for non-mcp server modes (dashboard/api/worker)', () => {
    expect(shouldShowInteractiveBanner(argv('dashboard'), 'dashboard')).toBe(true);
    expect(shouldShowInteractiveBanner(argv('api'), 'api')).toBe(true);
    expect(shouldShowInteractiveBanner(argv('worker'), 'worker')).toBe(true);
    // --mode form (flag-only, non-mcp).
    expect(shouldShowInteractiveBanner(argv('--mode', 'dashboard'), 'dashboard')).toBe(true);
  });

  it('does NOT show for the bare MCP stdio invocation', () => {
    expect(shouldShowInteractiveBanner(argv(), 'mcp')).toBe(false);
  });

  it('does NOT show for explicit --mode mcp (stdio server)', () => {
    expect(shouldShowInteractiveBanner(argv('--mode', 'mcp'), 'mcp')).toBe(false);
  });

  it('does NOT show for a flag-only --db launch (stdio server)', () => {
    expect(shouldShowInteractiveBanner(argv('--db', '/tmp/x.db'), 'mcp')).toBe(false);
  });

  it('does NOT show for --version / --help (flag-only, mode mcp)', () => {
    // These are handled (and must stay script-clean) after the banner block.
    expect(shouldShowInteractiveBanner(argv('--version'), 'mcp')).toBe(false);
    expect(shouldShowInteractiveBanner(argv('-v'), 'mcp')).toBe(false);
    expect(shouldShowInteractiveBanner(argv('--help'), 'mcp')).toBe(false);
  });
});
