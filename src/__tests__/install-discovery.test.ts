import { describe, expect, it } from '@jest/globals';
import path from 'path';
import {
  installRootFromPath,
  discoverShieldcortexInstalls,
  type DiscoveryDeps,
} from '../setup/install-discovery.js';

/**
 * Multi-install discovery (#76): repair must find every ShieldCortex install a
 * host references so a "layer split" (repair heals A while the MCP client spawns
 * a broken B) can never report a false all-clear.
 */

describe('installRootFromPath', () => {
  const idRealpath = (p: string) => p;

  it('derives the install root from a dist/index.js entry', () => {
    expect(
      installRootFromPath('/opt/n_modules/shieldcortex/dist/index.js', { realpath: idRealpath }),
    ).toBe('/opt/n_modules/shieldcortex');
  });

  it('follows a bin symlink via realpath to the dist entry', () => {
    const realpath = (p: string) =>
      p === '/usr/local/bin/shieldcortex' ? '/opt/lib/shieldcortex/dist/index.js' : p;
    expect(
      installRootFromPath('/usr/local/bin/shieldcortex', { realpath }),
    ).toBe('/opt/lib/shieldcortex');
  });

  it('returns null for a path that does not mention shieldcortex', () => {
    expect(installRootFromPath('/opt/other-server/dist/index.js', { realpath: idRealpath })).toBeNull();
  });

  it('returns null for a shieldcortex path that is not a dist entry', () => {
    expect(installRootFromPath('/opt/shieldcortex/README.md', { realpath: idRealpath })).toBeNull();
  });
});

describe('discoverShieldcortexInstalls', () => {
  function deps(over: Partial<DiscoveryDeps>): Partial<DiscoveryDeps> {
    return {
      home: () => '/home/u',
      selfInstallDir: () => '/opt/self/shieldcortex',
      whichAll: () => [],
      readFile: () => { throw new Error('ENOENT'); },
      realpath: (p) => p,
      exists: () => true,
      ...over,
    };
  }

  it('always includes the running install, tagged self', () => {
    const installs = discoverShieldcortexInstalls(deps({}));
    expect(installs).toEqual([{ path: '/opt/self/shieldcortex', sources: ['self'] }]);
  });

  it('discovers a PATH install with a real better-sqlite3 dir', () => {
    const installs = discoverShieldcortexInstalls(deps({
      whichAll: () => ['/usr/bin/shieldcortex'],
      realpath: (p) => (p === '/usr/bin/shieldcortex' ? '/opt/global/shieldcortex/dist/index.js' : p),
      exists: (p) => p.includes('better-sqlite3'),
    }));
    const paths = installs.map((i) => i.path).sort();
    expect(paths).toContain('/opt/global/shieldcortex');
    const global = installs.find((i) => i.path === '/opt/global/shieldcortex');
    expect(global?.sources).toEqual(['PATH']);
  });

  it('discovers an install referenced by ~/.claude.json memory entry', () => {
    const claudeJson = JSON.stringify({
      mcpServers: { memory: { command: '/usr/bin/node', args: ['/opt/claude/shieldcortex/dist/index.js'] } },
    });
    const installs = discoverShieldcortexInstalls(deps({
      readFile: (p) => (p === path.join('/home/u', '.claude.json') ? claudeJson : (() => { throw new Error('ENOENT'); })()),
      exists: (p) => p.includes('better-sqlite3'),
    }));
    const claude = installs.find((i) => i.path === '/opt/claude/shieldcortex');
    expect(claude).toBeDefined();
    expect(claude?.sources).toEqual(['claude.json']);
  });

  it('ignores a foreign MCP entry that does not mention shieldcortex', () => {
    const claudeJson = JSON.stringify({
      mcpServers: { memory: { command: 'node', args: ['/opt/somebody-else/dist/index.js'] } },
    });
    const installs = discoverShieldcortexInstalls(deps({
      readFile: (p) => (p.endsWith('.claude.json') ? claudeJson : (() => { throw new Error('ENOENT'); })()),
      exists: () => true,
    }));
    // Only the self install — the foreign entry was rejected.
    expect(installs.map((i) => i.path)).toEqual(['/opt/self/shieldcortex']);
  });

  it('dedupes the same install seen from multiple sources, merging tags', () => {
    const claudeJson = JSON.stringify({
      mcpServers: { memory: { command: 'node', args: ['/opt/self/shieldcortex/dist/index.js'] } },
    });
    const installs = discoverShieldcortexInstalls(deps({
      whichAll: () => ['/usr/bin/shieldcortex'],
      realpath: (p) => (p === '/usr/bin/shieldcortex' ? '/opt/self/shieldcortex/dist/index.js' : p),
      readFile: (p) => (p.endsWith('.claude.json') ? claudeJson : (() => { throw new Error('ENOENT'); })()),
      exists: (p) => p.includes('better-sqlite3'),
    }));
    expect(installs).toHaveLength(1);
    expect(installs[0].path).toBe('/opt/self/shieldcortex');
    expect(installs[0].sources).toEqual(['PATH', 'claude.json', 'self']);
  });

  it('picks up a Codex config.toml shieldcortex reference', () => {
    const toml = [
      '[mcp_servers.shieldcortex-memory]',
      'command = "/usr/bin/node"',
      'args = ["/opt/codex/shieldcortex/dist/index.js"]',
    ].join('\n');
    const installs = discoverShieldcortexInstalls(deps({
      readFile: (p) => (p.endsWith(path.join('.codex', 'config.toml')) ? toml : (() => { throw new Error('ENOENT'); })()),
      exists: (p) => p.includes('better-sqlite3'),
    }));
    const codex = installs.find((i) => i.path === '/opt/codex/shieldcortex');
    expect(codex?.sources).toEqual(['codex']);
  });
});
