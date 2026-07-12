import { describe, expect, it, jest } from '@jest/globals';
import {
  bootWithNativeSelfHeal,
  renderBreadcrumb,
  McpSpawnError,
  type BreadcrumbInput,
  type McpSelfHealDeps,
} from '../setup/mcp-self-heal.js';
import type { EnsureResult } from '../setup/native-binding.js';

/**
 * MCP-spawn self-heal (#76): a native-module load failure at MCP boot must
 * self-heal-and-retry or die LOUDLY with a breadcrumb — never a bare -32000.
 */

const NATIVE_ERR = new Error(
  'ShieldCortex could not load its database engine. Underlying error: NODE_MODULE_VERSION 115 vs 127',
);

function makeDeps(over: Partial<McpSelfHealDeps>): {
  deps: Partial<McpSelfHealDeps>;
  logs: string[];
  crumbs: BreadcrumbInput[];
} {
  const logs: string[] = [];
  const crumbs: BreadcrumbInput[] = [];
  const deps: Partial<McpSelfHealDeps> = {
    isNativeModuleLoadError: (e) => e instanceof Error && /NODE_MODULE_VERSION/.test(e.message),
    installDir: () => '/opt/shieldcortex',
    logStderr: (m) => { logs.push(m); },
    now: () => '2026-07-12T00:00:00.000Z',
    writeBreadcrumb: (input) => { crumbs.push(input); return '/home/u/.shieldcortex/logs/mcp-spawn-error.log'; },
    ...over,
  };
  return { deps, logs, crumbs };
}

describe('bootWithNativeSelfHeal', () => {
  it('returns the boot value with no heal when boot succeeds first try', async () => {
    const { deps, logs, crumbs } = makeDeps({
      ensureNativeBinding: jest.fn(async (): Promise<EnsureResult> => ({ status: 'ok' })) as never,
    });
    const value = await bootWithNativeSelfHeal(() => 'server', deps);
    expect(value).toBe('server');
    expect(deps.ensureNativeBinding).not.toHaveBeenCalled();
    expect(logs).toHaveLength(0);
    expect(crumbs).toHaveLength(0);
  });

  it('re-throws a NON-native boot error unchanged (never masks a real bug)', async () => {
    const other = new Error('table memories has no column named foo');
    const { deps } = makeDeps({});
    await expect(
      bootWithNativeSelfHeal(() => { throw other; }, deps),
    ).rejects.toBe(other);
  });

  it('heals then retries the boot, returning the value on success', async () => {
    let attempt = 0;
    const ensure = jest.fn(async (): Promise<EnsureResult> => ({ status: 'healed', rebuildOutput: 'ok' }));
    const { deps, logs, crumbs } = makeDeps({ ensureNativeBinding: ensure as never });

    const value = await bootWithNativeSelfHeal(() => {
      attempt++;
      if (attempt === 1) throw NATIVE_ERR;
      return 'server';
    }, deps);

    expect(value).toBe('server');
    expect(ensure).toHaveBeenCalledTimes(1);
    expect(attempt).toBe(2);
    expect(crumbs).toHaveLength(0);
    expect(logs.some((l) => /self-heal succeeded/.test(l))).toBe(true);
  });

  it('writes a breadcrumb + throws McpSpawnError when the rebuild fails', async () => {
    const ensure = jest.fn(async (): Promise<EnsureResult> => ({
      status: 'failed',
      error: 'still broken',
      remediation: 'cd "/opt/shieldcortex/node_modules/better-sqlite3" && npm run build-release',
    }));
    const { deps, logs, crumbs } = makeDeps({ ensureNativeBinding: ensure as never });

    const err = await bootWithNativeSelfHeal(() => { throw NATIVE_ERR; }, deps).catch((e) => e);

    expect(err).toBeInstanceOf(McpSpawnError);
    expect((err as McpSpawnError).breadcrumbPath).toMatch(/mcp-spawn-error\.log$/);
    expect(crumbs).toHaveLength(1);
    expect(crumbs[0].healStatus).toBe('failed');
    expect(crumbs[0].installDir).toBe('/opt/shieldcortex');
    expect(crumbs[0].remediation).toContain('build-release');
    // Loud, one-line, actionable — names the install and the repair command.
    expect(logs.some((l) => l.includes('/opt/shieldcortex') && /shieldcortex repair/.test(l))).toBe(true);
  });

  it('breadcrumbs "healed-needs-restart" when the rebuild worked but the process cannot reload', async () => {
    const ensure = jest.fn(async (): Promise<EnsureResult> => ({ status: 'healed' }));
    const { deps, crumbs, logs } = makeDeps({ ensureNativeBinding: ensure as never });

    // boot ALWAYS throws the native error (in-process reload impossible).
    const err = await bootWithNativeSelfHeal(() => { throw NATIVE_ERR; }, deps).catch((e) => e);

    expect(err).toBeInstanceOf(McpSpawnError);
    expect(crumbs).toHaveLength(1);
    expect(crumbs[0].healStatus).toBe('healed-needs-restart');
    expect(logs.some((l) => /restart Claude Code/.test(l))).toBe(true);
  });

  it('treats a thrown ensureNativeBinding as a failed heal (no unhandled rejection)', async () => {
    const ensure = jest.fn(async (): Promise<EnsureResult> => { throw new Error('npm exploded'); });
    const { deps, crumbs } = makeDeps({ ensureNativeBinding: ensure as never });

    const err = await bootWithNativeSelfHeal(() => { throw NATIVE_ERR; }, deps).catch((e) => e);
    expect(err).toBeInstanceOf(McpSpawnError);
    expect(crumbs[0].healStatus).toBe('failed');
    expect(crumbs[0].remediation).toContain('build-release');
  });
});

describe('renderBreadcrumb', () => {
  it('names the install path, the repair command, and the timestamp', () => {
    const body = renderBreadcrumb({
      timestamp: '2026-07-12T00:00:00.000Z',
      installDir: '/opt/shieldcortex',
      healStatus: 'failed',
      originalError: 'NODE_MODULE_VERSION 115 vs 127',
      remediation: 'cd "/opt/shieldcortex/node_modules/better-sqlite3" && npm run build-release',
    });
    expect(body).toContain('2026-07-12T00:00:00.000Z');
    expect(body).toContain('/opt/shieldcortex');
    expect(body).toContain('build-release');
    expect(body).toContain('better-sqlite3');
  });
});
