import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  selfHealMcpNativeBinding,
  formatMcpSpawnError,
  MCP_SPAWN_ERROR_LOG,
} from '../setup/mcp-self-heal.js';
import type { EnsureResult } from '../setup/native-binding.js';

/**
 * Issue #76: the MCP server dies with a bare JSON-RPC `-32000` when
 * better-sqlite3's native binding is ABI-mismatched (e.g. an npm version bump
 * without `shieldcortex repair`). The process spawns and dies before the MCP
 * handshake, and the operator — whose MCP server was spawned by a GUI app —
 * sees only `-32000`, no explanation.
 *
 * The fix: at MCP start, attempt the documented repair (reusing the
 * `shieldcortex repair` machinery, `ensureNativeBinding`); if it can't heal,
 * fail LOUDLY with a message naming the exact fix command + drop a breadcrumb.
 */
describe('MCP startup self-heal (#76)', () => {
  let logsDir: string;
  const installDir = '/opt/shieldcortex';

  beforeEach(() => {
    logsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-mcp-selfheal-'));
  });
  afterEach(() => {
    fs.rmSync(logsDir, { recursive: true, force: true });
  });

  const deps = (ensureResult: EnsureResult) => ({
    ensure: async () => ensureResult,
    installDir: () => installDir,
    logsDir: () => logsDir,
    now: () => '2026-07-12T00:00:00.000Z',
  });

  it('returns ok without a breadcrumb when the binding loads first try', async () => {
    const out = await selfHealMcpNativeBinding(deps({ status: 'ok' }));
    expect(out.ok).toBe(true);
    expect(out.healed).toBe(false);
    expect(fs.existsSync(path.join(logsDir, MCP_SPAWN_ERROR_LOG))).toBe(false);
  });

  it('self-heals (reusing the repair machinery) and reports healed, no breadcrumb', async () => {
    const out = await selfHealMcpNativeBinding(deps({ status: 'healed', rebuildOutput: 'built ok' }));
    expect(out.ok).toBe(true);
    expect(out.healed).toBe(true);
    expect(fs.existsSync(path.join(logsDir, MCP_SPAWN_ERROR_LOG))).toBe(false);
  });

  it('fails LOUDLY when heal is impossible: message names the exact fix command, never a bare -32000', async () => {
    const out = await selfHealMcpNativeBinding(
      deps({ status: 'failed', error: 'NODE_MODULE_VERSION mismatch', remediation: 'cd .../better-sqlite3 && npm run build-release' }),
    );
    expect(out.ok).toBe(false);
    expect(out.healed).toBe(false);
    expect(out.message).toBeDefined();
    // The whole point: a diagnosable message, not an opaque -32000.
    expect(out.message).not.toBe('-32000');
    expect(out.message).toContain('shieldcortex repair');
    expect(out.message).toContain(installDir);
  });

  it('drops a breadcrumb naming the install path and repair command on failure', async () => {
    const out = await selfHealMcpNativeBinding(
      deps({ status: 'failed', error: 'could not locate the bindings file', remediation: 'cd x && npm run build-release' }),
    );
    const crumb = path.join(logsDir, MCP_SPAWN_ERROR_LOG);
    expect(out.breadcrumbPath).toBe(crumb);
    expect(fs.existsSync(crumb)).toBe(true);
    const body = fs.readFileSync(crumb, 'utf-8');
    expect(body).toContain(installDir);
    expect(body).toContain('shieldcortex repair');
    // The underlying error is preserved for diagnosis.
    expect(body).toContain('could not locate the bindings file');
  });

  it('formatMcpSpawnError produces an actionable, non-opaque message', () => {
    const msg = formatMcpSpawnError(installDir, 'NODE_MODULE_VERSION 127 vs 108');
    expect(msg).toContain('shieldcortex repair');
    expect(msg).toContain(installDir);
    expect(msg).not.toBe('-32000');
    expect(msg.toLowerCase()).toContain('database engine');
  });
});
