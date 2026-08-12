/**
 * MCP-server startup self-heal for the better-sqlite3 native binding (issue #76).
 *
 * When the MCP server is spawned by a GUI app (Claude Code, VS Code, launchd)
 * and better-sqlite3's native binding is ABI-mismatched — the classic
 * "npm version bump without `shieldcortex repair`" trap — the process dies
 * before the MCP handshake and the operator sees only a bare JSON-RPC `-32000`
 * with no explanation.
 *
 * This module makes MCP startup:
 *   1. SELF-HEAL: attempt the documented repair programmatically, REUSING the
 *      `shieldcortex repair` machinery (`ensureNativeBinding`) — never a second
 *      rebuild implementation.
 *   2. FAIL LOUDLY: if the heal is impossible, produce a one-line actionable
 *      message naming the exact fix command (`shieldcortex repair`) AND drop a
 *      breadcrumb file (`~/.shieldcortex/logs/mcp-spawn-error.log`) naming the
 *      exact install path + repair command — so `-32000` is diagnosable in
 *      seconds instead of being opaque.
 *
 * Pure/injectable so both outcomes are unit-testable without a real ABI break.
 */

import fs from 'fs';
import { mkdirSecure } from './state-permissions.js';
import path from 'path';
import os from 'os';
import {
  ensureNativeBinding,
  resolveSelfInstallDir,
  type EnsureResult,
} from './native-binding.js';

/** Breadcrumb filename dropped under the logs dir on an unrecoverable failure. */
export const MCP_SPAWN_ERROR_LOG = 'mcp-spawn-error.log';

/** Injection seam so the self-heal orchestration is testable without a real
 * native failure or touching the real logs dir. */
export interface McpSelfHealDeps {
  /** The repair machinery — verify → rebuild → re-verify. */
  ensure: () => Promise<EnsureResult>;
  /** The running install's root dir (contains node_modules/better-sqlite3). */
  installDir: () => string;
  /** Where the breadcrumb is written (default ~/.shieldcortex/logs). */
  logsDir: () => string;
  /** ISO timestamp source (injectable for deterministic tests). */
  now: () => string;
}

export interface McpSelfHealOutcome {
  /** True when the binding is loadable (either it always was, or heal fixed it). */
  ok: boolean;
  /** True when a rebuild was needed and succeeded. */
  healed: boolean;
  /** Loud, actionable message — present only when `ok` is false. Names the exact
   * fix command; NEVER a bare `-32000`. */
  message?: string;
  /** Absolute path of the breadcrumb written on failure, if any. */
  breadcrumbPath?: string;
}

function defaultLogsDir(): string {
  return path.join(os.homedir(), '.shieldcortex', 'logs');
}

/**
 * Build the loud, actionable startup-failure message. Pure so it can be printed
 * to stderr AND embedded in the breadcrumb, and unit-tested directly.
 *
 * The contract: it must name the exact fix command and the install path, and it
 * must NEVER be an opaque `-32000` — that opacity is the whole bug.
 */
export function formatMcpSpawnError(installDir: string, underlying: string): string {
  return [
    'ShieldCortex MCP server failed to start: the database engine (better-sqlite3)',
    'could not be loaded and an automatic rebuild did not fix it (native-module',
    'ABI mismatch — typically an npm version bump without a repair).',
    '',
    `Install: ${installDir}`,
    '',
    'Fix it with:',
    '  shieldcortex repair',
    `  (or: cd "${path.join(installDir, 'node_modules', 'better-sqlite3')}" && npm run build-release)`,
    'Then restart the app that launches this MCP server.',
    '',
    `Underlying error: ${underlying}`,
  ].join('\n');
}

/**
 * Verify + heal the native binding for MCP startup; on unrecoverable failure,
 * write a breadcrumb and return a loud, actionable message. Never throws.
 *
 * REUSES `ensureNativeBinding` (the `shieldcortex repair` machinery) — no second
 * rebuild path. The caller (the MCP entry point) prints `message` to stderr and
 * exits non-zero when `ok` is false, so the client never just sees `-32000`.
 */
export async function selfHealMcpNativeBinding(
  deps: Partial<McpSelfHealDeps> = {},
): Promise<McpSelfHealOutcome> {
  const ensure = deps.ensure ?? ensureNativeBinding;
  const installDir = deps.installDir ?? resolveSelfInstallDir;
  const logsDir = deps.logsDir ?? defaultLogsDir;
  const now = deps.now ?? (() => new Date().toISOString());

  const result = await ensure();

  if (result.status === 'ok') return { ok: true, healed: false };
  if (result.status === 'healed') return { ok: true, healed: true };

  // status === 'failed' — heal impossible. Fail loudly.
  const dir = installDir();
  const underlying = result.error ?? 'unknown native-module load failure';
  const message = formatMcpSpawnError(dir, underlying);

  let breadcrumbPath: string | undefined;
  try {
    const target = logsDir();
    mkdirSecure(target);
    breadcrumbPath = path.join(target, MCP_SPAWN_ERROR_LOG);
    const body = [
      `[${now()}] ShieldCortex MCP server spawn failed (better-sqlite3 native-module load).`,
      message,
      result.remediation ? `\nRemediation:\n${result.remediation}` : '',
      result.rebuildOutput ? `\nRebuild output (tail):\n${result.rebuildOutput.split('\n').slice(-12).join('\n')}` : '',
      '',
    ].join('\n');
    fs.writeFileSync(breadcrumbPath, body, 'utf-8');
  } catch {
    // A breadcrumb-write failure must not mask the (already loud) message.
    breadcrumbPath = undefined;
  }

  return { ok: false, healed: false, message, breadcrumbPath };
}
