/**
 * MCP-spawn self-heal (#76).
 *
 * When Claude Code (or any GUI/launchd host) spawns the ShieldCortex MCP server
 * and the better-sqlite3 native binding is ABI-mismatched after an npm version
 * bump without a `shieldcortex repair`, the process dies before the MCP
 * handshake and the operator sees only a bare JSON-RPC `-32000` — no cause, no
 * fix, and the (false) impression that memory is lost.
 *
 * This wraps the MCP server boot so that a native-module load failure:
 *   1. triggers an automatic in-place rebuild (the same op as `repair`, scoped
 *      to the running install via `resolveSelfInstallDir`), and retries the boot
 *      once in-process; and
 *   2. if that can't heal it, dies LOUDLY — a one-line actionable error to
 *      stderr AND a breadcrumb file at ~/.shieldcortex/logs/mcp-spawn-error.log
 *      naming the exact install path and the repair command — so `-32000` is
 *      diagnosable in seconds.
 *
 * The rebuild never touches the OpenClaw gateway (no restart), so it is safe on
 * a live host: it only recompiles a native module on disk.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { isNativeModuleLoadError } from '../database/better-sqlite3-guard.js';
import {
  ensureNativeBinding,
  resolveSelfInstallDir,
  nativeBindingRemediation,
  type EnsureResult,
} from './native-binding.js';

/**
 * Thrown when the MCP server cannot start because of an unrecoverable native
 * binding failure. By the time this is thrown, a loud stderr line has already
 * been emitted and a breadcrumb written — `breadcrumbPath` points at it.
 */
export class McpSpawnError extends Error {
  readonly breadcrumbPath?: string;
  constructor(message: string, breadcrumbPath?: string) {
    super(message);
    this.name = 'McpSpawnError';
    this.breadcrumbPath = breadcrumbPath;
  }
}

export type HealStatus = 'healed-needs-restart' | 'failed';

export interface BreadcrumbInput {
  timestamp: string;
  installDir: string;
  healStatus: HealStatus;
  originalError: string;
  remediation: string;
  rebuildOutput?: string;
}

export interface McpSelfHealDeps {
  isNativeModuleLoadError: (e: unknown) => boolean;
  ensureNativeBinding: () => Promise<EnsureResult>;
  installDir: () => string;
  /** Write the breadcrumb and return the path it was written to. */
  writeBreadcrumb: (input: BreadcrumbInput) => string;
  logStderr: (msg: string) => void;
  now: () => string;
}

/** Human-readable breadcrumb body — the thing that turns `-32000` into a fix. */
export function renderBreadcrumb(input: BreadcrumbInput): string {
  const lines = [
    `[${input.timestamp}] ShieldCortex MCP server failed to start`,
    `cause: better-sqlite3 native binding could not load (ABI mismatch / missing binary)`,
    `install: ${input.installDir}`,
    input.healStatus === 'healed-needs-restart'
      ? `auto-rebuild: SUCCEEDED — the binding was rebuilt on disk, but this process could not reload it. Restart Claude Code / the OpenClaw gateway so a fresh spawn picks it up.`
      : `auto-rebuild: FAILED — an automatic rebuild did not fix it.`,
    `fix:`,
    ...input.remediation.split('\n').map((l) => `  ${l}`),
    `original error: ${input.originalError.split('\n')[0]}`,
  ];
  if (input.rebuildOutput && input.rebuildOutput.trim()) {
    const tail = input.rebuildOutput.trim().split('\n').slice(-8);
    lines.push('rebuild output (last lines):', ...tail.map((l) => `  ${l}`));
  }
  return lines.join('\n');
}

function defaultBreadcrumbPath(): string {
  return path.join(os.homedir(), '.shieldcortex', 'logs', 'mcp-spawn-error.log');
}

function defaultWriteBreadcrumb(input: BreadcrumbInput): string {
  const file = defaultBreadcrumbPath();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.appendFileSync(file, renderBreadcrumb(input) + '\n\n', 'utf-8');
  } catch {
    // Best effort — a breadcrumb we can't write must not mask the stderr line.
  }
  return file;
}

function resolveDeps(deps: Partial<McpSelfHealDeps>): McpSelfHealDeps {
  return {
    isNativeModuleLoadError: deps.isNativeModuleLoadError ?? isNativeModuleLoadError,
    ensureNativeBinding: deps.ensureNativeBinding ?? (() => ensureNativeBinding()),
    installDir: deps.installDir ?? resolveSelfInstallDir,
    writeBreadcrumb: deps.writeBreadcrumb ?? defaultWriteBreadcrumb,
    logStderr: deps.logStderr ?? ((msg) => { console.error(msg); }),
    now: deps.now ?? (() => new Date().toISOString()),
  };
}

/**
 * Run `boot()`; if it throws a native-module load failure, attempt an in-place
 * rebuild and retry once. On success returns the boot value. On any failure —
 * rebuild failed, or rebuilt-but-can't-reload-in-process — emits a loud stderr
 * line + breadcrumb and throws {@link McpSpawnError} (never a bare `-32000`).
 *
 * A non-native error from `boot()` is re-thrown unchanged: self-heal is scoped
 * strictly to the binding failure and never masks a real bug.
 */
export async function bootWithNativeSelfHeal<T>(
  boot: () => T,
  deps: Partial<McpSelfHealDeps> = {},
): Promise<T> {
  const d = resolveDeps(deps);
  try {
    return boot();
  } catch (error) {
    if (!d.isNativeModuleLoadError(error)) throw error;

    const installDir = d.installDir();
    const originalError = error instanceof Error ? error.message : String(error);
    d.logStderr(
      `[shieldcortex] database engine (better-sqlite3) failed to load at ${installDir} — attempting in-place rebuild…`,
    );

    let heal: EnsureResult;
    try {
      heal = await d.ensureNativeBinding();
    } catch (healErr) {
      heal = {
        status: 'failed',
        error: healErr instanceof Error ? healErr.message : String(healErr),
        remediation: nativeBindingRemediation(installDir),
      };
    }

    if (heal.status === 'ok' || heal.status === 'healed') {
      // The binding is fixed on disk — retry the boot once in this process.
      // Node does not cache a failed native `require`, so a fresh open can pick
      // up the freshly-built `.node`.
      try {
        const value = boot();
        d.logStderr(
          `[shieldcortex] self-heal succeeded — rebuilt better-sqlite3 at ${installDir}; MCP server continuing.`,
        );
        return value;
      } catch {
        const remediation = heal.remediation ?? nativeBindingRemediation(installDir);
        const crumb = d.writeBreadcrumb({
          timestamp: d.now(),
          installDir,
          healStatus: 'healed-needs-restart',
          originalError,
          remediation,
          rebuildOutput: heal.rebuildOutput,
        });
        const msg =
          `[shieldcortex] MCP start: rebuilt better-sqlite3 at ${installDir}, but this process can't reload it — ` +
          `restart Claude Code / the OpenClaw gateway to finish. Details: ${crumb}`;
        d.logStderr(msg);
        throw new McpSpawnError(msg, crumb);
      }
    }

    const remediation = heal.remediation ?? nativeBindingRemediation(installDir);
    const crumb = d.writeBreadcrumb({
      timestamp: d.now(),
      installDir,
      healStatus: 'failed',
      originalError,
      remediation,
      rebuildOutput: heal.rebuildOutput,
    });
    const msg =
      `[shieldcortex] MCP start FAILED: better-sqlite3 native binding could not load at ${installDir} ` +
      `and an automatic rebuild did not fix it — run \`shieldcortex repair\`. Details: ${crumb}`;
    d.logStderr(msg);
    throw new McpSpawnError(msg, crumb);
  }
}
