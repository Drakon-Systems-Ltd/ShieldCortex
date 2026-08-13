/**
 * #224 — bind `openclaw plugins inspect --runtime --json` (or our stand-in)
 * to the config path we actually read, the gateway pid, and a timestamp.
 *
 * The raw inspect payload is forgeable in both directions via
 * OPENCLAW_CONFIG_PATH. Stamping the path, pid and time is what makes a
 * payload about a host, not about any host.
 */
import { spawnSync } from 'node:child_process';
import { homedir } from 'node:os';

import { bindRuntimeInspectPayload } from '../defence/iron-dome/enforcement-binding.js';
import { defaultConfigPath } from './openclaw-config-validate.js';
import { readRunningGatewayProcess } from './openclaw-gateway-process.js';

export function openClawConfigPathForInspect(home: string = homedir()): string {
  return defaultConfigPath(home);
}

export function buildBoundRuntimeInspect(opts: {
  raw?: unknown;
  home?: string;
  pid?: number | null;
  timestamp?: string;
} = {}): Record<string, unknown> {
  const home = opts.home ?? homedir();
  const pid = opts.pid !== undefined ? opts.pid : (readRunningGatewayProcess(home)?.pid ?? process.pid);
  return bindRuntimeInspectPayload(opts.raw ?? { source: 'shieldcortex' }, {
    configPath: openClawConfigPathForInspect(home),
    pid,
    timestamp: opts.timestamp ?? new Date().toISOString(),
  });
}

/** Best-effort: run OpenClaw's inspect if present, then bind. Never throws. */
export function collectBoundRuntimeInspect(home: string = homedir()): Record<string, unknown> {
  let raw: unknown = { source: 'shieldcortex', inspect: 'unavailable' };
  try {
    const r = spawnSync('openclaw', ['plugins', 'inspect', '--runtime', '--json'], {
      encoding: 'utf8',
      timeout: 8_000,
      env: process.env,
    });
    if (r.status === 0 && r.stdout?.trim()) {
      try { raw = JSON.parse(r.stdout); } catch { raw = { source: 'openclaw', stdout: r.stdout.slice(0, 2000) }; }
    } else if (r.stderr) {
      raw = { source: 'openclaw', error: r.stderr.slice(0, 500), status: r.status };
    }
  } catch (err) {
    raw = { source: 'shieldcortex', inspect: 'unavailable', error: err instanceof Error ? err.message : String(err) };
  }
  return buildBoundRuntimeInspect({ raw, home });
}

export function printBoundRuntimeInspect(): void {
  process.stdout.write(`${JSON.stringify(collectBoundRuntimeInspect(), null, 2)}\n`);
}
