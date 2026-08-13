import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect } from '@jest/globals';
import { describeSpawnOutcome } from '../setup/openclaw-reconcile.js';

/**
 * #248 item 3 — `defaultRunCommand` collapsed a missing binary and a timeout
 * into an identical "exit 1" fact via `r.status ?? 1`. `spawnSync` reports
 * BOTH as `status: null` with no stdout/stderr — Node distinguishes them only
 * through `result.error.code` (ENOENT / ETIMEDOUT) and `result.signal`.
 * `defaultRunCommand` itself cannot be driven through a real spawn under Jest
 * (it is guarded twice over: its own JEST_WORKER_ID check, and
 * `resolveRepairConsent`, which is unconditionally hostile under Jest by
 * design — see repair-consent.ts). So the translation logic is pulled out
 * into `describeSpawnOutcome`, a pure function tested here with the exact
 * shapes Node's spawnSync actually returns (verified against a live probe):
 *
 *   ENOENT:   { status: null, signal: null,    error: { code: 'ENOENT' } }
 *   timeout:  { status: null, signal: 'SIGTERM', error: { code: 'ETIMEDOUT' } }
 *   nonzero:  { status: N,    signal: null,    (no error) }
 */

const COMMAND = 'openclaw plugins update --pinned @drakon-systems/shieldcortex-realtime@4.48.0';

describe('#248 — describeSpawnOutcome preserves missing-binary vs timeout vs nonzero provenance', () => {
  it('reports a missing binary distinctly, not a bare exit code', () => {
    const r = describeSpawnOutcome(COMMAND, {
      status: null,
      signal: null,
      error: Object.assign(new Error('spawnSync openclaw ENOENT'), { code: 'ENOENT' }),
    });
    expect(r.status).not.toBe(0);
    expect(r.output).toMatch(/not found/i);
    expect(r.output).toContain('ENOENT');
    expect(r.output).not.toMatch(/timed out/i);
  });

  it('reports a timeout distinctly, not a bare exit code', () => {
    const r = describeSpawnOutcome(COMMAND, {
      status: null,
      signal: 'SIGTERM',
      error: Object.assign(new Error('spawnSync openclaw ETIMEDOUT'), { code: 'ETIMEDOUT' }),
    });
    expect(r.status).not.toBe(0);
    expect(r.output).toMatch(/timed out/i);
    expect(r.output).not.toMatch(/not found/i);
    expect(r.output).not.toContain('ENOENT');
  });

  it('the missing-binary and timeout reports are not the same string (the collapse this closes)', () => {
    const enoent = describeSpawnOutcome(COMMAND, {
      status: null,
      signal: null,
      error: Object.assign(new Error('spawnSync openclaw ENOENT'), { code: 'ENOENT' }),
    });
    const timeout = describeSpawnOutcome(COMMAND, {
      status: null,
      signal: 'SIGTERM',
      error: Object.assign(new Error('spawnSync openclaw ETIMEDOUT'), { code: 'ETIMEDOUT' }),
    });
    expect(enoent.output).not.toBe(timeout.output);
  });

  it('preserves an ordinary nonzero exit with its stdout/stderr, unchanged from before', () => {
    const r = describeSpawnOutcome(COMMAND, {
      status: 3,
      signal: null,
      stdout: 'Unknown command: config validate\n',
      stderr: '',
    });
    expect(r.status).toBe(3);
    expect(r.output).toContain('Unknown command: config validate');
  });

  it('reports an external kill signal distinctly when there is no spawn error', () => {
    const r = describeSpawnOutcome(COMMAND, { status: null, signal: 'SIGKILL' });
    expect(r.status).not.toBe(0);
    expect(r.output).toMatch(/SIGKILL/);
    expect(r.output).not.toMatch(/not found|timed out/i);
  });

  it('falls back to status 1 for an unrecognised spawn error code rather than mislabelling it', () => {
    const r = describeSpawnOutcome(COMMAND, {
      status: null,
      signal: null,
      error: Object.assign(new Error('spawnSync openclaw EACCES'), { code: 'EACCES' }),
    });
    expect(r.status).not.toBe(0);
    expect(r.output).toContain('EACCES');
    expect(r.output).not.toMatch(/not found|timed out/i);
  });
});

describe('#248 — defaultRunCommand is wired through the provenance-preserving translator', () => {
  it('defaultRunCommand calls describeSpawnOutcome rather than inlining `r.status ?? 1`', () => {
    const src = readFileSync(
      resolve(dirname(fileURLToPath(import.meta.url)), '..', 'setup', 'openclaw-reconcile.ts'),
      'utf-8',
    );
    const at = src.indexOf('export function defaultRunCommand');
    expect(at).toBeGreaterThanOrEqual(0);
    const body = src.slice(at, src.indexOf('\n}', at));
    expect(body).toMatch(/describeSpawnOutcome\(/);
    expect(body).not.toMatch(/status:\s*r\.status\s*\?\?\s*1/);
  });
});
