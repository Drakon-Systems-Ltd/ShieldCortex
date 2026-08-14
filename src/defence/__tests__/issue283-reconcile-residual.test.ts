/**
 * #283 reconcile residual — CASE ownership stamp is the core.
 * TARS residual closes the SHIELDCORTEX_AGENT_SOURCE env path that CASE
 * left bare for below-cap agent claims.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { resolveToolSource } from '../trust/resolve-tool-source.js';
import { inferSourceFromEnvironment } from '../trust/env-detector.js';
import { scoreSource, isUntrustedInboundSourceString } from '../trust/source-scorer.js';
import { checkAccess } from '../trust/access-control.js';
import { guardReadBySensitivity } from '../trust/read-guard.js';
import type { DefenceSource } from '../types.js';
import type { Memory } from '../../memory/types.js';

const ENV_KEYS = [
  'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_AGENT_CONTEXT',
  'CODEX_INTERNAL_ORIGINATOR_OVERRIDE', 'CODEX_THREAD_ID', 'CODEX_CI',
  'OPENAI_BASE_URL', 'CURSOR_TRACE_ID', 'AIDER_MODEL', 'CONTINUE_GLOBAL_DIR',
  'SHIELDCORTEX_AGENT_SOURCE', 'TERM_PROGRAM',
];

function clearEnv(): void {
  for (const k of ENV_KEYS) delete process.env[k];
}

beforeEach(clearEnv);
afterEach(clearEnv);

function mem(source: string, sensitivity = 'INTERNAL'): {
  id: number; source: string; sensitivity_level: string;
} {
  return { id: 1, source, sensitivity_level: sensitivity };
}

describe('#283 reconcile — CASE ownership stamp retained', () => {
  it('declared hook:session-end under cli does not own host hook RESTRICTED', () => {
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource(
      { type: 'hook', identifier: 'session-end' },
      { toolName: 'recall', project: null, strict: false },
    );
    expect(r.envConfirmed).toBe(false);
    expect(r.source.identifier.startsWith('unattested>')).toBe(true);
    expect(r.source.type).toBe('hook');
    expect(scoreSource(r.source).score).toBe(0.8); // score preserved
    expect(
      checkAccess(mem('hook:session-end', 'RESTRICTED'), r.source, 'read').canRead,
    ).toBe(false);
    expect(
      checkAccess(
        mem(`${r.source.type}:${r.source.identifier}`, 'RESTRICTED'),
        r.source,
        'read',
      ).canRead,
    ).toBe(true); // own stamped row at >=0.7
  });

  it('strict mode still stamps ownership (CASE deriveEnvConfirmed)', () => {
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource(
      { type: 'hook', identifier: 'session-end' },
      { toolName: 'recall', project: null, strict: true },
    );
    expect(r.envConfirmed).toBe(false);
    expect(r.source.identifier.startsWith('unattested>')).toBe(true);
    // attested may be true under strict for consequences — ownership uses envConfirmed
    expect(
      checkAccess(mem('hook:session-end', 'RESTRICTED'), r.source, 'read').canRead,
    ).toBe(false);
  });
});

describe('#283 reconcile — TARS env residual on CASE base', () => {
  it('SHIELDCORTEX_AGENT_SOURCE=browser → env-claim @ 0.3, no host ownership', () => {
    process.env.SHIELDCORTEX_AGENT_SOURCE = 'browser';
    const env = inferSourceFromEnvironment();
    expect(env.source).toEqual({ type: 'agent', identifier: 'env-claim>browser' });
    expect(scoreSource(env.source).score).toBe(0.3);
    expect(
      checkAccess(mem('agent:browser'), env.source, 'read').canRead,
    ).toBe(false);
  });

  it('SHIELDCORTEX_AGENT_SOURCE=agent:cron stays env-override @ 0.5 and is inbound', () => {
    process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:cron';
    const env = inferSourceFromEnvironment();
    expect(env.source.identifier.startsWith('env-override>')).toBe(true);
    expect(scoreSource(env.source).score).toBe(0.5);
    expect(isUntrustedInboundSourceString(`${env.source.type}:${env.source.identifier}`)).toBe(true);
    const row = {
      id: 1,
      trustScore: 0.5,
      sensitivityLevel: 'INTERNAL',
      source: `${env.source.type}:${env.source.identifier}`,
      content: 'x',
    } as unknown as Memory;
    expect(guardReadBySensitivity([row])).toHaveLength(0);
  });

  it('declared agent:browser under cli is unattested and does not own host', () => {
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource(
      { type: 'agent', identifier: 'browser' },
      { toolName: 'get_context', project: null, strict: false },
    );
    expect(r.source).toEqual({ type: 'agent', identifier: 'unattested>browser' });
    expect(r.envConfirmed).toBe(false);
    expect(scoreSource(r.source).score).toBe(0.3);
    expect(
      checkAccess(mem('agent:browser'), r.source, 'read').canRead,
    ).toBe(false);
  });
});
