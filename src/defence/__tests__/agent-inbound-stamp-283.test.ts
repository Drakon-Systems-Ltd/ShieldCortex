/**
 * #283 — agent: is a self-applied trust label; inbound stamp must come from
 * the arrival path.
 *
 * Acceptance (issue body + CASE criteria):
 * 1. Inbound bit is minted at ingestion from the arrival path, not source.type
 * 2. Stored where tool/env/declaration writers cannot overwrite it
 * 3. Three reproduction rows fail closed (or host-attested by that stamp)
 * 4. Guards that exempted `agent` read the stamp, not the self-declared type
 * 5. checkAccess ownership uses the same host-attested stamp (not bare
 *    `${type}:${identifier}` equality against a writer-chosen id)
 * 6. Unattested below-ceiling declarations cannot own host-attested rows
 *    (thread ResolvedToolSource.attested; cover four default cli:* 0.9 rows)
 * 7. No writer-chosen bare identity reaches trust 0.5 on the env path
 */
import { afterEach, describe, expect, it } from '@jest/globals';
import { checkAccess } from '../trust/access-control.js';
import { resolveToolSource, rewriteUnattestedSource, deriveAttested } from '../trust/resolve-tool-source.js';
import { inferSourceFromEnvironment, bindIntegratorOverrideSource } from '../trust/env-detector.js';
import { scoreSource, isUntrustedInboundSourceString, isUntrustedInboundType } from '../trust/source-scorer.js';
import { guardReadBySensitivity } from '../trust/read-guard.js';
import type { DefenceSource } from '../types.js';
import type { Memory } from '../../memory/types.js';

const ENV_KEYS = [
  'SHIELDCORTEX_AGENT_SOURCE',
  'CLAUDE_CODE_ENTRYPOINT',
  'CLAUDE_AGENT_CONTEXT',
  'CODEX_INTERNAL_ORIGINATOR_OVERRIDE',
  'CODEX_THREAD_ID',
  'CODEX_CI',
] as const;

const saved: Record<string, string | undefined> = {};

function clearEnv(): void {
  for (const k of ENV_KEYS) {
    saved[k] = process.env[k];
    delete process.env[k];
  }
}

function restoreEnv(): void {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
}

function mem(source: string, id = 1): { id: number; source: string; sensitivity_level: string } {
  return { id, source, sensitivity_level: 'INTERNAL' };
}

function memoryRow(source: string, id = 1): Memory {
  return {
    id,
    title: 't',
    content: 'c',
    source,
    sensitivityLevel: 'INTERNAL',
    trustScore: 0.5,
    status: 'active',
    project: null,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    metadata: {},
  } as Memory;
}

afterEach(() => {
  restoreEnv();
});

describe('#283 — env below-cap claims are stamped without raising trust', () => {
  it('SHIELDCORTEX_AGENT_SOURCE=browser → agent:env-claim>browser @ 0.3', () => {
    clearEnv();
    process.env.SHIELDCORTEX_AGENT_SOURCE = 'browser';
    const inferred = inferSourceFromEnvironment();
    expect(inferred.source).toEqual({ type: 'agent', identifier: 'env-claim>browser' });
    expect(scoreSource(inferred.source).score).toBe(0.3);
  });

  it('SHIELDCORTEX_AGENT_SOURCE=agent:browser → agent:env-claim>browser @ 0.3', () => {
    clearEnv();
    process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:browser';
    const inferred = inferSourceFromEnvironment();
    expect(inferred.source).toEqual({ type: 'agent', identifier: 'env-claim>browser' });
    expect(scoreSource(inferred.source).score).toBe(0.3);
  });

  it('at-cap agent:cron stays env-override (0.5) and does not raise', () => {
    clearEnv();
    process.env.SHIELDCORTEX_AGENT_SOURCE = 'agent:cron';
    const inferred = inferSourceFromEnvironment();
    expect(inferred.source).toEqual({ type: 'agent', identifier: 'env-override>cron' });
    expect(scoreSource(inferred.source).score).toBe(0.5);
  });

  it('no writer-chosen bare identity reaches trust 0.5 on the env path', () => {
    clearEnv();
    // Below-cap bare names
    for (const claim of ['browser', 'agent:browser', 'agent:some-agent', 'agent:agent-spawned']) {
      const bound = claim.includes(':')
        ? bindIntegratorOverrideSource(claim.split(':')[0], claim.split(':').slice(1).join(':'))
        : bindIntegratorOverrideSource('agent', claim);
      const score = scoreSource(bound).score;
      expect(score).toBeLessThan(0.5);
      // Must not collide with host-attested bare agent:browser / agent:cron keys
      expect(`${bound.type}:${bound.identifier}`).not.toMatch(/^agent:(browser|cron|agent-spawned)$/);
    }
    // At-cap is stamped env-override>, not bare
    const cron = bindIntegratorOverrideSource('agent', 'cron');
    expect(cron.identifier.startsWith('env-override>')).toBe(true);
    expect(scoreSource(cron).score).toBe(0.5);
  });
});

describe('#283 — unattested below-ceiling declarations rewrite on resolve', () => {
  const declared: DefenceSource = { type: 'agent', identifier: 'browser' };

  const highCeilings: Array<{ env: Record<string, string>; label: string }> = [
    { label: 'claude-cli', env: { CLAUDE_CODE_ENTRYPOINT: 'cli' } },
    { label: 'claude-vscode', env: { CLAUDE_CODE_ENTRYPOINT: 'vscode' } },
    { label: 'codex-cli', env: { CODEX_THREAD_ID: 'thread-1' } },
    { label: 'codex-vscode', env: { CODEX_INTERNAL_ORIGINATOR_OVERRIDE: 'codex_vscode' } },
  ];

  it.each(highCeilings)('$label: declared agent:browser rewrites + attested=false', ({ env }) => {
    clearEnv();
    Object.assign(process.env, env);
    const resolved = resolveToolSource(declared, { toolName: 'get_context', project: null, strict: false });
    expect(resolved.attested).toBe(false);
    expect(resolved.clamped).toBe(false);
    expect(resolved.source).toEqual({ type: 'agent', identifier: 'unattested>browser' });
    expect(scoreSource(resolved.source).score).toBe(0.3);
    // Must not own host-attested agent:browser
    const policy = checkAccess(
      mem('agent:browser'),
      resolved.source,
      'read',
      { attested: resolved.attested },
    );
    expect(policy.canRead).toBe(false);
    expect(policy.reason).not.toMatch(/Owner access/);
  });

  it('low-ceiling env still clamps same-score spoof (attested via clamp)', () => {
    clearEnv();
    // no recognised vars → agent:unknown 0.3; declared agent:browser 0.3 is same-score spoof
    const resolved = resolveToolSource(declared, { toolName: 'get_context', project: null, strict: false });
    expect(resolved.clamped).toBe(true);
    expect(resolved.attested).toBe(true);
    expect(resolved.source).toEqual({ type: 'agent', identifier: 'unknown' });
    expect(
      checkAccess(mem('agent:browser'), resolved.source, 'read', { attested: true }).canRead,
    ).toBe(false);
  });
});

describe('#283 — checkAccess ownership requires attestation', () => {
  const hostRow = mem('agent:browser');
  const bare: DefenceSource = { type: 'agent', identifier: 'browser' };

  it('unattested bare agent:browser does NOT own host agent:browser INTERNAL', () => {
    const policy = checkAccess(hostRow, bare, 'read', { attested: false });
    expect(policy.canRead).toBe(false);
    expect(policy.reason).toMatch(/Unattested|Insufficient trust/i);
  });

  it('attested host agent:browser DOES own its own INTERNAL row', () => {
    const policy = checkAccess(hostRow, bare, 'read', { attested: true });
    expect(policy.canRead).toBe(true);
    expect(policy.reason).toBe('Owner access');
  });

  it('rewritten env-claim identity does not own host row', () => {
    const claim: DefenceSource = { type: 'agent', identifier: 'env-claim>browser' };
    expect(scoreSource(claim).score).toBe(0.3);
    const policy = checkAccess(hostRow, claim, 'read', { attested: true });
    expect(policy.canRead).toBe(false);
  });

  it('delete/revoke stay closed at 0.3 even if string matched (attested false)', () => {
    expect(checkAccess(hostRow, bare, 'delete', { attested: false }).canDelete).toBe(false);
    expect(checkAccess(hostRow, bare, 'revoke', { attested: false }).canDelete).toBe(false);
    // Even attested at 0.3 cannot delete (need ≥0.5)
    expect(checkAccess(hostRow, bare, 'delete', { attested: true }).canDelete).toBe(false);
  });

  it('default attested=true preserves legacy host-derived callers', () => {
    expect(checkAccess(hostRow, bare, 'read').canRead).toBe(true);
  });
});

describe('#283 — inbound bootstrap reads the stamp, not type alone', () => {
  it('host-attested agent:browser stays inbound-exempt (availability)', () => {
    expect(isUntrustedInboundSourceString('agent:browser')).toBe(false);
    expect(isUntrustedInboundType('agent')).toBe(false);
  });

  it('claim-stamped agent rows are untrusted inbound', () => {
    expect(isUntrustedInboundSourceString('agent:env-claim>browser')).toBe(true);
    expect(isUntrustedInboundSourceString('agent:env-override>cron')).toBe(true);
    expect(isUntrustedInboundSourceString('agent:unattested>browser')).toBe(true);
  });

  it('guardReadBySensitivity drops stamped agent rows, keeps host agent', () => {
    const rows = [
      memoryRow('agent:browser', 1),
      memoryRow('agent:env-claim>browser', 2),
      memoryRow('agent:unattested>browser', 3),
      memoryRow('agent:env-override>cron', 4),
      memoryRow('tool_response:fetch', 5),
    ];
    const kept = guardReadBySensitivity(rows).map((m) => m.id);
    expect(kept).toEqual([1]); // only host-attested agent
  });
});

describe('#283 — pure helpers', () => {
  it('rewriteUnattestedSource is idempotent on stamps', () => {
    const a = rewriteUnattestedSource({ type: 'agent', identifier: 'browser' });
    expect(a.identifier).toBe('unattested>browser');
    expect(rewriteUnattestedSource(a)).toEqual(a);
  });

  it('rewriteUnattestedSource strips writer-supplied env-override pin', () => {
    const a = rewriteUnattestedSource({ type: 'agent', identifier: 'env-override>browser' });
    expect(a).toEqual({ type: 'agent', identifier: 'unattested>browser' });
    expect(scoreSource(a).score).toBe(0.3);
  });

  it('deriveAttested is false for unclamped below-ceiling declaration', () => {
    expect(
      deriveAttested({
        declared: { type: 'agent', identifier: 'browser' },
        resolved: { type: 'agent', identifier: 'browser' },
        clamped: false,
        strict: false,
        envInferred: { type: 'cli', identifier: 'mcp' },
      }),
    ).toBe(false);
  });
});

describe('#283 dual-review blockers', () => {
  const declared: DefenceSource = { type: 'agent', identifier: 'browser' };

  it('strict:true still rewrites unconfirmed declaration and does not own host row', () => {
    clearEnv();
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const resolved = resolveToolSource(declared, {
      toolName: 'get_context',
      project: null,
      strict: true,
    });
    expect(resolved.source).toEqual({ type: 'agent', identifier: 'unattested>browser' });
    expect(resolved.attested).toBe(false);
    expect(scoreSource(resolved.source).score).toBe(0.3);
    expect(
      checkAccess(mem('agent:browser'), resolved.source, 'read', { attested: resolved.attested }).canRead,
    ).toBe(false);
  });

  it('declared env-override> stamp cannot keep 0.5 pin under cli ceiling', () => {
    clearEnv();
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const smuggled: DefenceSource = { type: 'agent', identifier: 'env-override>browser' };
    const resolved = resolveToolSource(smuggled, {
      toolName: 'recall',
      project: null,
      strict: false,
    });
    expect(resolved.source.identifier.startsWith('unattested>')).toBe(true);
    expect(scoreSource(resolved.source).score).toBe(0.3);
    expect(resolved.attested).toBe(false);
    // Must not gain shared read via 0.5 pin
    expect(scoreSource(resolved.source).score).toBeLessThan(0.5);
  });

  it('env-confirmed declaration stays bare and attested', () => {
    clearEnv();
    process.env.CLAUDE_CODE_ENTRYPOINT = 'subagent';
    // env infers agent:agent-spawned; declare the same
    const same: DefenceSource = { type: 'agent', identifier: 'agent-spawned' };
    const resolved = resolveToolSource(same, {
      toolName: 'recall',
      project: null,
      strict: false,
    });
    expect(resolved.source).toEqual(same);
    expect(resolved.attested).toBe(true);
    expect(resolved.clamped).toBe(false);
  });
});
