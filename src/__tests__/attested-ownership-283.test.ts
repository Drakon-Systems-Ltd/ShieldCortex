/**
 * #283 — a declared `source` is a self-applied identity.
 *
 * `resolveToolSource` only rejected a declaration that OUTSCORED the
 * environment ceiling (or tied it under a different name). Anything scoring
 * STRICTLY BELOW the ceiling was honoured verbatim — unclamped, unaudited,
 * `attested=false` — and then used as the `checkAccess` caller key, which keys
 * ownership on `${type}:${identifier}` string equality.
 *
 * On the four DEFAULT `cli:*` 0.9 deployments that gave a caller, for free:
 *
 *   declared            score  RESTRICTED own-read  own-delete  hierarchy revoke
 *   hook:session-end    0.80   YES (credential!)    YES         YES  (> 0.30)
 *   api:ingest          0.70   YES (credential!)    YES         YES  (> 0.30)
 *   file:notes          0.60   no (trust < 0.7)     YES         no
 *   agent:browser       0.30   no (trust < 0.7)     no          no
 *
 * …against rows written by the REAL holder of that name.
 *
 * The low-ceiling isolated-`HOME` case (no recognised vars → `agent:unknown`
 * 0.3) clamps these claims and looks closed. It INVERTS on the default hosts,
 * so every row below is proven on BOTH ceilings.
 *
 * Fix: `resolveToolSource` rewrites an unattested identity into the `claimed>`
 * keyspace the host never mints. One stamp, fed once, inherited by ownership,
 * delete, revoke and the inbound guards.
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { checkAccess } from '../defence/trust/access-control.js';
import { scoreSource, isUntrustedInboundType } from '../defence/trust/source-scorer.js';
import { guardReadBySensitivity } from '../defence/trust/read-guard.js';
import {
  UNATTESTED_CLAIM_MARKER,
  isUnattestedClaimIdentifier,
  stripUnattestedClaim,
} from '../defence/trust/attestation.js';
import { TYPE_SCORES } from '../defence/trust/source-scorer.js';
import type { DefenceSource } from '../defence/types.js';
import type { Memory } from '../memory/types.js';

// Audit logging needs no database here — the resolver writes a
// SOURCE_UNATTESTED_CLAIM row and we assert on it.
jest.unstable_mockModule('../defence/audit/logger.js', () => ({
  logAudit: jest.fn(() => 1),
  createContentHash: jest.fn(() => 'hash'),
}));

const { logAudit } = (await import('../defence/audit/logger.js')) as unknown as { logAudit: jest.Mock };
const { resolveToolSource } = await import('../defence/trust/resolve-tool-source.js');

const ENV_KEYS = [
  'CLAUDE_CODE_ENTRYPOINT',
  'CLAUDE_AGENT_CONTEXT',
  'CODEX_CI',
  'CODEX_INTERNAL_ORIGINATOR_OVERRIDE',
  'CODEX_THREAD_ID',
  'SHIELDCORTEX_AGENT_SOURCE',
] as const;

/** The four default deployments that infer a `cli:*` 0.9 ceiling. */
const CLI_HOSTS: ReadonlyArray<{ name: string; env: Record<string, string>; expect: string }> = [
  { name: 'Claude Code CLI', env: { CLAUDE_CODE_ENTRYPOINT: 'cli' }, expect: 'cli:mcp' },
  { name: 'Claude Code IDE', env: { CLAUDE_CODE_ENTRYPOINT: 'vscode' }, expect: 'cli:mcp' },
  { name: 'Codex CLI', env: { CODEX_THREAD_ID: 't-1' }, expect: 'cli:codex-cli' },
  {
    name: 'Codex VS Code',
    env: { CODEX_INTERNAL_ORIGINATOR_OVERRIDE: 'codex_vscode' },
    expect: 'cli:codex-vscode',
  },
];

/** Every rung that scores strictly below a 0.9 ceiling, i.e. every honoured claim. */
const RUNGS: ReadonlyArray<{ declared: DefenceSource; score: number }> = [
  { declared: { type: 'hook', identifier: 'session-end' }, score: 0.8 },
  { declared: { type: 'api', identifier: 'ingest' }, score: 0.7 },
  { declared: { type: 'file', identifier: 'notes' }, score: 0.6 },
  { declared: { type: 'agent', identifier: 'browser' }, score: 0.3 },
];

function key(s: DefenceSource): string {
  return `${s.type}:${s.identifier}`;
}

function resolve(declared: DefenceSource): DefenceSource {
  return resolveToolSource(declared, { toolName: 'recall', project: 'p', strict: false }).source;
}

function setHost(env: Record<string, string>): void {
  for (const k of ENV_KEYS) delete process.env[k];
  for (const [k, v] of Object.entries(env)) process.env[k] = v;
}

describe('#283 unattested below-ceiling claims cannot own host-attested rows', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    logAudit.mockClear();
    for (const k of ENV_KEYS) delete process.env[k];
  });
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  describe.each(CLI_HOSTS)('default host: $name', ({ env, expect: expectedCeiling }) => {
    beforeEach(() => setHost(env));

    it('infers the 0.9 cli ceiling this issue is about', () => {
      const ceiling = resolveToolSource(undefined, {
        toolName: 'recall', project: 'p', strict: false,
      });
      expect(key(ceiling.source)).toBe(expectedCeiling);
      expect(scoreSource(ceiling.source).score).toBe(0.9);
      expect(ceiling.attested).toBe(true);
      // A host-attested identity is never stamped.
      expect(isUnattestedClaimIdentifier(ceiling.source.identifier)).toBe(false);
    });

    it.each(RUNGS)(
      'stamps declared $declared.type:$declared.identifier without changing its trust',
      ({ declared, score }) => {
        const resolved = resolve(declared);

        // Stamped: type preserved (it carries the inbound decision), identifier
        // moved into the keyspace the host never mints.
        expect(resolved.type).toBe(declared.type);
        expect(resolved.identifier).toBe(`${UNATTESTED_CLAIM_MARKER}${declared.identifier}`);
        expect(key(resolved)).not.toBe(key(declared));

        // AC: the stamp must not raise (or lower) the score.
        expect(scoreSource(resolved).score).toBe(score);
        expect(scoreSource(resolved).score).toBe(scoreSource(declared).score);
        // …and specifically must not re-enter via the 0.5 `env-override>` pin.
        expect(scoreSource(resolved).score).not.toBe(0.5);
      },
    );

    it.each(RUNGS)(
      'declared $declared.type:$declared.identifier cannot own-read the host-attested row',
      ({ declared }) => {
        const caller = resolve(declared);
        const victimRestricted = { id: 1, source: key(declared), sensitivity_level: 'RESTRICTED' };
        const victimInternal = { id: 2, source: key(declared), sensitivity_level: 'INTERNAL' };

        // RESTRICTED: hook (0.8) and api (0.7) used to clear the trust floor and
        // then own-read. Now they fall through to the cross-agent denial.
        const restricted = checkAccess(victimRestricted, caller, 'read');
        expect(restricted.canRead).toBe(false);
        expect(restricted.reason).not.toMatch(/Owner/);

        // INTERNAL: every rung used to own-read at any trust. Now agent (0.3)
        // and the rest are refused ownership; only trust-tier sharing applies.
        const internal = checkAccess(victimInternal, caller, 'read');
        expect(internal.reason).not.toMatch(/Owner/);
        if (scoreSource(caller).score < 0.5) {
          expect(internal.canRead).toBe(false);
        }
      },
    );

    it.each(RUNGS)(
      'declared $declared.type:$declared.identifier cannot delete the host-attested row',
      ({ declared }) => {
        const caller = resolve(declared);
        const victim = { id: 3, source: key(declared), sensitivity_level: 'INTERNAL' };
        expect(checkAccess(victim, caller, 'delete').canDelete).toBe(false);
      },
    );

    it.each(RUNGS)(
      'declared $declared.type:$declared.identifier cannot hierarchy-revoke a lower source',
      ({ declared }) => {
        const caller = resolve(declared);
        // agent:agent-spawned scores 0.3 — outranked by hook 0.8 / api 0.7 under
        // the old trust-number-only branch.
        const target = { id: 4, source: 'agent:agent-spawned', sensitivity_level: 'INTERNAL' };
        const policy = checkAccess(target, caller, 'revoke');
        expect(policy.canDelete).toBe(false);
        expect(policy.reason).toMatch(/unattested/i);
      },
    );

    it('a stamped caller still owns, deletes and revokes ITS OWN rows', () => {
      const caller = resolve({ type: 'hook', identifier: 'session-end' });
      const ownRow = { id: 5, source: key(caller), sensitivity_level: 'RESTRICTED' };
      expect(checkAccess(ownRow, caller, 'read')).toMatchObject({ canRead: true, reason: 'Owner access' });
      expect(checkAccess(ownRow, caller, 'delete').canDelete).toBe(true);
      expect(checkAccess(ownRow, caller, 'revoke').canDelete).toBe(true);
    });

    it('an identity the environment DOES confirm is attested and left unstamped', () => {
      const [type, identifier] = expectedCeiling.split(':');
      const declared = { type, identifier } as DefenceSource;
      const resolved = resolveToolSource(declared, { toolName: 'recall', project: 'p', strict: false });
      expect(resolved.attested).toBe(true);
      expect(key(resolved.source)).toBe(expectedCeiling);

      // …and it keeps owner access to its own host-attested rows.
      const own = { id: 6, source: expectedCeiling, sensitivity_level: 'RESTRICTED' };
      expect(checkAccess(own, resolved.source, 'read')).toMatchObject({ canRead: true, reason: 'Owner access' });
    });

    it('writes a SOURCE_UNATTESTED_CLAIM audit row for the honoured-but-unconfirmed claim', () => {
      resolve({ type: 'hook', identifier: 'session-end' });
      const reasons = logAudit.mock.calls.map((c) => (c[0] as { reason: string }).reason);
      expect(reasons.some((r) => r.startsWith('SOURCE_UNATTESTED_CLAIM'))).toBe(true);
    });

    it('no writer-chosen BARE identity survives resolution at or above 0.5', () => {
      // The delete/revoke gate is `isOwner && trust >= 0.5`. Ownership is string
      // equality, so the invariant that matters is: nothing a writer chose comes
      // back as a bare `${type}:${identifier}` key that a host-attested row could
      // ever match. Sweep every declarable type, not just the four rungs.
      for (const type of Object.keys(TYPE_SCORES) as DefenceSource['type'][]) {
        const declared = { type, identifier: 'victim-name' };
        const resolved = resolve(declared);
        const bare = !isUnattestedClaimIdentifier(resolved.identifier);
        if (bare) {
          // Only an env-confirmed or clamped (host-chosen) identity may be bare.
          expect(key(resolved)).toBe(expectedCeiling);
        } else {
          expect(key(resolved)).not.toBe(key(declared));
          expect(stripUnattestedClaim(resolved.identifier)).toBe('victim-name');
        }
      }
    });
  });

  describe('low-ceiling isolated HOME (no recognised env vars)', () => {
    // The case that made this look closed: the ceiling is agent:unknown 0.3, so
    // hook/api/file OUTSCORE it and are clamped by the pre-existing #273 path.
    // agent:browser (0.3) ties the ceiling under a different name → identitySpoof.
    // Either way nothing writer-chosen survives — assert that, so a future change
    // to the clamp cannot silently reopen the rung here.
    it.each(RUNGS)('declared $declared.type:$declared.identifier never owns the victim row', ({ declared }) => {
      const caller = resolve(declared);
      const victim = { id: 7, source: key(declared), sensitivity_level: 'RESTRICTED' };
      expect(checkAccess(victim, caller, 'read').canRead).toBe(false);
      expect(checkAccess(victim, caller, 'delete').canDelete).toBe(false);
      expect(
        checkAccess({ id: 8, source: 'agent:agent-spawned', sensitivity_level: 'INTERNAL' }, caller, 'revoke').canDelete,
      ).toBe(false);
    });
  });
});

describe('#283 the stamp is disjoint from the host keyspace and inert on trust', () => {
  it('scores a stamped identity identically to the bare one, for every type', () => {
    for (const [type, score] of Object.entries(TYPE_SCORES)) {
      const bare = { type, identifier: 'x' } as DefenceSource;
      const stamped = { type, identifier: `${UNATTESTED_CLAIM_MARKER}x` } as DefenceSource;
      expect(scoreSource(stamped).score).toBe(scoreSource(bare).score);
      if (type !== 'agent') expect(scoreSource(stamped).score).toBe(score);
    }
  });

  it('does not lift file:import out of its 0.4 quarantine pin', () => {
    // The trap in a naive prefix: `file:import` is an EXACT-key override at 0.4.
    // A prefixed identifier misses that key and falls back to the `file` type
    // score 0.6 — inside the auto-quarantine band, i.e. the stamp would RAISE
    // trust. Stripping before scoring is what prevents it.
    expect(scoreSource({ type: 'file', identifier: `${UNATTESTED_CLAIM_MARKER}import` }).score).toBe(0.4);
  });

  it('does not add an agent-hierarchy decay level', () => {
    // `>` is the agent hierarchy separator, so an unstripped `claimed>` would
    // read as a spawn level: 0.3 × 0.7 = 0.21.
    expect(scoreSource({ type: 'agent', identifier: `${UNATTESTED_CLAIM_MARKER}agent-spawned` }).score).toBe(0.3);
    expect(scoreSource({ type: 'agent', identifier: 'agent-spawned' }).score).toBe(0.3);
  });

  it('is idempotent — re-declaring the stamp cannot escape or compound it', () => {
    expect(stripUnattestedClaim(`${UNATTESTED_CLAIM_MARKER}${UNATTESTED_CLAIM_MARKER}x`)).toBe('x');
    expect(scoreSource({ type: 'hook', identifier: `${UNATTESTED_CLAIM_MARKER}${UNATTESTED_CLAIM_MARKER}x` }).score)
      .toBe(0.8);
  });
});

describe('#283 `forget` stays env-inferred (pinned)', () => {
  // `checkAccess('revoke')` is the only destructive CROSS-identity branch in the
  // engine, and `forget` is the only call site that reaches it. The attestation
  // stamp makes a declared identity safe to key OWNERSHIP on, which is exactly
  // the argument someone will use to "simplify" this handler onto
  // resolveToolSource. Don't. Structural pin, not a comment.
  const serverSrc = readFileSync(
    fileURLToPath(new URL('../server.ts', import.meta.url)),
    'utf8',
  );

  /**
   * The CODE of the `forget` tool registration, up to the next `server.tool(`.
   * Line comments are stripped — the pin's own prose names the thing it forbids.
   */
  function forgetHandler(): string {
    const start = serverSrc.indexOf("server.tool(\n    'forget'");
    expect(start).toBeGreaterThan(-1);
    const end = serverSrc.indexOf('server.tool(', start + 10);
    return serverSrc
      .slice(start, end === -1 ? undefined : end)
      .split('\n')
      .filter((line) => !line.trim().startsWith('//'))
      .join('\n');
  }

  it('derives the caller identity from the environment', () => {
    expect(forgetHandler()).toMatch(/const source = inferSourceFromEnvironment\(\)\.source;/);
  });

  it('never resolves or forwards the caller-declared source', () => {
    const body = forgetHandler();
    expect(body).not.toMatch(/resolveToolSource/);
    expect(body).not.toMatch(/args\.source/);
  });
});

describe('#283 the agent inbound exemption reads the stamp, not the declared type', () => {
  const row = (source: string): Memory => ({
    id: 1,
    title: 't',
    content: 'c',
    type: 'context',
    project: 'p',
    tags: [],
    metadata: {},
    importance: 5,
    accessCount: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    source,
    sensitivityLevel: 'INTERNAL',
    trustScore: 0.5,
  } as unknown as Memory);

  it('keeps the availability carve-out for a host-attested agent row', () => {
    // Unchanged promise: a real subagent's capture still hydrates project context.
    expect(isUntrustedInboundType('agent')).toBe(false);
    expect(guardReadBySensitivity([row('agent:agent-spawned')])).toHaveLength(1);
  });

  it('drops a writer-chosen agent row from the shared-context bootstrap', () => {
    // "A capture written by agent A must not bootstrap agent B" — the half the
    // type-level exemption could never enforce, because the type is writer-chosen.
    expect(guardReadBySensitivity([row(`agent:${UNATTESTED_CLAIM_MARKER}browser`)])).toHaveLength(0);
  });

  it('still hydrates a stamped file row (the restore path stays available)', () => {
    // `file` is above the inbound floor and is NOT exempted, so the stamp must
    // not change its classification — a benign import must still bootstrap.
    expect(guardReadBySensitivity([row(`file:${UNATTESTED_CLAIM_MARKER}import`)])).toHaveLength(1);
  });

  it('does not treat a literal "claimed>" buried mid-identifier as the stamp', () => {
    expect(guardReadBySensitivity([row('agent:real>claimed>name')])).toHaveLength(1);
  });
});
