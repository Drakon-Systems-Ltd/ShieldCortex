/**
 * #283 — a self-declared identity may not wear a host-attested identity's name.
 *
 * The ceiling clamp (#273) asks "does this claim OUTSCORE the environment". A
 * DOWNGRADE does not, so on a default `cli:*` 0.9 deployment a declared
 * `hook:session-end` (0.8) was honoured verbatim, silently, with no
 * `SOURCE_ELEVATION_BLOCKED` row — and then owned the real hook's rows, because
 * `checkAccess` keys ownership on `${type}:${identifier}` string equality and
 * that string was writer-chosen.
 *
 * The question ownership needs is not "is this claim too high" but "did the
 * ENVIRONMENT confirm this identity". Where it did not, the identity keeps its
 * declared type and score and is keyed into a separate namespace.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve as resolvePath } from 'node:path';

import {
  UNATTESTED_ORIGIN,
  applyOwnershipStamp,
  isUnattestedIdentifier,
  isUnattestedSourceKey,
  stampUnattestedIdentifier,
  stripUnattestedStamp,
} from '../trust/attestation-stamp.js';
import { resolveToolSource, deriveEnvConfirmed } from '../trust/resolve-tool-source.js';
import { checkAccess } from '../trust/access-control.js';
import { scoreSource } from '../trust/source-scorer.js';
import { scoreAgent, getAgentDepth, buildAgentHierarchy } from '../trust/agent-scorer.js';
import type { DefenceSource } from '../types.js';

const ENV_KEYS = [
  'CLAUDE_CODE_ENTRYPOINT',
  'CLAUDE_AGENT_CONTEXT',
  'CODEX_THREAD_ID',
  'CODEX_CI',
  'CODEX_INTERNAL_ORIGINATOR_OVERRIDE',
  'SHIELDCORTEX_AGENT_SOURCE',
  'SHIELDCORTEX_STRICT_SOURCE',
];

/** The four env shapes that give a default deployment a `cli:*` 0.9 ceiling. */
const CLI_HOSTS: Array<[string, Record<string, string>]> = [
  ['CLAUDE_CODE_ENTRYPOINT=cli', { CLAUDE_CODE_ENTRYPOINT: 'cli' }],
  ['CLAUDE_CODE_ENTRYPOINT=vscode', { CLAUDE_CODE_ENTRYPOINT: 'vscode' }],
  ['CODEX_THREAD_ID=t1', { CODEX_THREAD_ID: 't1' }],
  [
    'CODEX_INTERNAL_ORIGINATOR_OVERRIDE=codex_vscode',
    { CODEX_INTERNAL_ORIGINATOR_OVERRIDE: 'codex_vscode' },
  ],
];

/** Below-ceiling declarations: none of these is an over-claim under `cli:*` 0.9. */
const BELOW_CEILING: Array<[DefenceSource, number]> = [
  [{ type: 'hook', identifier: 'session-end' }, 0.8],
  [{ type: 'api', identifier: 'ingest' }, 0.7],
  [{ type: 'file', identifier: 'notes' }, 0.6],
  [{ type: 'agent', identifier: 'browser' }, 0.3],
];

let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  savedEnv = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  for (const k of ENV_KEYS) delete process.env[k];
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
});

describe('#283 ownership stamp — primitives', () => {
  it('is idempotent, so a caller cannot escape stamping by pre-stamping itself', () => {
    const once = stampUnattestedIdentifier('session-end');
    expect(once).toBe(`${UNATTESTED_ORIGIN}>session-end`);
    expect(stampUnattestedIdentifier(once)).toBe(once);
    expect(stampUnattestedIdentifier(stampUnattestedIdentifier(once))).toBe(once);
  });

  it('round-trips: strip undoes stamp, and strip is a no-op on bare identifiers', () => {
    expect(stripUnattestedStamp(stampUnattestedIdentifier('a>b'))).toBe('a>b');
    expect(stripUnattestedStamp('a>b')).toBe('a>b');
    expect(isUnattestedIdentifier('a>b')).toBe(false);
  });

  it('cannot collide with a host-attested key: an attested identifier is never stamped', () => {
    // The stamp sits at the FRONT of the identifier, and `applyOwnershipStamp`
    // is the only writer of it — so a confirmed identity can never carry it.
    const attested = applyOwnershipStamp({ type: 'hook', identifier: 'session-end' }, true);
    const declared = applyOwnershipStamp({ type: 'hook', identifier: 'session-end' }, false);
    expect(attested.identifier).toBe('session-end');
    expect(declared.identifier).toBe(`${UNATTESTED_ORIGIN}>session-end`);
    expect(`${attested.type}:${attested.identifier}`)
      .not.toBe(`${declared.type}:${declared.identifier}`);
  });

  it('returns the same object when the environment confirmed the identity', () => {
    const source: DefenceSource = { type: 'hook', identifier: 'session-end' };
    expect(applyOwnershipStamp(source, true)).toBe(source);
  });

  it('recognises a stamped STORED source string', () => {
    expect(isUnattestedSourceKey(`hook:${UNATTESTED_ORIGIN}>session-end`)).toBe(true);
    expect(isUnattestedSourceKey('hook:session-end')).toBe(false);
    expect(isUnattestedSourceKey('no-separator')).toBe(false);
  });
});

describe('#283 ownership stamp — never raises a score', () => {
  it.each(BELOW_CEILING)('keeps %j at its declared score when stamped', (declared, expected) => {
    const bare = scoreSource(declared).score;
    const stamped = scoreSource(applyOwnershipStamp(declared, false)).score;
    expect(bare).toBe(expected);
    expect(stamped).toBe(expected);
  });

  it('bars a self-declared identity from claiming a privileged agent ORIGIN', () => {
    // `env-override`/`cron`/`user-spawned` all mean "the host or the integrator's
    // environment said so". A writer-chosen string claiming to be one of them is
    // the exact claim under audit — it gets the unprivileged default instead.
    // This is the one place the stamp moves a score, and it only ever lowers it.
    for (const origin of ['env-override', 'cron', 'user-spawned']) {
      const privileged = scoreAgent(origin);
      const selfDeclared = scoreAgent(stampUnattestedIdentifier(origin));
      expect(selfDeclared).toBeLessThan(privileged);
      expect(selfDeclared).toBe(0.3);
    }
    expect(scoreAgent(stampUnattestedIdentifier('env-override>user-spawned'))).toBeLessThan(0.5);
  });

  it('does not read the stamp as a hierarchy rung', () => {
    expect(getAgentDepth(stampUnattestedIdentifier('user-spawned>task-1')))
      .toBe(getAgentDepth('user-spawned>task-1'));
    expect(scoreAgent(stampUnattestedIdentifier('agent-spawned>x')))
      .toBe(scoreAgent('agent-spawned>x'));
  });

  it('shows the stamp in the hierarchy display with the scores the ACL uses', () => {
    const lines = buildAgentHierarchy(stampUnattestedIdentifier('user-spawned>task-1'));
    expect(lines[0]).toContain(UNATTESTED_ORIGIN);
    expect(lines.join('\n')).toContain('trust=0.300');
  });
});

describe('#283 deriveEnvConfirmed', () => {
  const env: DefenceSource = { type: 'cli', identifier: 'claude-code' };

  it('confirms when nothing was declared', () => {
    expect(deriveEnvConfirmed({ declared: undefined, clamped: false, envInferred: env })).toBe(true);
  });

  it('confirms when the over-claim was clamped to the env identity', () => {
    expect(deriveEnvConfirmed({
      declared: { type: 'user', identifier: 'direct' }, clamped: true, envInferred: env,
    })).toBe(true);
  });

  it('confirms when the declaration is exactly what the environment produced', () => {
    expect(deriveEnvConfirmed({ declared: { ...env }, clamped: false, envInferred: env })).toBe(true);
  });

  it('does NOT confirm a below-ceiling declaration the environment never produced', () => {
    expect(deriveEnvConfirmed({
      declared: { type: 'hook', identifier: 'session-end' }, clamped: false, envInferred: env,
    })).toBe(false);
  });

  it('does not confuse a matching identifier under a different type', () => {
    expect(deriveEnvConfirmed({
      declared: { type: 'agent', identifier: 'claude-code' }, clamped: false, envInferred: env,
    })).toBe(false);
  });
});

describe('#283 resolveToolSource on the four cli:* 0.9 hosts', () => {
  it.each(CLI_HOSTS)('stamps every below-ceiling declaration on %s', (_label, hostEnv) => {
    for (const [declared] of BELOW_CEILING) {
      Object.assign(process.env, hostEnv);
      const r = resolveToolSource(declared, { toolName: 'recall', project: null, strict: false });
      expect(r.clamped).toBe(false); // a downgrade is not an over-claim
      expect(r.envConfirmed).toBe(false);
      expect(r.source.type).toBe(declared.type); // the declaration is still honoured
      expect(isUnattestedIdentifier(r.source.identifier)).toBe(true);
      expect(stripUnattestedStamp(r.source.identifier)).toBe(declared.identifier);
      for (const k of ENV_KEYS) delete process.env[k];
    }
  });

  it('leaves an env-confirmed identity unstamped', () => {
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource(undefined, { toolName: 'recall', project: null, strict: false });
    expect(r.envConfirmed).toBe(true);
    expect(isUnattestedIdentifier(r.source.identifier)).toBe(false);
  });

  it('stamps under strictSourceMode too — the hardened posture must not carry the hole', () => {
    // `attested` folds in strict mode; ownership deliberately does not.
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource({ type: 'hook', identifier: 'session-end' },
      { toolName: 'recall', project: null, strict: true });
    expect(r.envConfirmed).toBe(false);
    expect(isUnattestedIdentifier(r.source.identifier)).toBe(true);
  });
});

describe('#283 ACL — a declared identity owns only what it wrote itself', () => {
  it.each(CLI_HOSTS)('denies cross-identity ownership on %s', (_label, hostEnv) => {
    for (const [declared] of BELOW_CEILING) {
      Object.assign(process.env, hostEnv);
      const r = resolveToolSource(declared, { toolName: 'recall', project: null, strict: false });

      // A row written by the REAL, host-attested holder of the declared name.
      const victimKey = `${declared.type}:${declared.identifier}`;
      const victimRestricted = { id: 1, source: victimKey, sensitivity_level: 'RESTRICTED' };

      expect(checkAccess(victimRestricted, r.source, 'read').canRead).toBe(false);
      expect(checkAccess(victimRestricted, r.source, 'delete').canDelete).toBe(false);
      expect(checkAccess({ id: 2, source: victimKey }, r.source, 'revoke').canDelete).toBe(false);

      // ...but it still owns its OWN writes, keyed to the stamped identity.
      // (RESTRICTED own-read additionally needs trust ≥0.7, which is the
      // pre-existing gate and not what this issue changed — see below.)
      const ownKey = `${r.source.type}:${r.source.identifier}`;
      expect(checkAccess({ id: 3, source: ownKey, sensitivity_level: 'INTERNAL' }, r.source, 'read').canRead)
        .toBe(true);

      for (const k of ENV_KEYS) delete process.env[k];
    }
  });

  it('a stamped identity at trust ≥0.7 still reads its OWN RESTRICTED rows', () => {
    // The stamp namespaces ownership; it does not demote the identity. A
    // declared `hook:session-end` keeps 0.8 and therefore keeps owner access to
    // the rows it wrote itself — only the real hook's rows moved out of reach.
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource({ type: 'hook', identifier: 'session-end' },
      { toolName: 'recall', project: null, strict: false });
    const ownKey = `${r.source.type}:${r.source.identifier}`;
    expect(scoreSource(r.source).score).toBe(0.8);
    expect(checkAccess({ id: 1, source: ownKey, sensitivity_level: 'RESTRICTED' }, r.source, 'read').canRead)
      .toBe(true);
  });

  it('the host-attested holder still owns its own rows', () => {
    process.env.CLAUDE_CODE_ENTRYPOINT = 'cli';
    const r = resolveToolSource(undefined, { toolName: 'recall', project: null, strict: false });
    const ownKey = `${r.source.type}:${r.source.identifier}`;
    expect(checkAccess({ id: 1, source: ownKey, sensitivity_level: 'RESTRICTED' }, r.source, 'read').canRead)
      .toBe(true);
  });
});

describe('#283 destructive floor', () => {
  it('keeps hierarchy revoke off the wire: forget derives its identity from the environment', () => {
    // `forget`/revoke-by-source is the only route to cross-identity deletion, and
    // it is safe ONLY because it ignores the declared `source` param. A declared
    // `hook:session-end` scores 0.8 — enough to outrank a real 0.3 agent — so if
    // this handler ever starts honouring `args.source`, #283 becomes destructive.
    const here = dirname(fileURLToPath(import.meta.url));
    const server = readFileSync(resolvePath(here, '../../server.ts'), 'utf8');
    const forgetHandler = server.slice(server.indexOf("withKillSwitchGuard('memory_write'"));
    expect(forgetHandler).toContain('inferSourceFromEnvironment().source');
    expect(forgetHandler.slice(0, forgetHandler.indexOf('executeForget')))
      .not.toMatch(/source\s*=\s*args\.source/);
  });
});
