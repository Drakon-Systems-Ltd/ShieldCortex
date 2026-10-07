/**
 * Copy contract: what watch-only (and the enforce-when-ready shadow) still
 * stops, as described by `shieldcortex setup` and `shieldcortex guard
 * readiness`.
 *
 * What the shipped consumers do (pinned by the first describe block): the
 * #509 R4-1 self-protection floor — calls touching the guard's approval
 * store, decisions ledger, config, or a disable/advisory/uninstall seam — is
 * excluded from the `enforce:false` advisory branch and from the shadow
 * branch in the Claude Code hook, the OpenClaw interceptor and the Hermes
 * policy. So the catastrophic tier is NOT the only thing watch-only stops,
 * and the copy must not say it is.
 *
 * The floor is a classifier on the tool call: it does not stop a same-UID
 * call that reaches the same files another way (tool-action-guard.ts). So the
 * copy says calls the guard RECOGNISES, never "any call", and lists the
 * exceptions as examples ("including"), never as a closed "except" list —
 * the session-lease refusal and invalid tool input also stop calls in shadow.
 *
 * Text only: files are read and matched. Nothing here imports an application
 * module, runs the guard, a hook, setup or doctor, or reads any config. A
 * static text match is not runtime proof that anything is stopped.
 * Dependency-free (node:test) and NOT part of the Jest suite — run directly:
 *
 *   node --test scripts/docs-contract/watch-only-self-protection-copy.node-test.mjs
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const read = (...rel) => fs.readFileSync(path.join(REPO_ROOT, ...rel), 'utf8');

/** Text from `start` up to (not including) `end`. */
function between(src, start, end) {
  const a = src.indexOf(start);
  assert.ok(a > -1, `start not found: ${start}`);
  const b = src.indexOf(end, a + start.length);
  assert.ok(b > a, `end not found after start: ${end}`);
  return src.slice(a, b);
}

/** Concatenated single-quoted string literals in `src` (enough for this copy). */
function literals(src) {
  return [...src.matchAll(/'((?:[^'\\]|\\.)*)'/g)].map((m) => m[1].replace(/\\'/g, "'")).join('');
}

const SIGNALS = ['touch-approval-store', 'touch-decisions-ledger', 'touch-guard-config', 'disable-action-guard'];

describe('source: the self-protection floor is not advisory and not shadowed', () => {
  it('core guard declares the four floor signals as enforced in every posture', () => {
    const src = read('src', 'defence', 'iron-dome', 'tool-action-guard.ts');
    const list = between(src, 'export const GUARD_SELF_PROTECTION_SIGNALS', ']);');
    for (const s of SIGNALS) assert.ok(list.includes(`'${s}'`), `missing ${s}`);
    assert.match(src, /enforced in every posture and mode/);
    assert.match(src, /watch-only \(`enforce:false`\) advisory never turn it into/);
  });

  it('Claude Code hook: advisory and shadow branches both exclude selfProtected', () => {
    const src = read('scripts', 'pre-tool-hook.mjs');
    assert.match(src, /if \(shadow && !unscannedBlock && !selfProtected\)/);
    assert.match(src, /if \(!cfg\.enforce && !unscannedBlock && !selfProtected\)/);
    // Outage fallback: the floor is never advisory either.
    assert.match(src, /if \(!cfg\.enforce && !selfProtectSignal\)/);
  });

  it('OpenClaw interceptor: advisory and shadow branches both exclude selfProtected', () => {
    const src = read('plugins', 'openclaw', 'interceptor.ts');
    assert.match(src, /if \(gate\.shadow && !unscannedBlock && !selfProtected\)/);
    assert.match(src, /if \(!actionGuardCfg\.enforce && !unscannedBlock && !selfProtected\)/);
  });

  it('Hermes policy: a floor verdict blocks even when enforce is false', () => {
    const src = read('plugins', 'hermes', 'shieldcortex', 'policy.py');
    assert.match(src, /if verdict\.decision == "require_approval" and \(enforce or self_protected\):/);
  });
});

describe('setup: Watch only copy', () => {
  const src = read('src', 'setup', 'action-guard-posture.ts');
  const block = between(src, "choice: 'watch-only'", "choice: 'enforce-when-ready'");
  const body = literals(between(block, 'body:', '},'));

  it('no longer says only the catastrophic tier is ever stopped', () => {
    assert.doesNotMatch(body, /only the\s+catastrophic tier/i);
    assert.doesNotMatch(body, /is ever stopped/i);
    assert.doesNotMatch(body, /\bonly\b[^.]*\bcatastrophic\b/i);
  });

  it('names the catastrophic tier and the guard-own-files exception', () => {
    assert.match(body, /catastrophic tier/);
    assert.match(body, /calls the guard recognises as changing its own files/);
    assert.match(body, /explicitly disabling it/);
    assert.match(body, /held for your approval/);
    assert.match(body, /\bincluding\b/, 'the list must stay non-exhaustive');
  });

  it('bounds the floor to what the guard recognises, not every such call', () => {
    assert.doesNotMatch(body, /\bany call\b/i);
    assert.doesNotMatch(body, /\bevery call that changes\b/i);
    assert.match(body, /may not be caught/);
  });

  it('qualifies Hermes, which has no approval prompt', () => {
    assert.match(body, /Hermes[^.]*blocked/);
  });

  it('keeps the existing setup wording rules (no safe/protect/recommended)', () => {
    assert.doesNotMatch(body, /\bsafe(ly|ty)?\b/i);
    assert.doesNotMatch(body, /protect/i);
    assert.doesNotMatch(body, /recommended/i);
  });

  it('Enforce when ready still starts exactly like Watch only', () => {
    assert.match(src, /Starts exactly like Watch only\./);
  });
});

describe('guard readiness: posture and mode lines', () => {
  const src = read('src', 'cli', 'guard.ts');
  const posture = between(src, 'const POSTURE_TEXT', '};');
  const mode = between(src, 'const MODE_TEXT', '};');
  const line = (block, key) => {
    const m = block.match(new RegExp(`(?:'${key}'|\\b${key}):\\s*'((?:[^'\\\\]|\\\\.)*)'`));
    assert.ok(m, `no entry for ${key}`);
    return m[1].replace(/\\'/g, "'");
  };

  /** Recognition boundary and non-exhaustive exceptions, shared by every watch/shadow line. */
  const assertQualifiedExceptions = (t) => {
    assert.match(t, /ordinary dangerous ops/);
    assert.match(t, /held or blocked, including catastrophic ops/);
    assert.match(t, /calls the guard recognises as changing its own state\/config or disabling it/);
    assert.doesNotMatch(t, /\bexcept\b/, 'a closed except-list omits the lease and invalid-input floors');
    assert.doesNotMatch(t, /\bany call\b|changes to the guard's own/i);
  };

  it('watch-only posture line names the self-protection exception', () => {
    const t = line(posture, 'watch-only');
    assert.doesNotMatch(t, /\(catastrophic still blocks\)/);
    assert.match(t, /logged, not stopped/);
    assertQualifiedExceptions(t);
  });

  it('watch-only mode line names the self-protection exception', () => {
    const t = line(mode, 'watch-only');
    assert.match(t, /advisory/);
    assertQualifiedExceptions(t);
  });

  it('shadow mode line no longer says dangerous ops are categorically NOT stopped', () => {
    const t = line(mode, 'shadow');
    assert.match(t, /would-stop/);
    assertQualifiedExceptions(t);
  });

  it('enforcing and off lines are unchanged', () => {
    assert.equal(line(mode, 'enforcing'), 'ENFORCING — dangerous ops need approval or are blocked');
    assert.equal(line(mode, 'off'), 'not gating');
    assert.equal(line(posture, 'off'), 'off — tool calls are not gated');
  });
});

describe('CHANGELOG', () => {
  it('Unreleased names the watch-only copy correction', () => {
    const unreleased = between(read('CHANGELOG.md'), '## [Unreleased]', '\n## [');
    assert.match(unreleased, /Watch only[^\n]*catastrophic[^\n]*not the only/i);
    const bullet = unreleased.split('\n').find((l) => /Watch only copy/.test(l));
    assert.ok(bullet, 'no Watch only copy bullet');
    assert.match(bullet, /recognises as changing its own config/);
    assert.match(bullet, /does not promise that every route to those files is caught/);
    assert.match(bullet, /not a complete list/);
    assert.doesNotMatch(bullet, /a call that changes the guard's own/);
  });
});
