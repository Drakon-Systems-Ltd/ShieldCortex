/**
 * Copy contract: what `shieldcortex config --action-guard-advisory` (watch
 * only) and `--action-guard-enforce-when-ready` (shadow) say still stops, in
 * the confirmation messages and `config --help` text of src/cloud/cli.ts.
 *
 * Companion to watch-only-self-protection-copy.node-test.mjs, which pins the
 * source facts (the #509 R4-1 self-protection floor is excluded from the
 * advisory and shadow branches) and the setup / guard readiness copy. Here the
 * same rules apply to the config CLI: catastrophic is not the only exception,
 * the floor is bounded to calls the guard RECOGNISES, and the list stays
 * non-exhaustive ("including").
 *
 * Hermes reads its own enforce setting from SHIELDCORTEX_ENFORCE
 * (plugins/hermes/shieldcortex/__init__.py) and never the shared
 * actionGuard.enforce key, so the advisory copy must not imply the config
 * switch changes Hermes.
 *
 * Text only: files are read and matched. Nothing here imports an application
 * module, runs the CLI or the guard, or reads any config. A static text match
 * is not runtime proof that anything is stopped. Dependency-free (node:test)
 * and NOT part of the Jest suite — run directly:
 *
 *   node --test scripts/docs-contract/cloud-cli-watch-only-copy.node-test.mjs
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

/** Concatenated single-quoted string literals in `src`, help-line padding collapsed. */
function literals(src) {
  return [...src.matchAll(/'((?:[^'\\]|\\.)*)'/g)]
    .map((m) => m[1].replace(/\\'/g, "'"))
    .join(' ')
    .replace(/\s+/g, ' ');
}

const SRC = read('src', 'cloud', 'cli.ts');

/** Recognition boundary and non-exhaustive exceptions. */
const assertQualifiedExceptions = (t) => {
  assert.match(t, /ordinary dangerous ops/);
  assert.match(t, /held or blocked/);
  assert.match(t, /calls the guard recognises as changing its own state\/config or disabling it/);
  assert.doesNotMatch(t, /\(catastrophic still blocks/);
  assert.doesNotMatch(t, /\bexcept\b/);
  assert.doesNotMatch(t, /\bany call\b|\bevery call\b/i);
};

describe('source: Hermes enforce is independent of the shared config switch', () => {
  it('Hermes resolves enforce from SHIELDCORTEX_ENFORCE', () => {
    const src = read('plugins', 'hermes', 'shieldcortex', '__init__.py');
    assert.match(src, /resolve_enforce\(os\.environ\.get\("SHIELDCORTEX_ENFORCE"\)\)/);
    assert.doesNotMatch(src, /actionGuard/);
  });

  it('the advisory flag still writes only enforce:false / readinessGate:false', () => {
    const block = between(SRC, "args.includes('--action-guard-advisory')", 'changed = true;');
    assert.match(block, /\{ enforce: false, readinessGate: false \}/);
  });
});

describe('config --action-guard-advisory confirmation message', () => {
  const t = literals(between(SRC, "args.includes('--action-guard-advisory')", 'changed = true;'));

  it('names catastrophic and the self-protection floor, non-exhaustively', () => {
    assertQualifiedExceptions(t);
    assert.match(t, /including catastrophic ops/);
  });

  it('does not imply the switch controls Hermes', () => {
    assert.match(t, /Hermes plugin has its own enforce setting \(SHIELDCORTEX_ENFORCE\), which this does not change/);
  });
});

describe('config --action-guard-enforce-when-ready confirmation message', () => {
  const t = literals(between(SRC, "args.includes('--action-guard-enforce-when-ready')", 'initReadinessTransitions('));

  it('scopes the shadow to ordinary dangerous ops and names the floor', () => {
    assert.doesNotMatch(t, /— dangerous ops are logged/);
    assert.match(t, /in shadow calls the guard recognises as changing its own state\/config or disabling it are still held or blocked/);
    assertQualifiedExceptions(t);
  });

  it('keeps the Hermes-ignores-the-gate qualifier', () => {
    assert.match(t, /the Hermes plugin does not implement the gate and enforces immediately/);
  });
});

describe('config --help Action Guard lines', () => {
  const help = between(SRC, "'  --action-guard-enforce-when-ready", "'  --action-guard-notify-openclaw");
  const advisory = literals(help.slice(help.indexOf("'  --action-guard-advisory")));

  it('watch-only help line names the floor and Hermes independence', () => {
    assertQualifiedExceptions(advisory);
    assert.match(advisory, /including catastrophic ops/);
    assert.match(advisory, /Hermes has its own enforce setting \(SHIELDCORTEX_ENFORCE\), which this does not change/);
  });

  it('shadow help line scopes logging to ordinary dangerous ops', () => {
    assert.match(literals(help), /Log ordinary dangerous ops \(shadow\)/);
  });
});

describe('CHANGELOG', () => {
  it('Docs (Unreleased, or the release that shipped it) names the config CLI watch-only copy correction', () => {
    // The bullet starts under [Unreleased] and moves into a versioned section at
    // release time; the contract is its wording, not which heading it sits under.
    const bullet = read('CHANGELOG.md').split('\n').find((l) => l.startsWith('- **') && /config` watch only copy/i.test(l));
    assert.ok(bullet, 'no config watch only copy bullet in CHANGELOG.md');
    assert.match(bullet, /SHIELDCORTEX_ENFORCE/);
    assert.match(bullet, /not runtime proof/);
  });
});
