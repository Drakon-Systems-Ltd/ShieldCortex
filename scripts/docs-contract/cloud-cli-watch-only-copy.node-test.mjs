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

/** Hermes ignores the gate, but enforcing is conditional on its own setting. */
const HERMES_QUALIFIED = /enforces immediately unless its own enforce setting \(SHIELDCORTEX_ENFORCE\) opts it out/;
const assertHermesQualified = (t) => {
  assert.match(t, HERMES_QUALIFIED);
  assert.match(t, /does not change that setting/);
  assert.doesNotMatch(t, /enforces immediately(?! unless its own enforce setting \(SHIELDCORTEX_ENFORCE\))/);
};

describe('source: Hermes enforce is independent of the shared config switch', () => {
  it('Hermes resolves enforce from SHIELDCORTEX_ENFORCE', () => {
    const src = read('plugins', 'hermes', 'shieldcortex', '__init__.py');
    assert.match(src, /resolve_enforce\(os\.environ\.get\("SHIELDCORTEX_ENFORCE"\)\)/);
    assert.doesNotMatch(src, /actionGuard/);
  });

  it('resolve_enforce is on unless an explicit opt-out word', () => {
    const src = read('plugins', 'hermes', 'shieldcortex', 'policy.py');
    assert.match(src, /_ENFORCE_OPTOUT = frozenset\(/);
    assert.match(src, /return \(value or ""\)\.strip\(\)\.lower\(\) not in _ENFORCE_OPTOUT/);
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

  it('says Hermes ignores the gate without promising it enforces regardless of SHIELDCORTEX_ENFORCE', () => {
    assert.match(t, /the Hermes plugin does not implement the gate/);
    assertHermesQualified(t);
  });
});

describe('config --help Action Guard lines', () => {
  // `config --help` text lives in the CONFIG_HELP template literal (#767 moved it
  // out of src/cloud/cli.ts); collapse the help-line padding before matching.
  const HELP_SRC = read('src', 'cli', 'dispatch-help.ts');
  const flat = (s) => s.replace(/\s+/g, ' ');
  const configHelp = between(HELP_SRC, 'export const CONFIG_HELP = `', '`;');
  const help = between(configHelp, '  --action-guard-enforce-when-ready', '  --action-guard-notify-openclaw');
  const advisory = flat(help.slice(help.indexOf('  --action-guard-advisory')));

  it('watch-only help line names the floor and Hermes independence', () => {
    assertQualifiedExceptions(advisory);
    assert.match(advisory, /including catastrophic ops/);
    assert.match(advisory, /Hermes has its own enforce setting \(SHIELDCORTEX_ENFORCE\), which this does not change/);
  });

  it('shadow help line scopes logging to ordinary dangerous ops', () => {
    assert.match(flat(help), /Log ordinary dangerous ops \(shadow\)/);
  });

  it('shadow help line qualifies Hermes by its own SHIELDCORTEX_ENFORCE setting', () => {
    const shadow = flat(help.slice(0, help.indexOf('  --action-guard-advisory')));
    assert.match(shadow, /Hermes ignores the gate/);
    assertHermesQualified(shadow);
  });
});

describe('Hermes outage fallback documentation', () => {
  // Static source/copy contract only; this does not exercise the runtime gate.
  it('source keeps self-protection and catastrophic floors, plus dangerous matches when enforcing', () => {
    const plugin = read('plugins', 'hermes', 'shieldcortex', '__init__.py');
    const policy = read('plugins', 'hermes', 'shieldcortex', 'policy.py');
    assert.match(plugin, /fallback_denies = fallback_blocked or fallback_self_protected or \(fallback_dangerous and enforce\)/);
    const actionFallback = between(policy, '    if not verdict.available:', '    if verdict.decision == "block":');
    assert.match(actionFallback, /if fallback_self_protected:/);
    assert.match(actionFallback, /return tool_call_decision\([\s\S]*enforce=enforce,[\s\S]*fallback_blocked=fallback_blocked,[\s\S]*fallback_dangerous=fallback_dangerous,/);
    const toolFallback = between(policy, '    if not verdict.available:', '    if not enforce:');
    assert.match(toolFallback, /if fallback_blocked:/);
    assert.match(toolFallback, /if fallback_dangerous and enforce:/);
  });

  for (const file of ['README.md', 'CHANGELOG.md']) {
    it(`${file} distinguishes default-enforcing and advisory outage tiers`, () => {
      const paragraph = read(file === 'README.md' ? 'docs/README-DETAILS.md' : file).split('\n').find((line) => file === 'README.md'
        ? line.startsWith('Hermes gates tool calls')
        : line.startsWith('- **README "Where it can block":'));
      assert.ok(paragraph, `no Hermes gate paragraph in ${file}`);
      assert.match(paragraph, /enforces by default/);
      assert.match(paragraph, /While the API is unreachable, its bounded fallback scan blocks the self-protection and catastrophic shapes it recognises in every mode, and recognised dangerous shapes while enforcing \(the default\)\./);
      assert.match(paragraph, /In advisory mode, only the recognised self-protection and catastrophic shapes are blocked by the fallback\./);
      assert.doesNotMatch(paragraph, /bounded fallback scan blocks only/);
    });
  }

  it('plugin README names the same outage fallback tiers as the main README', () => {
    const plugin = read('plugins', 'hermes', 'shieldcortex', 'README.md').replace(/\s+/g, ' ');
    assert.match(plugin, /While the API is unreachable, its bounded fallback scan blocks the self-protection and catastrophic shapes it recognises in every mode, and recognised dangerous shapes while enforcing \(the default\)\./);
    assert.match(plugin, /In advisory mode, only the recognised self-protection and catastrophic shapes are blocked by the fallback\./);
    assert.doesNotMatch(plugin, /still denies the unambiguous catastrophic shapes/);
  });

  it('outage log label names the deciding fallback tier', () => {
    const plugin = read('plugins', 'hermes', 'shieldcortex', '__init__.py');
    assert.match(plugin, /FALLBACK_BLOCK \(self-protection\)/);
    // Precedence mirrors policy.action_guard_decision: self-protection, then
    // catastrophic, then dangerous-while-enforcing.
    const order = [
      /if fallback_self_protected:\s+tier = "FALLBACK_BLOCK \(self-protection\)"/,
      /elif fallback_blocked:\s+tier = "FALLBACK_BLOCK \(catastrophic\)"/,
      /elif fallback_dangerous and enforce:\s+tier = "FALLBACK_BLOCK \(dangerous\)"/,
    ];
    let at = -1;
    for (const re of order) {
      const m = re.exec(plugin);
      assert.ok(m, `missing tier branch ${re}`);
      assert.ok(m.index > at, `tier branch out of order: ${re}`);
      at = m.index;
    }
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

  it('Docs (Unreleased, or the release that shipped it) names the enforce-when-ready Hermes qualification', () => {
    // Same rule as above: the bullet moves into a versioned section at release time.
    const bullet = read('CHANGELOG.md').split('\n').find((l) => l.startsWith('- **') && /enforce-when-ready` copy: Hermes/i.test(l));
    assert.ok(bullet, 'no enforce-when-ready Hermes copy bullet');
    assert.match(bullet, /SHIELDCORTEX_ENFORCE/);
    assert.match(bullet, /not runtime proof/);
  });
});
