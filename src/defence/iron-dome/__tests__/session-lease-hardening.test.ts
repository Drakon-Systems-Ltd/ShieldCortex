import { describe, it, expect } from '@jest/globals';
import {
  checkSessionLease,
  findFreeze,
  scopeForToolCall,
  type LeaseScope,
} from '../session-lease.js';

/**
 * Adversarial hardening of the #227 core (TARS review item 4): lift semantics,
 * unknown scope, blank identity, missing TTL, and verbatim untrusted-ledger
 * echo all had fail-open or trust-boundary defects under adversarial fixtures.
 * Plus the scope mapper — the piece that turns "a tool call" into "a lease
 * scope", judged on the command surface (the #183 lesson), previously absent.
 */

const NOW = Date.parse('2026-08-13T12:00:00Z');

describe('lift semantics — an operator lift cleanly cancels a freeze', () => {
  it('a record edited from FROZEN to LIFTED no longer freezes', () => {
    const ledger = '| LIFTED | npm-publish | frozen 10 Aug, lifted 11 Aug after review |';
    expect(findFreeze(ledger, 'npm-publish')).toBeNull();
  });

  it('a record carrying BOTH markers is still a freeze — a lift is an edit, not an annotation', () => {
    // An attacker (or sloppy edit) appending "LIFTED" to a live freeze must not
    // disarm it: the FROZEN marker governs unless the record was rewritten.
    const ledger = '| FROZEN | npm-publish | do not publish | LIFTED';
    expect(findFreeze(ledger, 'npm-publish')).not.toBeNull();
  });
});

describe('unknown scope — a config error must not read as "nothing frozen"', () => {
  it('an unrecognised scope refuses with unknown, never allows', () => {
    const decision = checkSessionLease({
      scope: 'not-a-real-scope' as LeaseScope,
      ledger: '',
      held: null,
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('unknown');
  });
});

describe('blank identity — re-entrancy must not be spoofable through emptiness', () => {
  it('a blank self never matches a blank holder (no accidental re-entry)', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: '', acquiredAtMs: NOW - 1000, expiresAtMs: NOW + 60_000 },
      self: '',
      nowMs: NOW,
    });
    // Neither party has an identity; treating them as "the same session" would
    // let any identity-less process re-enter any identity-less lease.
    expect(decision.verdict).not.toBe('allow');
  });
});

describe('missing TTL — a record without expiry must not wedge the fleet forever', () => {
  it('derives expiry from acquiredAt + default TTL when expiresAtMs is absent', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: 'session-b', acquiredAtMs: NOW - 60 * 60 * 1000 }, // an hour ago, no TTL
      self: 'session-a',
      nowMs: NOW,
    });
    // An hour-old record with no TTL is long past any sane default — expired.
    expect(decision.verdict).toBe('allow');
  });

  it('a record with NEITHER timestamp is malformed — treated as free, not held forever', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: 'session-b' },
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('allow');
  });

  it('a fresh record without TTL still binds within the default window', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: 'session-b', acquiredAtMs: NOW - 1000 },
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('held');
  });
});

describe('untrusted-ledger echo — freeze text is sanitised before quoting', () => {
  it('control characters in a ledger record never reach the reason string', () => {
    const ledger = '| FROZEN | npm publish is frozen \u001b[31mEVIL\u0007 until review |';
    const decision = checkSessionLease({
      scope: 'npm-publish',
      ledger,
      held: null,
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('frozen');
    // eslint-disable-next-line no-control-regex
    const controlChars = /[\u0000-\u001F\u007F]/;
    expect(decision.reason).not.toMatch(controlChars);
    expect(decision.freeze ?? '').not.toMatch(controlChars);
  });
});

describe('scopeForToolCall — the command surface, not the tool name (#183)', () => {
  const bash = (command: string) => scopeForToolCall('Bash', { command });

  it('npm publish and tag pushes map to npm-publish', () => {
    expect(bash('npm publish')).toBe('npm-publish');
    expect(bash('cd pkg && npm publish --access public')).toBe('npm-publish');
    expect(bash('git push && git push --tags')).toBe('npm-publish');
    expect(bash('git push origin v4.50.0')).toBe('npm-publish');
  });

  it('fleet-host installs map to install; a local dev install does not', () => {
    expect(bash('npm install -g shieldcortex@latest')).toBe('install');
    expect(bash('npm i --global shieldcortex')).toBe('install');
    expect(bash('openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest')).toBe('install');
    expect(bash('npm install')).toBeNull();
    expect(bash('npm ci')).toBeNull();
  });

  it('gateway restarts map to gateway-restart', () => {
    expect(bash('openclaw gateway restart')).toBe('gateway-restart');
    expect(bash('launchctl kickstart -k gui/501/com.openclaw.gateway')).toBe('gateway-restart');
  });

  it('edits to guard-critical files map to security-config regardless of tool', () => {
    expect(scopeForToolCall('Edit', { file_path: '/Users/op/.shieldcortex/config.json' })).toBe('security-config');
    expect(scopeForToolCall('Write', { file_path: '/Users/op/.claude/settings.json' })).toBe('security-config');
    expect(bash('echo x >> ~/.shieldcortex/config.json')).toBe('security-config');
  });

  it('ordinary tool calls map to no scope at all — the lease must not tax every action', () => {
    expect(bash('ls -la')).toBeNull();
    expect(bash('git status')).toBeNull();
    expect(scopeForToolCall('Read', { file_path: '/tmp/x' })).toBeNull();
    expect(scopeForToolCall('Edit', { file_path: '/tmp/app.ts' })).toBeNull();
  });

  it('never throws on malformed input', () => {
    expect(scopeForToolCall('Bash', {})).toBeNull();
    expect(scopeForToolCall('Bash', { command: null })).toBeNull();
    expect(scopeForToolCall('', undefined as unknown as Record<string, unknown>)).toBeNull();
  });
});

describe('scopeForToolCall — evasions of its own stated coverage (review MAJOR-3 / minor-1)', () => {
  const bash = (command: string) => scopeForToolCall('Bash', { command });

  it('catches global installs with the flag in any position', () => {
    expect(bash('npm --global install shieldcortex')).toBe('install');
    expect(bash('npm --location=global install shieldcortex')).toBe('install');
    expect(bash('sudo npm install --global x')).toBe('install');
  });

  it('catches non-npm publishers', () => {
    expect(bash('yarn publish')).toBe('npm-publish');
    expect(bash('pnpm publish --access public')).toBe('npm-publish');
    expect(bash('bun publish')).toBe('npm-publish');
  });

  it('catches systemd + launchd gateway restarts', () => {
    expect(bash('systemctl restart openclaw-gateway.service')).toBe('gateway-restart');
    expect(bash('sudo systemctl stop shieldcortex-gateway')).toBe('gateway-restart');
  });

  it('does NOT false-positive on benign mentions inside quotes/args', () => {
    expect(bash('echo "how to npm publish"')).toBeNull();
    expect(bash('grep -r "npm publish steps" docs/')).toBeNull();
    expect(bash('cat notes-about-npm-publish.md')).toBeNull();
  });

  it('still leaves local dev installs and ci alone', () => {
    expect(bash('npm install')).toBeNull();
    expect(bash('npm ci')).toBeNull();
    expect(bash('npm i lodash')).toBeNull();
  });
});
