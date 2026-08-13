import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { runFreezeCommand, runUnfreezeCommand, runLeaseStatusCommand } from '../freeze.js';
import { findFreeze } from '../../defence/iron-dome/session-lease.js';

/**
 * #227 operator surface. The load-bearing properties:
 *  - freeze/unfreeze REFUSE without a TTY — no env escape hatch, because an
 *    agent must not lift (or pre-empt) a freeze that binds it;
 *  - a freeze written by the CLI is a record the enforcement parser actually
 *    matches (write and read share SCOPE_KEYWORDS — no drift);
 *  - a lift is a rewrite that keeps history, not a deletion;
 *  - the freeze output states capability coverage instead of implying
 *    fleet-wide reach it does not have.
 */

let dir: string;
let out: string[];
let err: string[];

const tty = { stdin: { isTTY: true }, stdout: { isTTY: true }, log: (l: string) => out.push(l), error: (l: string) => err.push(l) };
const noTty = { stdin: { isTTY: false }, stdout: { isTTY: false }, log: (l: string) => out.push(l), error: (l: string) => err.push(l) };

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'sc-freeze-cli-'));
  out = [];
  err = [];
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

describe('TTY gate — operator-only, no escape hatch', () => {
  it('freeze refuses without a terminal', () => {
    expect(runFreezeCommand(['npm-publish', '--reason', 'x'], { dir, streams: noTty })).toBe(1);
    expect(err.join('\n')).toMatch(/TTY/);
  });

  it('unfreeze refuses without a terminal', () => {
    expect(runUnfreezeCommand(['npm-publish'], { dir, streams: noTty })).toBe(1);
    expect(err.join('\n')).toMatch(/TTY/);
  });
});

describe('freeze → enforcement parser round-trip', () => {
  it('a CLI-written freeze is found by the same parser the planes use', () => {
    expect(runFreezeCommand(['npm-publish', '--reason', 'no publishes until the review lands'], { dir, streams: tty, user: 'michael' })).toBe(0);
    const ledger = readFileSync(join(dir, 'DECISIONS.md'), 'utf-8');
    expect(findFreeze(ledger, 'npm-publish')).not.toBeNull();
    // And it does NOT accidentally freeze unrelated scopes.
    expect(findFreeze(ledger, 'gateway-restart')).toBeNull();
  });

  it('requires a reason — a freeze without a why gets routed around', () => {
    expect(runFreezeCommand(['npm-publish'], { dir, streams: tty })).toBe(1);
  });

  it('refuses an unknown scope', () => {
    expect(runFreezeCommand(['everything', '--reason', 'x'], { dir, streams: tty })).toBe(1);
  });

  it('the freeze output states plane coverage instead of implying fleet-wide reach', () => {
    runFreezeCommand(['install', '--reason', 'hold installs'], { dir, home: dir, streams: tty });
    const text = out.join('\n');
    expect(text).toMatch(/claude-code hook/);
    expect(text).toMatch(/openclaw interceptor/);
    expect(text).toMatch(/NOT bound anywhere/);
  });
});

describe('unfreeze — a lift is a rewrite that keeps history', () => {
  it('lifts the freeze so the parser no longer matches, keeping the record', () => {
    runFreezeCommand(['npm-publish', '--reason', 'hold for review'], { dir, streams: tty, user: 'michael' });
    expect(runUnfreezeCommand(['npm-publish'], { dir, streams: tty, user: 'michael' })).toBe(0);
    const ledger = readFileSync(join(dir, 'DECISIONS.md'), 'utf-8');
    expect(findFreeze(ledger, 'npm-publish')).toBeNull();
    expect(ledger).toContain('| LIFTED |');
    expect(ledger).toContain('hold for review'); // history preserved
  });

  it('reports cleanly when nothing is frozen', () => {
    expect(runUnfreezeCommand(['npm-publish'], { dir, streams: tty })).toBe(1);
    expect(err.join('\n')).toMatch(/not frozen|nothing is frozen/i);
  });
});

describe('lease status — read-only, ungated', () => {
  it('lists freezes and reports plane coverage without a TTY', () => {
    runFreezeCommand(['npm-publish', '--reason', 'hold'], { dir, streams: tty });
    out = [];
    expect(runLeaseStatusCommand({ dir, home: dir, streams: noTty })).toBe(0);
    const text = out.join('\n');
    expect(text).toMatch(/FROZEN/);
    expect(text).toMatch(/Enforcement planes/);
  });
});

describe('unfreeze — whitespace-tolerant markers (review minor-2)', () => {
  it('lifts a hand-written double-spaced FROZEN marker, and does not falsely claim success', () => {
    // Hand-authored ledger with a non-single-space marker.
    writeFileSync(join(dir, 'DECISIONS.md'), '|  FROZEN  | npm-publish | hand written hold |\n');
    expect(runUnfreezeCommand(['npm-publish'], { dir, streams: tty, user: 'michael' })).toBe(0);
    const ledger = readFileSync(join(dir, 'DECISIONS.md'), 'utf-8');
    expect(findFreeze(ledger, 'npm-publish')).toBeNull();
    expect(ledger).toMatch(/\| LIFTED \|/);
  });
});
