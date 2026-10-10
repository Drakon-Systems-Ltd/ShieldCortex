/**
 * #654 PAR1 — the two receipt readers must agree byte for byte on guard
 * identity: src/defence/iron-dome/session-guard.ts (OpenClaw) and
 * scripts/stop-hook.mjs (Claude Code), which cannot import each other.
 *
 * Three independent checks:
 *   1. Golden vectors (fixtures/guard-identity-vectors-654.json), computed from
 *      the canonical preimages outside the product code, pin the TS functions.
 *   2. A verbatim copy of HEAD's stop-hook `guardFingerprint` (58c3e89a) pins v1
 *      as the LEGACY formula, including the String() coercion edge (N2).
 *   3. The real hook, spawned on fixtures built from the same vectors, must list
 *      exactly the fingerprints the TS reader computes — including a non-ASCII
 *      `tool` split across the 64 KiB chunk boundary, which both readers decode
 *      per chunk (a decoder fix must land in both at once).
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import {
  guardIdentity,
  nonceFingerprint,
  recordActionGuardDegraded,
  SAFE_SUMMARY_SIGNALS,
  sessionKeyFor,
  v1Fingerprint,
} from '../defence/iron-dome/session-guard.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(__dirname, '..', '..');
const STOP_HOOK = join(REPO, 'scripts', 'stop-hook.mjs');
const SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

interface Vector {
  name: string;
  row: Record<string, unknown>;
  physKey: string;
  v1: string;
  basis: 'eventId' | 'bindingNonce' | 'physicalRow';
  primary: string;
  nonceFp?: string;
}
const VECTORS: Vector[] = JSON.parse(
  readFileSync(join(__dirname, 'fixtures', 'guard-identity-vectors-654.json'), 'utf8'),
).vectors;

// HIST1: every file that existed before a summariser run keeps its bytes as a
// prefix afterwards (EOF appends only). Returns the post-run check.
function appendOnlyCheck(root: string): () => void {
  const files: string[] = [];
  const visit = (dir: string) => {
    if (!existsSync(dir)) return;
    for (const name of readdirSync(dir)) {
      const p = join(dir, name);
      const st = lstatSync(p);
      if (st.isDirectory()) visit(p);
      else if (st.isFile() && !name.endsWith('.lock') && name !== 'memories.db') files.push(p);
    }
  };
  visit(root);
  const before = new Map(files.map((p) => [p, readFileSync(p)]));
  return () => {
    for (const [p, bytes] of before) {
      expect(readFileSync(p).subarray(0, bytes.length).equals(bytes)).toBe(true);
    }
  };
}

// ---- HEAD 58c3e89a scripts/stop-hook.mjs:308-318 and :447-458, copied verbatim.
const HEAD_SAFE_SUMMARY_SIGNALS = new Set([
  'secret-egress', 'approval-required', 'fallback-scan', 'privilege-escalation',
  'filesystem-destructive', 'destructive-filesystem', 'dangerous-shell',
  'command-exec', 'network-egress', 'credential-access', 'data-exfiltration',
  'untrusted-script', 'reviewed-script', 'shell-injection', 'persistence-risk',
]);
function headCleanSignal(value: unknown) {
  const signal = String(value ?? '').trim();
  return HEAD_SAFE_SUMMARY_SIGNALS.has(signal) ? signal : signal ? 'redacted-signal' : null;
}
function headGuardFingerprint(row: any) {
  const payload = JSON.stringify({
    sessionKey: row.sessionKey,
    action: row.action,
    outcome: row.outcome,
    tool: row.tool,
    ts: row.ts,
    auditEventId: /^[a-f0-9]{32}$/.test(String(row.auditEventId ?? '')) ? String(row.auditEventId) : row._auditLineKey,
    threats: Array.isArray(row.threats) ? row.threats.map(headCleanSignal).filter(Boolean).sort() : [],
  });
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

describe('#654 PAR1 — TS identity reproduces the golden vectors and HEAD v1', () => {
  it('covers every basis, the coercion edge, malformed IDs/nonces and undefined fields', () => {
    const names = new Set(VECTORS.map((v) => v.name));
    for (const n of ['id-string', 'nonce-only', 'id-and-nonce', 'physical', 'coerced-array-id-no-nonce',
      'coerced-array-id-with-nonce', 'undefined-tool-and-threats', 'every-allowlisted-signal']) {
      expect(names.has(n)).toBe(true);
    }
    expect(new Set(VECTORS.map((v) => v.basis))).toEqual(new Set(['eventId', 'bindingNonce', 'physicalRow']));
  });

  it.each(VECTORS.map((v) => [v.name, v] as const))('%s', (_name, v) => {
    const id = guardIdentity(v.row, v.physKey);
    expect(id.basis).toBe(v.basis);
    expect(id.primary).toBe(v.primary);
    expect(id.v1).toBe(v.v1);
    expect(v1Fingerprint(v.row, v.physKey)).toBe(v.v1);
    // v1 is HEAD's formula, byte for byte, evaluated at the same position.
    expect(v.v1).toBe(headGuardFingerprint({ ...v.row, _auditLineKey: v.physKey }));
    if (v.nonceFp) expect(nonceFingerprint(v.row)).toBe(v.nonceFp);
    // Domain separation: a nonce fingerprint is never a v1 value of the same row.
    if (v.basis === 'bindingNonce') expect(id.primary).not.toBe(id.v1);
  });

  it('the TS allow-list equals the hook\'s (copied, never imported)', () => {
    const src = readFileSync(STOP_HOOK, 'utf8');
    const m = src.match(/const SAFE_SUMMARY_SIGNALS = new Set\(\[([\s\S]*?)\]\);/);
    expect(m).not.toBeNull();
    const hookSet = new Set(m![1].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter(Boolean));
    expect(new Set(SAFE_SUMMARY_SIGNALS)).toEqual(hookSet);
    expect(new Set(SAFE_SUMMARY_SIGNALS)).toEqual(HEAD_SAFE_SUMMARY_SIGNALS);
  });
});

describe('#654 PAR1 — hook half (spawned) agrees with the TS reader', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-654-par-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function runHook(hookHome: string, session: string) {
    const appendOnly = appendOnlyCheck(join(hookHome, '.shieldcortex', 'audit'));
    const res = spawnSync(process.execPath, [STOP_HOOK], {
      input: JSON.stringify({ session_id: session }),
      encoding: 'utf8',
      env: { ...process.env, HOME: hookHome, SHIELDCORTEX_CONFIG_DIR: join(hookHome, '.shieldcortex'), SHIELDCORTEX_SESSION_SALT: SALT },
    });
    expect(res.status).toBe(0);
    appendOnly();
    const dir = join(hookHome, '.shieldcortex', 'audit');
    return readdirSync(dir).filter((f) => /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
      .flatMap((f) => readFileSync(join(dir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)))
      .filter((r) => r.origin === 'claude-code-stop-hook');
  }

  it('lists exactly the TS primaries for every vector row, at its real position (macOS-safe path string)', () => {
    const session = 'par1-hook';
    const key = sessionKeyFor(session, { salt: SALT })!;
    // physKey uses the path string the hook resolves from HOME, not realpath.
    const indexFile = join(home, '.shieldcortex', 'audit', 'session-guard', `${key}.jsonl`);
    mkdirSync(dirname(indexFile), { recursive: true });
    const rows = VECTORS.map((v) => ({ recordKind: 'guard', type: 'intercept', origin: 'openclaw-interceptor', ...v.row, sessionKey: key }));
    writeFileSync(indexFile, `${rows.map((r) => JSON.stringify(r)).join('\n')}\n`);
    const expected = rows.map((r, i) => guardIdentity(r, `${indexFile}:${i}`));
    const expectedPrimaries = [...new Set(expected.map((e) => e.primary))];

    const receipts = runHook(home, session);
    expect(receipts).toHaveLength(1);
    expect([...receipts[0].guardFingerprints].sort()).toEqual([...expectedPrimaries].sort());
    expect(receipts[0].identityBasis).toEqual({
      eventId: expected.filter((e, i) => e.basis === 'eventId' && expected.findIndex((x) => x.primary === e.primary) === i).length,
      bindingNonce: expected.filter((e, i) => e.basis === 'bindingNonce' && expected.findIndex((x) => x.primary === e.primary) === i).length,
      physicalRow: expected.filter((e, i) => e.basis === 'physicalRow' && expected.findIndex((x) => x.primary === e.primary) === i).length,
    });
  });

  it('a non-ASCII tool straddling the 64 KiB chunk boundary fingerprints identically in both readers', () => {
    const session = 'par1-utf8';
    const key = sessionKeyFor(session, { salt: SALT })!;
    const guardLine = JSON.stringify({
      recordKind: 'guard', type: 'intercept', origin: 'openclaw-interceptor', sessionKey: key,
      action: 'require_approval', outcome: 'failure_denied', tool: '€-tool', threats: [],
      ts: '2026-08-11T10:00:00.000Z', auditEventId: 'f'.repeat(32),
    });
    const euroAt = Buffer.byteLength(guardLine.slice(0, guardLine.indexOf('€')), 'utf8');
    // Put the euro's first byte at offset 65535 so its 3 bytes straddle 65536.
    const noisePrefix = '{"type":"noise","pad":"';
    const noiseSuffix = '"}';
    const padLen = 65535 - 1 - euroAt - Buffer.byteLength(noisePrefix + noiseSuffix, 'utf8');
    expect(padLen).toBeGreaterThan(0);
    const content = `${noisePrefix}${'x'.repeat(padLen)}${noiseSuffix}\n${guardLine}\n`;
    expect(Buffer.from(content, 'utf8').subarray(65535, 65538).toString('utf8')).toBe('€');

    const tsHome = mkdtempSync(join(tmpdir(), 'sc-654-par-ts-'));
    try {
      for (const h of [home, tsHome]) {
        const file = join(h, '.shieldcortex', 'audit', 'session-guard', `${key}.jsonl`);
        mkdirSync(dirname(file), { recursive: true });
        writeFileSync(file, content);
      }
      const appendOnly = appendOnlyCheck(tsHome);
      const ts = recordActionGuardDegraded(session, { home: tsHome, salt: SALT });
      appendOnly();
      expect(ts).toMatchObject({ recorded: true, count: 1 });
      const tsDir = join(tsHome, '.shieldcortex', 'audit');
      const tsReceipt = readdirSync(tsDir).filter((f) => /^realtime-/.test(f))
        .flatMap((f) => readFileSync(join(tsDir, f), 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)))
        .find((r) => r.origin === 'openclaw-session-end');
      const hookReceipt = runHook(home, session)[0];
      expect(hookReceipt.guardFingerprints).toHaveLength(1);
      expect(tsReceipt.guardFingerprints).toEqual(hookReceipt.guardFingerprints);
      // Both decode per chunk, so neither sees the intact '€-tool': parity by
      // reproduction, not by a fixed decoder (that fix is a joint follow-up).
      expect(hookReceipt.guardFingerprints[0]).not.toBe(v1Fingerprint(JSON.parse(guardLine), ''));
    } finally {
      rmSync(tsHome, { recursive: true, force: true });
    }
  });
});
