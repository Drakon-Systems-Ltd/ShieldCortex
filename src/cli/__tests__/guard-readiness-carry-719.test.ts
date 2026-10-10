/**
 * #719 — what `shieldcortex guard readiness` and doctor say about evidence
 * carried across releases: "fresh since this policy" and "carried from
 * compatible prior policy" separately, and "evidence retained" when a release
 * did not change the policy hash.
 *
 * The summary is assembled from a throwaway audit tree; the live
 * ~/.shieldcortex is never read.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { appendFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { formatReadinessLines, type ReadinessSummary } from '../guard.js';
import { checkActionGuardReadiness } from '../doctor.js';
import {
  computeReadiness,
  initReadinessTransitions,
  readTransitionRecord,
  transitionsPathFor,
  type ReadinessPaths,
  type ReadinessPin,
} from '../../defence/iron-dome/guard-readiness.js';

const DAY = 24 * 60 * 60 * 1000;
const NOW = Date.parse('2026-10-10T20:00:00.000Z');
const CHANNEL = { configured: true, kind: 'openclaw-card', pushesNotices: true };
const V1_H: ReadinessPin = { adapter: 'openclaw-interceptor@5.5.0', policy: 'tool-action-guard:1111111111111111' };
const V2_H: ReadinessPin = { adapter: 'openclaw-interceptor@5.6.0', policy: V1_H.policy };
const V2_H_PRIME: ReadinessPin = { adapter: 'openclaw-interceptor@5.6.0', policy: 'tool-action-guard:2222222222222222' };

let root: string;
let paths: ReadinessPaths;
let seq = 0;

function writeCalls(pin: ReadinessPin, total: number): void {
  mkdirSync(paths.auditDir, { recursive: true });
  for (let i = 0; i < total; i += 1) {
    seq += 1;
    const ts = new Date(NOW - 9 * DAY + i * 60_000).toISOString();
    const r = {
      ts, auditEventId: `e${seq}`, readinessPin: pin, type: 'intercept', origin: 'openclaw-interceptor',
      tool: 'exec', severity: 'low', action: 'allow', outcome: 'allowed',
    };
    appendFileSync(join(paths.auditDir, `realtime-${ts.slice(0, 10)}.jsonl`), `${JSON.stringify(r)}\n`);
  }
}

function summary(pin: ReadinessPin): ReadinessSummary {
  // `home` points the config read at the empty temp tree: the default carry.
  const report = computeReadiness({ channel: CHANNEL, paths, home: root, now: NOW, pin, adapter: 'openclaw-interceptor' });
  const record = readTransitionRecord(transitionsPathFor(paths));
  return {
    adapter: 'openclaw-interceptor', surface: 'OpenClaw plugin', journalPath: transitionsPathFor(paths),
    posture: 'enforce-when-ready', lockOverrides: false, mode: 'shadow', channel: CHANNEL, report, state: null,
    demoted: false, record, recordUnknown: false, notInUse: false, recentTamper: null, lastPromotion: null,
  };
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'sc-readiness-719-cli-'));
  paths = {
    auditDir: join(root, 'audit'),
    statePath: join(root, 'approvals', 'guard-readiness.openclaw-interceptor.json'),
    readAuditDirs: [join(root, 'audit')],
  };
  initReadinessTransitions({ postureChanged: true, reason: 'test posture', paths, now: NOW - 60 * DAY });
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('#719 readiness output', () => {
  it('a release that kept the policy hash says "evidence retained" and counts the rows as fresh', async () => {
    writeCalls(V1_H, 40);
    const s = summary(V2_H);
    const text = formatReadinessLines(s).join('\n');
    expect(text).toMatch(/Evidence key: {2}tool-action-guard:1111111111111111 \(the policy hash/);
    expect(text).toMatch(/fresh since this policy: 40 call\(s\); carried from compatible prior policy: 0/);
    expect(text).toMatch(/evidence retained: the upgrade from openclaw-interceptor@5\.5\.0 did not change the policy hash, so 40 row\(s\)/);
    expect(text).not.toMatch(/policy changed since/);
    expect(text).not.toMatch(/Not counted/);
    const [row] = await checkActionGuardReadiness({ summary: () => s });
    expect(row!.message).toMatch(/evidence: 40 call\(s\) fresh since this policy, 0 carried from compatible prior policy; evidence retained/);
  });

  it('a policy change reports the carried share, the setting and the fresh window', async () => {
    writeCalls(V1_H, 40);
    const s = summary(V2_H_PRIME);
    const text = formatReadinessLines(s).join('\n');
    expect(text).toMatch(/fresh since this policy: 0 call\(s\); carried from compatible prior policy: 20 \(of 40, at 50%\) — fresh window ≥ 100 calls \/ ≥ 48h not met/);
    expect(text).toMatch(/policy changed since tool-action-guard:1111111111111111: its evidence is carried at 50% \(actionGuard\.readiness\.priorPolicyCarry default 0\.5\)/);
    expect(text).not.toMatch(/evidence retained/);
    const [row] = await checkActionGuardReadiness({ summary: () => s });
    expect(row!.message).toMatch(/0 call\(s\) fresh since this policy, 20 carried from compatible prior policy; policy changed since/);
  });

  it('unpinned rows are named as such in "Not counted"', () => {
    mkdirSync(paths.auditDir, { recursive: true });
    const ts = new Date(NOW - DAY).toISOString();
    appendFileSync(
      join(paths.auditDir, `realtime-${ts.slice(0, 10)}.jsonl`),
      `${JSON.stringify({ ts, auditEventId: 'u1', type: 'intercept', origin: 'openclaw-interceptor', tool: 'exec', severity: 'low', action: 'allow', outcome: 'allowed' })}\n`,
    );
    const text = formatReadinessLines(summary(V2_H)).join('\n');
    expect(text).toMatch(/Not counted: {3}1 evidence row\(s\) from another adapter or with no usable readiness pin \(1 carry no pin at all/);
  });
});
