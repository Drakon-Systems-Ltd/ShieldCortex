/**
 * #284 — Deny-path forensics.
 *
 * Four faces from live production hosts:
 * 1. signals must not collapse to redacted-signal for real guard rules
 * 2. origin present on auto_deny / critical denial rows
 * 3. action-scoped id distinct from session id
 * 4. notify status on the denial/audit path (not only stderr)
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { buildActionGuardOutcomeNotification, formatActionGuardOutcomeNotification } from '../operator-notify.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const hookPath = path.resolve(here, '../../../../scripts/pre-tool-hook.mjs');

function runHook(payload: Record<string, unknown>, home: string) {
  const res = spawnSync(process.execPath, [hookPath], {
    input: JSON.stringify(payload),
    encoding: 'utf8',
    env: { ...process.env, HOME: home, USERPROFILE: home },
    timeout: 15_000,
  });
  return res;
}

function readJsonl(file: string): Array<Record<string, unknown>> {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

describe('#284 deny-path forensics', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-284-'));
    fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
    // enforced Action Guard with no notify channel configured
    fs.writeFileSync(
      path.join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({
        actionGuard: { enabled: true, enforce: true, autoApprove: [] },
      }),
    );
  });

  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('Face 1+2+3: auto_deny row names real signal, origin, and action id', () => {
    const session = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; // 32 hex → sc- hash path may differ; pass session_id
    const res = runHook({
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
      session_id: session,
      permission_mode: 'default',
    }, home);
    expect(res.status).toBe(0);

    const denials = readJsonl(path.join(home, '.shieldcortex', 'denials.jsonl'));
    expect(denials.length).toBeGreaterThan(0);
    const row = denials[denials.length - 1];

    // Face 1 — real signal, not only redacted-signal
    expect(Array.isArray(row.signals)).toBe(true);
    expect(row.signals).toEqual(expect.arrayContaining(['recursive-force-delete']));
    expect(row.signals).not.toEqual(['redacted-signal']);

    // Face 1 wording — do not claim a sink that does not hold the command
    expect(String(row.surface)).toMatch(/redacted action surface/i);
    expect(String(row.surface)).not.toMatch(/realtime-\*\.jsonl/);
    expect(String(row.surface)).toMatch(/not persisted/i);

    // Face 2 — origin on auto_deny/critical
    expect(row.origin).toBe('claude-code-hook');
    expect(row.outcome).toBe('auto_denied');
    expect(row.severity === 'critical' || row.severity === 'catastrophic').toBe(true);

    // Face 3 — action-scoped id
    expect(String(row.actionId)).toMatch(/^act-[a-f0-9]{16}$/);
    expect(String(row.correlationId)).toMatch(/^act-[a-f0-9]{16}$/);
    // session id separate when present
    if (row.sessionId) {
      expect(String(row.sessionId)).toMatch(/^sc-[a-f0-9]{16}$/);
      expect(row.sessionId).not.toBe(row.actionId);
    }

    // Face 4 — notify status on the denial row itself
    expect(row.notify).toEqual(expect.objectContaining({
      status: expect.stringMatching(/^(not_configured|no_channel|delivered|error)$/),
    }));
  });

  it('Face 3: two denials in one session get distinct action ids', () => {
    const session = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    for (const cmd of ['rm -rf /', 'mkfs.ext4 /dev/sda']) {
      const res = runHook({
        tool_name: 'Bash',
        tool_input: { command: cmd },
        session_id: session,
        permission_mode: 'bypassPermissions',
      }, home);
      expect(res.status).toBe(0);
    }
    const denials = readJsonl(path.join(home, '.shieldcortex', 'denials.jsonl'));
    // write-first records pending+final per call (same actionId); two calls → 2 unique ids.
    expect(denials.length).toBeGreaterThanOrEqual(4);
    const ids = [...new Set(denials.map((d) => d.actionId))];
    expect(ids.length).toBe(2);
    for (const id of ids) expect(String(id)).toMatch(/^act-[a-f0-9]{16}$/);
  });


  it('Face 4 write-first: denial row exists before notify settles (pending then final)', () => {
    const res = runHook({
      tool_name: 'Bash',
      tool_input: { command: 'rm -rf /' },
      session_id: 'cccccccccccccccccccccccccccccccc',
      permission_mode: 'default',
    }, home);
    expect(res.status).toBe(0);
    const denials = readJsonl(path.join(home, '.shieldcortex', 'denials.jsonl'));
    // With no notify channel: pending + final(not_configured|no_channel)
    expect(denials.length).toBeGreaterThanOrEqual(2);
    const ids = new Set(denials.map((d) => d.actionId));
    expect(ids.size).toBe(1);
    const statuses = denials.map((d) => (d.notify as { status?: string } | undefined)?.status);
    expect(statuses).toEqual(expect.arrayContaining(['pending']));
    expect(statuses.some((s) => s && s !== 'pending')).toBe(true);
    // Every row still carries forensics faces
    for (const row of denials) {
      expect(row.origin).toBe('claude-code-hook');
      expect(row.signals).toEqual(expect.arrayContaining(['recursive-force-delete']));
    }
  });

  it('operator-notify keeps recursive-force-delete and action correlation', () => {
    const n = buildActionGuardOutcomeNotification({
      event: 'action_guard_denial',
      outcome: 'auto_denied',
      tool: 'Bash',
      signals: ['recursive-force-delete', 'totally-unknown-signal'],
      severity: 'critical',
      detectedAt: '2026-08-14T12:00:00.000Z',
      correlationId: 'act-0123456789abcdef',
      // @ts-expect-error extended fields for #284
      actionId: 'act-0123456789abcdef',
      sessionId: 'sc-0123456789abcdef',
      origin: 'claude-code-hook',
    } as any);
    expect(n.signals).toEqual(expect.arrayContaining(['recursive-force-delete', 'redacted-signal']));
    expect(n.correlationId).toBe('act-0123456789abcdef');
    const text = formatActionGuardOutcomeNotification(n as any);
    expect(text).toMatch(/recursive-force-delete/);
    expect(text).toMatch(/Origin:\s+claude-code-hook/);
    expect(text).toMatch(/Action:\s+act-0123456789abcdef/);
  });
});
