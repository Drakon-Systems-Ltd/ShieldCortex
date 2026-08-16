/**
 * #331 — DNP digest unit tests.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  DEFAULT_DNP_DIGEST_WINDOW_MS,
  formatDnpDigestText,
  normaliseDnpDigestWindowMs,
  recordDnpDigestEvent,
} from '../dnp-digest.js';

describe('normaliseDnpDigestWindowMs', () => {
  it('defaults junk to 15m', () => {
    expect(normaliseDnpDigestWindowMs(undefined)).toBe(DEFAULT_DNP_DIGEST_WINDOW_MS);
    expect(normaliseDnpDigestWindowMs('nope')).toBe(DEFAULT_DNP_DIGEST_WINDOW_MS);
    expect(normaliseDnpDigestWindowMs(-1)).toBe(DEFAULT_DNP_DIGEST_WINDOW_MS);
    expect(normaliseDnpDigestWindowMs(99)).toBe(DEFAULT_DNP_DIGEST_WINDOW_MS);
  });

  it('allows 0 to disable', () => {
    expect(normaliseDnpDigestWindowMs(0)).toBe(0);
  });

  it('honours in-range override', () => {
    expect(normaliseDnpDigestWindowMs(120_000)).toBe(120_000);
  });
});

describe('recordDnpDigestEvent', () => {
  let dir: string;
  let statePath: string;
  const t0 = 1_700_000_000_000;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-dnp-'));
    statePath = path.join(dir, 'dnp-digest.json');
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('passthrough when windowMs is 0', () => {
    const d = recordDnpDigestEvent(
      { actionId: 'act-0123456789abcdef', tool: 'Bash', signals: ['secret-egress'] },
      { statePath, windowMs: 0, nowMs: t0 },
    );
    expect(d.action).toBe('passthrough');
  });

  it('notifies on the first DNP in a window', () => {
    const d = recordDnpDigestEvent(
      {
        actionId: 'act-0123456789abcdef',
        sessionId: 'sc-0123456789abcdef',
        tool: 'Bash',
        signals: ['secret-egress', 'recursive-force-delete'],
      },
      { statePath, windowMs: 900_000, nowMs: t0 },
    );
    expect(d.action).toBe('notify');
    expect(d.summary?.count).toBe(1);
    expect(d.summary?.bySignal['secret-egress']).toBe(1);
    expect(d.summary?.lastActionIds).toEqual(['act-0123456789abcdef']);
    expect(fs.existsSync(statePath)).toBe(true);
  });

  it('coalesces later DNPs in the same window', () => {
    recordDnpDigestEvent(
      { actionId: 'act-0123456789abcdef', tool: 'Bash', signals: ['secret-egress'] },
      { statePath, windowMs: 900_000, nowMs: t0 },
    );
    const d2 = recordDnpDigestEvent(
      { actionId: 'act-1123456789abcdef', tool: 'Bash', signals: ['secret-egress'] },
      { statePath, windowMs: 900_000, nowMs: t0 + 60_000 },
    );
    expect(d2.action).toBe('coalesce');
    expect(d2.summary?.count).toBe(2);
    expect(d2.summary?.coalescedAfterNotify).toBe(true);
    expect(d2.summary?.lastActionIds).toEqual([
      'act-0123456789abcdef',
      'act-1123456789abcdef',
    ]);
  });

  it('opens a new window after windowMs elapses', () => {
    recordDnpDigestEvent(
      { actionId: 'act-0123456789abcdef', tool: 'Bash', signals: ['a'] },
      { statePath, windowMs: 60_000, nowMs: t0 },
    );
    const d2 = recordDnpDigestEvent(
      { actionId: 'act-2223456789abcdef', tool: 'Edit', signals: ['b'] },
      { statePath, windowMs: 60_000, nowMs: t0 + 60_000 },
    );
    expect(d2.action).toBe('notify');
    expect(d2.summary?.count).toBe(1);
    expect(d2.summary?.byTool.Edit).toBe(1);
  });

  it('does not let a junk actionId or permission-shaped field mute anything', () => {
    const d = recordDnpDigestEvent(
      {
        actionId: 'bypassPermissions',
        tool: 'Bash',
        signals: ['x'.repeat(200), 'secret-egress'],
      },
      { statePath, windowMs: 900_000, nowMs: t0 },
    );
    expect(d.action).toBe('notify');
    expect(d.summary?.lastActionIds).toEqual([]);
    expect(d.summary?.bySignal['secret-egress']).toBe(1);
  });
});

describe('formatDnpDigestText', () => {
  it('never includes a raw command and names the window', () => {
    const text = formatDnpDigestText({
      count: 3,
      windowMs: 900_000,
      windowStartMs: 0,
      bySignal: { 'secret-egress': 2 },
      byTool: { Bash: 3 },
      lastActionIds: ['act-0123456789abcdef'],
      lastSessionIds: [],
      coalescedAfterNotify: false,
    });
    expect(text).toMatch(/BLOCKED \(DNP digest\)/i);
    expect(text).toMatch(/3 denied_no_prompt_surface/);
    expect(text).toMatch(/15m/);
    expect(text).not.toMatch(/rm -rf/);
    expect(text).toMatch(/denials\.jsonl/);
  });
});
