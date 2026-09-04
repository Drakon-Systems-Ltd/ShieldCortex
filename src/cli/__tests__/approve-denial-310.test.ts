/**
 * #310 — `shieldcortex approve --denial <actionId>`, the TTY half of retry
 * control.
 *
 * This is the only surface that can widen a retry grant beyond its default
 * (`--any-origin` drops the directory binding, `--override-deny` overrules the
 * operator's own earlier Deny), so the tests below are mostly about what has
 * to be TRUE before either of those happens: a real TTY, and a typed
 * confirmation that names what is being handed out.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, mkdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { runApprove } from '../approve.js';
import {
  canonicaliseCwd,
  claimCardLaunch,
  consumeRetryGrant,
  fingerprintId,
  getRetryRow,
  grantRetry,
  hashToolCall,
  isDenySuppressed,
  recordDenialFingerprint,
  recordDenySuppression,
} from '../../defence/iron-dome/retry-control.js';

const HASH = hashToolCall('Bash', { command: 'sudo modprobe softdog' });
const ACTION_ID = 'act-00000000000000ab';

describe('#310 — approve --denial', () => {
  let home: string;
  let cwd: string;
  let t0: number;

  const sink = () => {
    const lines: string[] = [];
    return { lines, write: (m: string) => { lines.push(m); }, text: () => lines.join('\n') };
  };

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-approve-denial-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    cwd = mkdtempSync(join(tmpdir(), 'sc-approve-job-'));
    t0 = 1_760_000_000_000;
  });

  afterEach(() => {
    for (const dir of [home, cwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function denial(opts: { cwd?: string | null; actionId?: string } = {}) {
    return recordDenialFingerprint(
      {
        hash: HASH,
        tool: 'Bash',
        actionId: opts.actionId ?? ACTION_ID,
        signals: ['privilege-escalation'],
        redactedSurface: 'Bash: [redacted action surface] fields=command',
        cwd: opts.cwd === undefined ? cwd : (opts.cwd ?? undefined),
      },
      { home, now: t0 },
    );
  }

  it('lists headless denials without needing a TTY — looking is not granting', () => {
    denial();
    const out = sink();
    const code = runApprove(['--denial'], {
      home, now: t0, interactive: false, log: out.write, error: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain(ACTION_ID);
    expect(out.text()).toContain('headless denials');
    expect(out.text()).toContain('shieldcortex approve --denial <actionId>');
    // Nothing was granted by looking.
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('refuses to authorise a retry when stdio is not a TTY', () => {
    denial();
    const out = sink();
    const code = runApprove(['--denial', ACTION_ID], {
      home, now: t0, interactive: false, log: out.write, error: out.write,
    });

    expect(code).toBe(1);
    expect(out.text()).toMatch(/interactive terminal/i);
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 })).toBeNull();
  });

  it('authorises exactly one scoped retry, and says so truthfully', () => {
    denial();
    const out = sink();
    const code = runApprove(['--denial', ACTION_ID, '--ttl', '20'], {
      home, now: t0, interactive: true, log: out.write, error: out.write,
    });

    expect(code).toBe(0);
    const text = out.text();
    expect(text).toContain('Authorised ONE retry');
    expect(text).toContain('Single use');
    expect(text).toContain(`Scope: ${canonicaliseCwd(cwd)}`);
    expect(text).toContain('tool Bash');
    expect(text).toContain('20 minute(s) from now');
    expect(text).toContain(new Date(t0 + 20 * 60_000).toISOString());

    const grant = getRetryRow({ hash: HASH, cwd }, { home })!.grant!;
    expect(grant.ttlMs).toBe(20 * 60_000);
    expect(grant.via).toBe('tty');
    // Exactly one: it spends, then it is gone.
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 1_000 })).not.toBeNull();
    expect(consumeRetryGrant({ hash: HASH, origin: { cwd, tool: 'Bash' } }, { home, now: t0 + 2_000 })).toBeNull();
  });

  it('does not extend a live grant on a second run', () => {
    denial();
    runApprove(['--denial', ACTION_ID], { home, now: t0, interactive: true, log: () => {}, error: () => {} });
    const out = sink();
    const code = runApprove(['--denial', ACTION_ID], {
      home, now: t0 + 60_000, interactive: true, log: out.write, error: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain('Already authorised');
    expect(out.text()).toContain('does NOT extend');
    expect(getRetryRow({ hash: HASH, cwd }, { home })!.grant!.approvedAt).toBe(t0);
  });

  it('refuses an unscopeable denial and names the flag that would accept the risk', () => {
    denial({ cwd: null });
    const out = sink();
    const code = runApprove(['--denial', ACTION_ID], {
      home, now: t0, interactive: true, log: out.write, error: out.write,
    });

    expect(code).toBe(1);
    expect(out.text()).toContain('no recorded working directory');
    expect(out.text()).toContain('--any-origin');
    expect(getRetryRow({ id: fingerprintId(HASH, undefined) }, { home })?.grant).toBeUndefined();
  });

  it('--any-origin needs a typed confirmation that names what it hands out', () => {
    denial({ cwd: null });
    const asked: string[] = [];
    const refused = sink();
    const code = runApprove(['--denial', ACTION_ID, '--any-origin'], {
      home,
      now: t0,
      interactive: true,
      log: refused.write,
      error: refused.write,
      confirm: (q) => { asked.push(q); return false; },
    });

    expect(code).toBe(1);
    expect(asked.join('\n')).toContain('ANY local process');
    expect(refused.text()).toContain('Not confirmed');
    expect(getRetryRow({ id: fingerprintId(HASH, undefined) }, { home })?.grant).toBeUndefined();

    const ok = sink();
    expect(runApprove(['--denial', ACTION_ID, '--any-origin'], {
      home, now: t0, interactive: true, log: ok.write, error: ok.write, confirm: () => true,
    })).toBe(0);
    expect(ok.text()).toContain('Scope: ANY directory');
    expect(getRetryRow({ id: fingerprintId(HASH, undefined) }, { home })!.grant!.origin.anyOrigin).toBe(true);
  });

  it('--any-origin copy says DIRECTORY only, and reports a session binding that survives it', () => {
    const sessionKey = 'hermes-task-1111';
    const boundActionId = 'act-00000000000000cd';
    recordDenialFingerprint(
      {
        hash: HASH,
        tool: 'Bash',
        actionId: boundActionId,
        signals: ['privilege-escalation'],
        redactedSurface: 'Bash: [redacted action surface] fields=command',
        cwd,
        sessionKey,
        bindSession: true,
      },
      { home, now: t0 },
    );

    const asked: string[] = [];
    const out = sink();
    const code = runApprove(['--denial', boundActionId, '--any-origin'], {
      home,
      now: t0,
      interactive: true,
      log: out.write,
      error: out.write,
      confirm: (q) => { asked.push(q); return true; },
    });

    expect(code).toBe(0);
    // The confirmation must not promise more than the store hands out.
    expect(asked.join('\n')).toContain('DIRECTORY binding');
    expect(asked.join('\n')).toContain('session-bound, and stays bound');
    // ...and neither may the success copy.
    expect(out.text()).toContain('--any-origin widens the directory only');
    expect(out.text()).toContain('still bound');

    const grant = getRetryRow({ id: fingerprintId(HASH, canonicaliseCwd(cwd), sessionKey) }, { home })!.grant!;
    expect(grant.origin.anyOrigin).toBe(true);
    expect(grant.origin.sessionKey).toBe(sessionKey);
    // The copy is honest because the predicate is: another session is refused
    // in any directory, the recorded one passes once.
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash', sessionKey: 'hermes-task-2222' } },
      { home, now: t0 + 1_000 },
    )).toBeNull();
    expect(consumeRetryGrant(
      { hash: HASH, origin: { cwd, tool: 'Bash', sessionKey } },
      { home, now: t0 + 1_100 },
    )).not.toBeNull();
  });

  it('refuses by default during a deny suppression, and names when the silence ends', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000, via: 'card' });
    const out = sink();
    const code = runApprove(['--denial', ACTION_ID], {
      home, now: t0 + 1_000, interactive: true, log: out.write, error: out.write,
    });

    expect(code).toBe(1);
    expect(out.text()).toContain('You denied this action');
    expect(out.text()).toContain(new Date(t0 + 900_000).toISOString());
    expect(out.text()).toContain('--override-deny');
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('--override-deny confirms in the operator\'s own words before overruling their Deny', () => {
    denial();
    recordDenySuppression({ hash: HASH, cwd }, { home, now: t0, suppressionMs: 900_000, via: 'card' });
    const asked: string[] = [];
    const refused = sink();
    expect(runApprove(['--denial', ACTION_ID, '--override-deny'], {
      home,
      now: t0 + 1_000,
      interactive: true,
      log: refused.write,
      error: refused.write,
      confirm: (q) => { asked.push(q); return false; },
    })).toBe(1);
    expect(asked.join('\n')).toContain('overriding your OWN deny');
    expect(asked.join('\n')).toContain(new Date(t0).toISOString());
    expect(refused.text()).toContain('the deny stands');
    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: t0 + 1_000 }).suppressed).toBe(true);

    const ok = sink();
    expect(runApprove(['--denial', ACTION_ID, '--override-deny'], {
      home, now: t0 + 2_000, interactive: true, log: ok.write, error: ok.write, confirm: () => true,
    })).toBe(0);
    expect(getRetryRow({ hash: HASH, cwd }, { home })!.grant!.via).toBe('tty');
    // The silence it overrode is lifted with it — otherwise the very retry
    // just authorised would be muted for the rest of the window.
    expect(isDenySuppressed({ hash: HASH, cwd }, { home, now: t0 + 2_000 }).suppressed).toBe(false);
  });

  it('rejects a --ttl outside the retry bounds instead of silently defaulting it', () => {
    denial();
    const out = sink();
    const code = runApprove(['--denial', ACTION_ID, '--ttl', '120'], {
      home, now: t0, interactive: true, log: out.write, error: out.write,
    });

    expect(code).toBe(1);
    expect(out.text()).toContain('--ttl for a retry must be between');
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('rejects the widening flags outside --denial rather than silently ignoring them', () => {
    const out = sink();
    expect(runApprove(['--any-origin'], { home, now: t0, interactive: true, log: out.write, error: out.write })).toBe(1);
    expect(out.text()).toContain('only apply to');
  });

  it('reports an unknown actionId instead of granting something adjacent', () => {
    denial();
    const out = sink();
    const code = runApprove(['--denial', 'act-0000000000000fff'], {
      home, now: t0, interactive: true, log: out.write, error: out.write,
    });

    expect(code).toBe(1);
    expect(out.text()).toContain('No headless denial matches');
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });

  it('sweeps unspent-expiry notices on the way past — the named non-daemon trigger', () => {
    denial();
    const claim = claimCardLaunch(
      { id: fingerprintId(HASH, canonicaliseCwd(cwd)) },
      { home, now: t0, windowStartMs: t0, windowMs: 900_000 },
    );
    expect(claim.ok).toBe(true);
    grantRetry({ hash: HASH, cwd }, { nonce: claim.ok ? claim.nonce : '' }, { home, now: t0, ttlMs: 600_000 });

    const out = sink();
    const code = runApprove([], {
      home, now: t0 + 600_001, interactive: false, log: out.write, error: out.write,
    });

    expect(code).toBe(0);
    expect(out.text()).toContain('expired UNSPENT');
    expect(out.text()).toContain('shieldcortex approve --denial');
  });

  it('leaves an install that never switched retry cards on completely untouched', () => {
    const out = sink();
    const code = runApprove([], { home, now: t0, interactive: false, log: out.write, error: out.write });
    expect(code).toBe(0);
    expect(out.text()).toContain('No pending Action Guard approvals');
    expect(out.text()).not.toContain('headless denial');
    // No store file was created just by looking.
    expect(getRetryRow({ hash: HASH, cwd }, { home })).toBeUndefined();
  });

  it('#378 bare approve points at --denial when fingerprints exist', () => {
    denial();
    const out = sink();
    const code = runApprove([], { home, now: t0, interactive: false, log: out.write, error: out.write });
    expect(code).toBe(0);
    expect(out.text()).toContain('No pending Action Guard approvals');
    expect(out.text()).toMatch(/1 headless denial/);
    expect(out.text()).toContain('shieldcortex approve --denial');
    // Looking still does not grant.
    expect(getRetryRow({ hash: HASH, cwd }, { home })?.grant).toBeUndefined();
  });
});
