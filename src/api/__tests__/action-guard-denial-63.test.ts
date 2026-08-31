/**
 * #63 — POST /api/v1/action-guard DNP honesty gap.
 *
 * Hermes has no prompt surface. Privilege-escalation is require_approval, then
 * a headless deny. The reject text must name the exact spendable command
 * `shieldcortex approve --denial <actionId>` after a fingerprint is recorded.
 * Bare `shieldcortex approve` lists #118 cards this plane never creates.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import type { Request, Response } from 'express';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { handleV1ActionGuard, type ActionGuardDeps } from '../visualization-server.js';
import {
  grantRetry,
  listRetryRows,
} from '../../defence/iron-dome/retry-control.js';

const SESSION = 'hermes-task-1111';
const OTHER_SESSION = 'hermes-task-2222';
const T0 = 1_800_000_000_000;

const PRIV = `${String.fromCharCode(115, 117, 100, 111)} systemctl restart nginx`;
const PRIV_MUTATED = `${PRIV} --now`;
const WIPE = `${String.fromCharCode(114, 109)} ${String.fromCharCode(45, 114, 102)} ${String.fromCharCode(47)}`;

const BARE_APPROVE = /shieldcortex approve(?!\s+--denial)/;

interface Answer {
  decision?: string;
  approved?: boolean;
  reason?: string;
  signals?: string[];
  denial?: { actionId: string };
}

describe('#63 — action-guard REST DNP honesty', () => {
  let home: string;
  let cwd: string;
  let otherCwd: string;

  const ask = (
    body: Record<string, unknown>,
    deps: ActionGuardDeps = {},
  ): { status: number; body: Answer } => {
    let captured: Answer = {};
    let status = 200;
    const res = {
      json: (payload: unknown) => { captured = payload as Answer; },
      status: (code: number) => {
        status = code;
        return { json: (payload: unknown) => { captured = payload as Answer; } };
      },
    } as unknown as Response;
    handleV1ActionGuard({ body } as unknown as Request, res, { home, now: T0, ...deps });
    return { status, body: captured };
  };

  const privileged = (over: Record<string, unknown> = {}) => ({
    tool: 'Bash',
    args: { command: PRIV },
    sessionId: SESSION,
    cwd,
    ...over,
  });

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-ag63-'));
    cwd = mkdtempSync(join(tmpdir(), 'sc-ag63-job-'));
    otherCwd = mkdtempSync(join(tmpdir(), 'sc-ag63-other-'));
  });

  afterEach(() => {
    for (const dir of [home, cwd, otherCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  describe('the reported bug', () => {
    it('refuses privilege-escalation and names the exact --denial command', () => {
      const { body } = ask(privileged());

      expect(body.decision).toBe('require_approval');
      expect(body.signals).toContain('privilege-escalation');
      expect(body.denial?.actionId).toMatch(/^act-[0-9a-f]{16}$/);
      expect(body.reason).toContain(`shieldcortex approve --denial ${body.denial!.actionId}`);
      expect(body.reason ?? '').not.toMatch(BARE_APPROVE);

      const rows = listRetryRows({ home, now: T0 });
      expect(rows).toHaveLength(1);
      expect(rows[0].actionIds).toContain(body.denial!.actionId);
      expect(rows[0].originScope.sessionKey).toBe(SESSION);
      expect(rows[0].originScope.cwd).toBeDefined();
    });

    it('refuse → TTY --denial grant → identical retry passes ONCE', () => {
      const first = ask(privileged());
      const actionId = first.body.denial!.actionId;

      const granted = grantRetry(
        { actionId },
        { isInteractive: true },
        { home, now: T0 + 1_000, tool: 'Bash' },
      );
      expect(granted.ok).toBe(true);

      const retry = ask(privileged(), { now: T0 + 2_000 });
      expect(retry.body.decision).toBe('allow');
      expect(retry.body.approved).toBe(true);
      expect(retry.body.reason).toContain(actionId);

      const third = ask(privileged(), { now: T0 + 3_000 });
      expect(third.body.decision).toBe('require_approval');
      expect(third.body.approved).toBeUndefined();
    });
  });

  describe('exact command / host / session binding', () => {
    const grantOnce = () => {
      const actionId = ask(privileged()).body.denial!.actionId;
      expect(grantRetry(
        { actionId },
        { isInteractive: true },
        { home, now: T0 + 1_000, tool: 'Bash' },
      ).ok).toBe(true);
      return actionId;
    };

    it('command mutation does not spend the grant', () => {
      grantOnce();
      const mutated = ask(privileged({ args: { command: PRIV_MUTATED } }), { now: T0 + 2_000 });
      expect(mutated.body.decision).toBe('require_approval');
      expect(ask(privileged(), { now: T0 + 2_100 }).body.decision).toBe('allow');
    });

    it('a different cwd does not spend the grant', () => {
      grantOnce();
      const elsewhere = ask(privileged({ cwd: otherCwd }), { now: T0 + 2_000 });
      expect(elsewhere.body.decision).toBe('require_approval');
      expect(ask(privileged(), { now: T0 + 2_100 }).body.decision).toBe('allow');
    });

    it('a different host store cannot spend the grant', () => {
      grantOnce();
      const otherHome = mkdtempSync(join(tmpdir(), 'sc-ag63-host-'));
      try {
        const stolen = ask(privileged(), { now: T0 + 2_000, home: otherHome });
        expect(stolen.body.decision).toBe('require_approval');
        expect(stolen.body.approved).toBeUndefined();
      } finally {
        try { rmSync(otherHome, { recursive: true, force: true }); } catch { /* best effort */ }
      }
      expect(ask(privileged(), { now: T0 + 2_100 }).body.decision).toBe('allow');
    });

    it('records sessionKey on the fingerprint; ungranted other session cannot allow', () => {
      const a = ask(privileged());
      expect(listRetryRows({ home, now: T0 })[0].originScope.sessionKey).toBe(SESSION);
      const b = ask(privileged({ sessionId: OTHER_SESSION }));
      expect(b.body.decision).toBe('require_approval');
      expect(b.body.approved).toBeUndefined();
      expect(a.body.denial?.actionId).not.toBe(b.body.denial?.actionId);
    });
  });

  describe('fail-closed edges', () => {
    it('catastrophic block records nothing and offers no approve path', () => {
      const { body } = ask({
        tool: 'Bash',
        args: { command: WIPE },
        sessionId: SESSION,
        cwd,
      });
      expect(body.decision).toBe('block');
      expect(body.denial).toBeUndefined();
      expect(listRetryRows({ home, now: T0 })).toHaveLength(0);
      expect(body.reason ?? '').not.toMatch(BARE_APPROVE);
      expect(body.reason ?? '').not.toMatch(/approve --denial/);
    });

    it('no session ⇒ nothing is recorded and no id is advertised', () => {
      for (const sessionId of [undefined, '', '   ', 42, { id: 'x' }]) {
        const { body } = ask({ tool: 'Bash', args: { command: PRIV }, sessionId, cwd });
        expect(body.decision).toBe('require_approval');
        expect(body.denial).toBeUndefined();
        expect(body.reason ?? '').not.toMatch(BARE_APPROVE);
      }
      expect(listRetryRows({ home, now: T0 })).toHaveLength(0);
    });

    it('a session cannot be smuggled through tool args', () => {
      const { body } = ask({
        tool: 'Bash',
        args: { command: PRIV, sessionId: SESSION },
      });
      expect(body.decision).not.toBe('allow');
      expect(body.denial).toBeUndefined();
      expect(body.reason ?? '').not.toMatch(BARE_APPROVE);
      expect(listRetryRows({ home, now: T0 })).toHaveLength(0);
    });

    it('an allow verdict records nothing', () => {
      const { body } = ask({
        tool: 'Bash',
        args: { command: 'git status' },
        sessionId: SESSION,
        cwd,
      });
      expect(body.decision).toBe('allow');
      expect(body.denial).toBeUndefined();
      expect(listRetryRows({ home, now: T0 })).toHaveLength(0);
    });
  });

  describe('request validation is unchanged', () => {
    it('rejects a missing tool', () => {
      const { status, body } = ask({ args: { command: 'ls' } });
      expect(status).toBe(400);
      expect(body).toEqual({ error: 'tool (string) is required' });
    });

    it('rejects non-object args', () => {
      const { status } = ask({ tool: 'Bash', args: 'ls' });
      expect(status).toBe(400);
    });
  });
});
