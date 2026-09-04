/**
 * #63 — POST /api/v1/action-guard DNP honesty gap.
 *
 * Hermes has no prompt surface. Privilege-escalation is require_approval, then
 * a headless deny. A DNP fingerprint is recorded and its id is returned in
 * `denial.actionId` — the ONE source of truth for the operator command. The
 * `reason` stays semantic: the Hermes policy renders
 * `shieldcortex approve --denial <actionId>` from the id, exactly once, and a
 * REST reason that spelled the command out too made the reject copy say it
 * twice. Bare `shieldcortex approve` lists #118 cards this plane never creates.
 *
 * Two other things are pinned here because this lane is where they are load-
 * bearing: a consumed retry grant leaves a real audit row before the allow is
 * returned, and `--any-origin` never widens past the recorded session.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import type { Request, Response } from 'express';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { closeDatabase, getDatabase, initDatabase } from '../../database/init.js';
import { handleV1ActionGuard, type ActionGuardDeps } from '../visualization-server.js';
import {
  canonicaliseCwd,
  fingerprintId,
  getRetryRow,
  grantRetry,
  hashToolCall,
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
    it('refuses privilege-escalation and carries the id in denial.actionId, not the copy', () => {
      const { body } = ask(privileged());

      expect(body.decision).toBe('require_approval');
      expect(body.signals).toContain('privilege-escalation');
      expect(body.denial?.actionId).toMatch(/^act-[0-9a-f]{16}$/);
      // ONE source of truth: the id travels in `denial.actionId`, and the
      // reason stays semantic. Spelling the command here too is what produced
      // a Hermes reject message that named it twice.
      expect(body.reason).toContain('headless denial recorded');
      expect(body.reason ?? '').not.toContain('--denial');
      expect(body.reason ?? '').not.toContain(body.denial!.actionId);
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

  // The bug above was pinned on privilege-escalation alone, whose remediation
  // copy happened to be clean — so two install hints that DID spell the
  // command out shipped a doubled reject message anyway (#451). The contract
  // belongs to the lane, not to one signal.
  describe('one source of truth holds for every require_approval signal', () => {
    const signalled: Array<[string, string]> = [
      ['privilege-escalation', PRIV],
      ['install-package-global', `${'n' + 'pm'} ${'in' + 'stall'} ${'-' + 'g'} left-pad`],
      ['install-package', `${'p' + 'ip'} ${'in' + 'stall'} requests`],
      ['git-force-push', `git ${'pu' + 'sh'} --force origin main`],
      ['registry-code-exec', `${'uv' + 'x'} ruff check .`],
    ];

    it.each(signalled)('%s: the id travels in denial.actionId, never in the copy', (signal, command) => {
      const { body } = ask({ tool: 'Bash', args: { command }, sessionId: SESSION, cwd });

      expect(body.decision).toBe('require_approval');
      expect(body.signals).toContain(signal);
      expect(body.denial?.actionId).toMatch(/^act-[0-9a-f]{16}$/);
      expect(body.reason).toContain('headless denial recorded');
      // The Hermes policy is the ONE renderer. A reason that names the command
      // makes the reject text say it twice, and the copy here can only ever
      // spell an id nobody can run.
      expect(body.reason ?? '').not.toContain('--denial');
      expect(body.reason ?? '').not.toMatch(BARE_APPROVE);
      expect(body.reason ?? '').not.toMatch(/<\s*action[_ -]?id\s*>/i);
      expect(body.reason ?? '').not.toContain(body.denial!.actionId);
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

    it('a granted retry cannot cross sessions and remains spendable once by its session', () => {
      const actionId = grantOnce();

      const stolen = ask(privileged({ sessionId: OTHER_SESSION }), { now: T0 + 2_000 });
      expect(stolen.body.decision).toBe('require_approval');
      expect(stolen.body.approved).toBeUndefined();
      expect(stolen.body.denial?.actionId).not.toBe(actionId);

      const original = ask(privileged(), { now: T0 + 2_100 });
      expect(original.body.decision).toBe('allow');
      expect(original.body.approved).toBe(true);
      expect(original.body.reason).toContain(actionId);

      const rows = listRetryRows({ home, now: T0 + 2_100 });
      expect(rows.map((row) => row.originScope.sessionKey)).toEqual(
        expect.arrayContaining([SESSION, OTHER_SESSION]),
      );
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

  describe('a consumed retry grant is audited before the allow is returned', () => {
    let dbDir: string;

    beforeEach(() => {
      dbDir = mkdtempSync(join(tmpdir(), 'sc-ag63-db-'));
      initDatabase(join(dbDir, 'shieldcortex.db'));
    });

    afterEach(() => {
      closeDatabase();
      try { rmSync(dbDir, { recursive: true, force: true }); } catch { /* best effort */ }
    });

    const auditRows = (): Array<Record<string, unknown>> =>
      getDatabase()
        .prepare('SELECT * FROM defence_audit ORDER BY id')
        .all() as Array<Record<string, unknown>>;

    it('writes one ALLOW row bound to the action id and the exact call, never the command', () => {
      const actionId = ask(privileged()).body.denial!.actionId;
      // The refusal itself is not what this row is for: nothing is written yet.
      expect(auditRows()).toHaveLength(0);

      expect(grantRetry(
        { actionId },
        { isInteractive: true },
        { home, now: T0 + 1_000, tool: 'Bash' },
      ).ok).toBe(true);
      expect(auditRows()).toHaveLength(0);

      // The response is only built AFTER the ledger has the row: snapshot the
      // table from inside res.json, which is the last thing the allow path does.
      let rowsAtResponse = -1;
      const res = {
        json: () => { rowsAtResponse = auditRows().length; },
        status: () => ({ json: () => { rowsAtResponse = auditRows().length; } }),
      } as unknown as Response;
      handleV1ActionGuard(
        { body: privileged() } as unknown as Request,
        res,
        { home, now: T0 + 2_000 },
      );
      expect(rowsAtResponse).toBe(1);

      const rows = auditRows();
      expect(rows).toHaveLength(1);
      const row = rows[0];
      expect(row.firewall_result).toBe('ALLOW');
      expect(row.source_type).toBe('api');
      expect(row.source_identifier).toBe('action-guard');
      expect(row.timestamp).toBe(new Date(T0 + 2_000).toISOString());

      // The evidence the hook lane records for the same event: which action,
      // which outcome, and how the grant was minted.
      const reason = String(row.reason);
      expect(reason).toContain('[action-guard:retry_grant_consumed]');
      expect(reason).toContain('tool=Bash');
      expect(reason).toContain('action=require_approval');
      expect(reason).toContain('outcome=approved');
      expect(reason).toContain('grantKind=retry');
      expect(reason).toContain('via=tty');
      expect(reason).toContain(`session=${SESSION}`);
      expect(reason).toContain(`actionId=${actionId}`);
      expect(JSON.parse(String(row.threat_indicators))).toContain('privilege-escalation');

      // Bound to the EXACT call by its byte-exact hash — and carrying none of it.
      expect(row.content_hash).toBe(hashToolCall('Bash', { command: PRIV }));
      const serialised = JSON.stringify(row);
      expect(serialised).not.toContain(PRIV);
      for (const fragment of ['systemctl', 'nginx', String.fromCharCode(115, 117, 100, 111)]) {
        expect(serialised).not.toContain(fragment);
      }
    });

    it('writes nothing when the retry is refused — one row per grant actually spent', () => {
      const actionId = ask(privileged()).body.denial!.actionId;
      expect(grantRetry(
        { actionId },
        { isInteractive: true },
        { home, now: T0 + 1_000, tool: 'Bash' },
      ).ok).toBe(true);

      // Wrong session, wrong cwd, mutated command: three refusals, no rows.
      expect(ask(privileged({ sessionId: OTHER_SESSION }), { now: T0 + 2_000 }).body.decision)
        .toBe('require_approval');
      expect(ask(privileged({ cwd: otherCwd }), { now: T0 + 2_100 }).body.decision)
        .toBe('require_approval');
      expect(ask(privileged({ args: { command: PRIV_MUTATED } }), { now: T0 + 2_200 }).body.decision)
        .toBe('require_approval');
      expect(auditRows()).toHaveLength(0);

      // The real retry spends once and is audited once; the replay adds nothing.
      expect(ask(privileged(), { now: T0 + 2_300 }).body.decision).toBe('allow');
      expect(ask(privileged(), { now: T0 + 2_400 }).body.decision).toBe('require_approval');
      expect(auditRows()).toHaveLength(1);
    });

    it('a catastrophic block is never audited as an allow and never reaches the retry plane', () => {
      const { body } = ask({ tool: 'Bash', args: { command: WIPE }, sessionId: SESSION, cwd });
      expect(body.decision).toBe('block');
      expect(auditRows()).toHaveLength(0);
    });
  });

  describe('--any-origin widens cwd only, never the session', () => {
    it('a grant widened to any directory still spends only in its recorded session', () => {
      const actionId = ask(privileged()).body.denial!.actionId;
      const granted = grantRetry(
        { actionId },
        { isInteractive: true, anyOrigin: true },
        { home, now: T0 + 1_000, tool: 'Bash' },
      );
      expect(granted.ok).toBe(true);
      expect(granted.ok && granted.grant.origin.anyOrigin).toBe(true);
      expect(granted.ok && granted.grant.origin.sessionKey).toBe(SESSION);

      // Another Hermes task cannot spend it — not even from the same directory.
      const stolen = ask(privileged({ sessionId: OTHER_SESSION }), { now: T0 + 2_000 });
      expect(stolen.body.decision).toBe('require_approval');
      expect(stolen.body.approved).toBeUndefined();

      // What --any-origin actually bought: the SAME session, a DIFFERENT cwd.
      const elsewhere = ask(privileged({ cwd: otherCwd }), { now: T0 + 2_100 });
      expect(elsewhere.body.decision).toBe('allow');
      expect(elsewhere.body.approved).toBe(true);

      // Still one-shot.
      expect(ask(privileged(), { now: T0 + 2_200 }).body.decision).toBe('require_approval');
    });

    it('the widened grant keeps its session binding in the store, not just in the copy', () => {
      const actionId = ask(privileged()).body.denial!.actionId;
      expect(grantRetry(
        { actionId },
        { isInteractive: true, anyOrigin: true },
        { home, now: T0 + 1_000, tool: 'Bash' },
      ).ok).toBe(true);

      const id = fingerprintId(hashToolCall('Bash', { command: PRIV }), canonicaliseCwd(cwd), SESSION);
      const grant = getRetryRow({ id }, { home, now: T0 + 1_000 })!.grant!;
      expect(grant.origin.cwd).toBeUndefined();
      expect(grant.origin.sessionKey).toBe(SESSION);
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
