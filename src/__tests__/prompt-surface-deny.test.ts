/**
 * Action Guard hook — an approval verdict with nowhere to ask becomes a DENY.
 *
 * Motivating incident (2026-07-30, aiquant): the hook returned
 * `permissionDecision: "ask"` for a global npm install in a headless
 * `bypassPermissions` session. Claude Code 2.1.76 discarded the ask and ran the
 * command; 2.1.220 on the same box, same hook, same policy, blocked it. The
 * guard's verdict was right both times — the harness decided what to do with it.
 *
 * `deny` is the one PreToolUse verdict every observed version honours, so when
 * approval is required and no prompt surface can be confirmed, the hook denies.
 * These tests pin that mapping per permission mode so a future refactor can't
 * quietly restore the version-dependent outcome.
 */
import { execSync, spawn } from 'child_process';
import { createHmac } from 'crypto';
import fs from 'fs';
import http from 'http';
import type { AddressInfo } from 'net';
import os from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.resolve(REPO_ROOT, 'scripts', 'pre-tool-hook.mjs');

/** Dangerous tier, not catastrophic — catastrophic denies regardless of mode. */
const DANGEROUS_COMMAND = 'sudo systemctl stop nginx';

type HookResult = { stdout: string; stderr: string; code: number };

function runHook(payload: unknown, envOverrides: NodeJS.ProcessEnv = {}): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...envOverrides },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

/** `permissionMode: undefined` omits the field, mirroring a harness that never sends it. */
function call(command: string, permissionMode?: string): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    session_id: 'test-session',
    cwd: '/tmp',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
  if (permissionMode !== undefined) payload.permission_mode = permissionMode;
  return payload;
}

function decisionOf(stdout: string): { permissionDecision?: string; permissionDecisionReason?: string } {
  const parsed = JSON.parse(stdout);
  expect(parsed.hookSpecificOutput?.hookEventName).toBe('PreToolUse');
  return parsed.hookSpecificOutput;
}

describe('Action Guard hook — prompt-surface rule', () => {
  const originalHome = process.env.HOME;
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-prompt-surface-'));
    process.env.HOME = tempHome;
  });
  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function writeActionGuardConfig(actionGuard: Record<string, unknown>): void {
    const dir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard }));
  }

  function lastAudit(): Record<string, unknown> {
    const dir = path.join(tempHome, '.shieldcortex', 'audit');
    const file = fs.readdirSync(dir).find((n) => /^realtime-.*\.jsonl$/.test(n))!;
    const lines = fs.readFileSync(path.join(dir, file), 'utf-8').trim().split('\n');
    return JSON.parse(lines[lines.length - 1]);
  }

  describe('modes that can raise a prompt → ask', () => {
    it.each(['default', 'manual', 'acceptEdits', 'plan', 'auto'])('%s asks', async (mode) => {
      const result = await runHook(call(DANGEROUS_COMMAND, mode));
      expect(result.code).toBe(0);
      expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
      expect(lastAudit().outcome).toBe('asked');
    });
  });

  describe('modes with no prompt surface → deny', () => {
    // bypassPermissions and dontAsk are documented as showing no prompt; an
    // unknown or absent mode means the harness hasn't told us it can prompt.
    it.each([
      ['bypassPermissions', 'bypassPermissions'],
      ['dontAsk', 'dontAsk'],
      ['an unrecognised mode', 'yoloMode'],
      ['an empty mode string', ''],
    ])('%s denies', async (_label, mode) => {
      const result = await runHook(call(DANGEROUS_COMMAND, mode));
      expect(result.code).toBe(0);
      const decision = decisionOf(result.stdout);
      expect(decision.permissionDecision).toBe('deny');
      // The deny reason reaches Claude (an "ask" reason does not), so it has to
      // carry both the original verdict and a way forward.
      expect(decision.permissionDecisionReason).toMatch(/ShieldCortex Action Guard/);
      expect(decision.permissionDecisionReason).toMatch(/autoApprove|enforce/);
    });

    it('denies when the harness sends no permission_mode at all', async () => {
      const result = await runHook(call(DANGEROUS_COMMAND));
      expect(result.code).toBe(0);
      expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
    });
  });

  describe('audit trail', () => {
    it('records the mode and a distinct outcome, keeping the verdict as require_approval', async () => {
      await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      const entry = lastAudit();
      // The guard's verdict didn't change — only what could be done with it.
      expect(entry.action).toBe('require_approval');
      expect(entry.outcome).toBe('denied_no_prompt_surface');
      expect(entry.permissionMode).toBe('bypassPermissions');
      expect(String(entry.noPromptSurfaceReason)).toMatch(/no prompt/i);
    });

    it('separates a prompt-surface deny from a catastrophic auto-deny', async () => {
      await runHook(call('rm -rf /', 'bypassPermissions'));
      const entry = lastAudit();
      expect(entry.outcome).toBe('auto_denied');
      expect(entry.severity).toBe('critical');
    });

    it('records the mode on the ask path too', async () => {
      await runHook(call(DANGEROUS_COMMAND, 'default'));
      expect(lastAudit().permissionMode).toBe('default');
    });
  });

  describe('the rule narrows nothing else', () => {
    it('enforce:false stays advisory in bypassPermissions — no decision emitted', async () => {
      writeActionGuardConfig({ enforce: false });
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      expect(result.code).toBe(0);
      expect(result.stdout).toBe('');
      expect(result.stderr).toMatch(/action guard/i);
    });

    it('an autoApprove match still defers to Claude Code, never denied', async () => {
      writeActionGuardConfig({ autoApprove: ['sudo_command'] });
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      expect(result.code).toBe(0);
      expect(result.stdout).toBe('');
    });

    it('benign commands emit nothing regardless of mode', async () => {
      const result = await runHook(call('ls -la', 'bypassPermissions'));
      expect(result.code).toBe(0);
      expect(result.stdout).toBe('');
    });
  });

  /**
   * #143 — a denial must reach the operator AS a denial.
   *
   * The rule above is right and is not changing: an unanswerable ask becomes a
   * deny. What was wrong is what the operator was TOLD about it. The notify
   * ping fired on the shared path before the ask/deny branch, so on a
   * promptless box — `bypassPermissions`, how every unattended agent and cron
   * on this fleet runs — the message read "approve this?" for a call that had
   * already been refused and handed back to the agent, and it never said that
   * a job had just died or which one. 41 gated actions were hard-denied on
   * this fleet in one week with nobody told; one was a nightly backup that is
   * simply absent from the backup repo, another was `email_pickup.py` denied
   * 15 times over 7 hours, found by reading audit jsonl by hand.
   *
   * This drives the REAL hook against the REAL dist and the REAL webhook
   * channel, over a throwaway loopback server — no fake channel, no network
   * beyond 127.0.0.1 — so the header, the signature and the body are the ones
   * an operator's receiver would actually get.
   */
  describe('the operator is told a job died (#143)', () => {
    const SECRET = 'notify-signing-key';
    type Delivery = { headers: http.IncomingHttpHeaders; body: string };

    let server: http.Server;
    let port: number;
    let deliveries: Delivery[];
    /** Per-test behaviour of the receiver — the failure modes a real one has. */
    let mode: 'ok' | 'error' | 'hang';
    const openSockets = new Set<import('net').Socket>();

    beforeAll(async () => {
      // The hook loads the guard, the approvals store and the notify transport
      // from dist. Mirrors pre-tool-hook-notify-143.test.ts's probe.
      const distProbes = ['tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js', 'webhook-notify-channel.js']
        .map((f) => path.join(REPO_ROOT, 'dist', 'defence', 'iron-dome', f));
      if (!distProbes.every((p) => fs.existsSync(p))) {
        execSync('npm run build:ts', { cwd: REPO_ROOT, stdio: 'ignore' });
      }

      server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (c) => { body += c; });
        req.on('end', () => {
          deliveries.push({ headers: req.headers, body });
          if (mode === 'hang') return; // never responds — the channel must abort
          res.writeHead(mode === 'error' ? 500 : 204).end();
        });
      });
      server.on('connection', (s) => {
        openSockets.add(s);
        s.on('close', () => openSockets.delete(s));
      });
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      port = (server.address() as AddressInfo).port;
    }, 300_000);

    afterAll(async () => {
      for (const s of openSockets) s.destroy();
      await new Promise<void>((r) => server.close(() => r()));
    });

    beforeEach(() => {
      deliveries = [];
      mode = 'ok';
    });

    /** `notify.timeoutMs` is deliberately short: a hook is one process per tool
     *  call, and a hanging receiver must cost the guard a bounded wait, not a
     *  session. 600ms clears notify-config's 500ms floor. */
    function writeNotifyConfig(extra: Record<string, unknown> = {}): void {
      writeActionGuardConfig({
        enabled: true,
        enforce: true,
        notify: { enabled: true, webhookUrl: `http://127.0.0.1:${port}/hook`, webhookSecret: SECRET, timeoutMs: 600, ...extra },
      });
    }

    function delivered(): Record<string, unknown> {
      expect(deliveries).toHaveLength(1);
      return JSON.parse(deliveries[0].body);
    }

    it('delivers a denied_no_prompt_surface event naming the reason, the session and the cwd', async () => {
      writeNotifyConfig();
      const payload = call(DANGEROUS_COMMAND, 'bypassPermissions');
      payload.session_id = 'nightly-backup-42';
      payload.cwd = '/home/ubuntu/backups';

      const result = await runHook(payload);

      // The verdict is untouched — this feature tells the operator things.
      expect(decisionOf(result.stdout).permissionDecision).toBe('deny');

      const body = delivered();
      expect(deliveries[0].headers['x-shieldcortex-event']).toBe('denied_no_prompt_surface');
      expect(body.event).toBe('denied_no_prompt_surface');
      expect(String(body.deniedReason)).toMatch(/bypassPermissions mode shows no prompt/);
      expect(body.sessionId).toBe('nightly-backup-42');
      expect(body.cwd).toBe('/home/ubuntu/backups');
      // The wording is true at the moment it arrives, and the retry is still
      // authorisable — but nothing is offered that would do nothing.
      expect(String(body.text)).toMatch(/BLOCKED/);
      expect(String(body.text)).toMatch(/did NOT run/i);
      expect(String(body.approveCommand)).toMatch(/shieldcortex approve [0-9a-f]{12}/);
      expect(body.denyCommand).toBeUndefined();
    });

    it('signs the body with notify.webhookSecret, so the receiver can reject a forged POST', async () => {
      writeNotifyConfig();
      await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      const { headers, body } = deliveries[0];
      expect(headers['x-shieldcortex-signature']).toBe(createHmac('sha256', SECRET).update(body).digest('hex'));
    });

    it('never leaks the secret into stdout, stderr, or the audit row', async () => {
      writeNotifyConfig();
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      expect(result.stdout).not.toContain(SECRET);
      expect(result.stderr).not.toContain(SECRET);
      expect(JSON.stringify(lastAudit())).not.toContain(SECRET);
    });

    it('a prompting session still gets the approval event, unchanged', async () => {
      writeNotifyConfig();
      const result = await runHook(call(DANGEROUS_COMMAND, 'default'));
      expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
      const body = delivered();
      expect(deliveries[0].headers['x-shieldcortex-event']).toBe('approval_requested');
      expect(body.event).toBe('approval_requested');
      expect(body.deniedReason).toBeUndefined();
      expect(String(body.denyCommand)).toMatch(/shieldcortex deny/);
      expect(String(body.text)).toContain('approval needed');
    });

    it('the notification carries the SAME hash the denial reason offers for the retry', async () => {
      writeNotifyConfig();
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      const reason = String(decisionOf(result.stdout).permissionDecisionReason);
      expect(String(delivered().shortHash)).toBe(reason.match(/shieldcortex approve ([0-9a-f]{12})/)![1]);
    });

    it('the approve command it offers really does authorise the retry', async () => {
      // The denial text tells the operator that approving unblocks the NEXT
      // attempt. That is only true because the pending record is written
      // before the prompt-surface branch — pin it, or the message becomes a
      // promise the guard does not keep.
      writeNotifyConfig();
      await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      const shortHash = String(delivered().shortHash);

      const { approveRequest } = await import(
        pathToFileURL(path.join(REPO_ROOT, 'dist', 'defence', 'iron-dome', 'action-approvals.js')).href
      ) as { approveRequest: (h: string, o: { home: string }) => { ok: boolean } };
      expect(approveRequest(shortHash, { home: tempHome }).ok).toBe(true);

      // The retry now defers to the harness's own permission system: no
      // decision emitted at all, exactly as #118 has always behaved.
      const retry = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      expect(retry.stdout).toBe('');
    });

    // ── the property that matters most ──────────────────────────────────────
    // A notify channel is best-effort. Whatever it does — 500, hang, refuse
    // the connection — the guard's decision, its reason, and its audit row are
    // exactly what they are with no channel configured at all. Pinned for BOTH
    // events, because the denial path is the newly-wired one.
    describe.each([
      ['a promptless denial', 'bypassPermissions', 'deny'],
      ['a live hold', 'default', 'ask'],
    ])('%s survives a broken channel', (_label, permissionMode, expectedDecision) => {
      async function baseline(): Promise<{ decision?: string; reason?: string }> {
        writeActionGuardConfig({ enabled: true, enforce: true });
        const result = await runHook(call(DANGEROUS_COMMAND, permissionMode));
        return decisionOf(result.stdout);
      }

      it('a receiver returning 500 changes nothing', async () => {
        const before = await baseline();
        mode = 'error';
        writeNotifyConfig();
        const after = decisionOf((await runHook(call(DANGEROUS_COMMAND, permissionMode))).stdout);
        expect(after.permissionDecision).toBe(expectedDecision);
        expect(after).toEqual(before);
      });

      it('a receiver that never responds is cut off at the deadline and changes nothing', async () => {
        const before = await baseline();
        mode = 'hang';
        writeNotifyConfig();
        const started = Date.now();
        const after = decisionOf((await runHook(call(DANGEROUS_COMMAND, permissionMode))).stdout);
        expect(after).toEqual(before);
        // Bounded by notify.timeoutMs (600ms) plus process start-up — nowhere
        // near an unbounded wait on a dead receiver.
        expect(Date.now() - started).toBeLessThan(15_000);
      }, 30_000);

      it('a refused connection changes nothing', async () => {
        const before = await baseline();
        // Port 1 on loopback: nothing listens, so this is an immediate ECONNREFUSED.
        writeActionGuardConfig({
          enabled: true, enforce: true,
          notify: { enabled: true, webhookUrl: 'http://127.0.0.1:1/hook', timeoutMs: 600 },
        });
        const after = decisionOf((await runHook(call(DANGEROUS_COMMAND, permissionMode))).stdout);
        expect(after).toEqual(before);
      });
    });
  });

  describe('degraded guard (WS2 fallback) follows the same rule', () => {
    let emptyDist: string;
    beforeEach(() => { emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-emptydist-')); });
    afterEach(() => { fs.rmSync(emptyDist, { recursive: true, force: true }); });

    it('denies a dangerous op when the guard cannot scan and nothing can prompt', async () => {
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'), {
        SHIELDCORTEX_DIST_ROOT: emptyDist,
      });
      expect(result.code).toBe(0);
      expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
      const entry = lastAudit();
      expect(entry.action).toBe('gate_degraded');
      expect(entry.outcome).toBe('denied_no_prompt_surface');
      expect(entry.threats).toContain('fallback-scan');
    });

    it('still asks when the guard cannot scan but a prompt can be raised', async () => {
      const result = await runHook(call(DANGEROUS_COMMAND, 'default'), {
        SHIELDCORTEX_DIST_ROOT: emptyDist,
      });
      expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
      expect(lastAudit().outcome).toBe('asked');
    });
  });
});
