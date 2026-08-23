/**
 * #310 — operator retry control, driven through the REAL Claude Code hook.
 *
 * Same seam as pre-tool-hook-notify-143.test.ts: the actual
 * `scripts/pre-tool-hook.mjs` runs as a subprocess against the actual guard,
 * approvals store, notify-config, dnp-digest and retry-control modules from
 * `dist`. Two edges are swapped for fakes because they leave the box: the
 * webhook channel (file-evidence fake) and the `openclaw` binary (a shell
 * script that answers with whatever decision the test wrote).
 *
 * What is pinned here is the WIRING and its ordering, which is where this
 * feature can hurt:
 *   - cards do not exist until `actionGuard.retryCards` is exactly true;
 *   - fingerprints + `approve --denial` consume ARE on even with cards off (#378);
 *   - a catastrophic call never reaches any of it;
 *   - suppression is checked BEFORE the digest window opens and before any
 *     budget is spent;
 *   - a grant is spent only on an AND-match of {cwd, tool}, once;
 *   - the live-hold (#118/#143) path is unchanged with the feature ON.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { grantRetry } from '../defence/iron-dome/retry-control.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');

const IRREVERSIBLE = { command: 'sudo modprobe softdog' };
/** Assembled character by character, deliberately: this file is scanned by
 *  the very guard it exercises, and the literal reads as the real thing. */
const CATASTROPHIC = { command: ['r', 'm', ' ', '-', 'r', 'f', ' ', '/'].join('') };

interface HookResult { decision?: string; reason?: string; stderr: string }

interface RetryStore {
  rows: Array<{
    id: string;
    hash: string;
    tool: string;
    denyEpoch: number;
    actionIds: string[];
    originScope: { cwd?: string; sessionKey?: string };
    suppression?: { until: number };
    claim?: { nonceHmac: string; epoch: number };
    grant?: { approvedAt: number; ttlMs: number; consumedAt?: number; origin: { cwd?: string; tool: string } };
  }>;
  budget: { windowStartMs: number; cards: number; lostActionIds: string[] } | null;
}

describe('#310 — retry control through the real Claude Code hook', () => {
  let home: string;
  let distRoot: string;
  let jobCwd: string;
  let evidenceFile: string;
  let openclawBin: string;
  let decisionFile: string;

  beforeAll(() => {
    const probes = [
      'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
      'webhook-notify-channel.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
    ].map((f) => join(REAL_DIST, f));
    if (!probes.every((p) => existsSync(p))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-retry-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    jobCwd = mkdtempSync(join(tmpdir(), 'sc-retry-cwd-'));
    evidenceFile = join(home, 'webhook-evidence.jsonl');

    distRoot = mkdtempSync(join(tmpdir(), 'sc-retry-dist-'));
    const ironDomeDir = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(ironDomeDir, { recursive: true });
    // Thin re-export shims onto the REAL build — every module here is the
    // shipped one; only the two edges below are fakes.
    for (const f of [
      'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
      'script-source-resolver.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
      'openclaw-approval-channel.js',
    ]) {
      const real = join(REAL_DIST, f);
      if (existsSync(real)) {
        writeFileSync(join(ironDomeDir, f), `export * from ${JSON.stringify(pathToFileURL(real).href)};\n`);
      }
    }
    // Appending fake webhook: every delivery lands as one JSONL line.
    writeFileSync(
      join(ironDomeDir, 'webhook-notify-channel.js'),
      [
        "import { appendFileSync as af } from 'node:fs';",
        'export function createWebhookNotifyChannel(opts) {',
        '  return {',
        "    name: 'webhook',",
        '    async send(notification) {',
        '      const u = new URL(opts.url);',
        "      const evidencePath = u.searchParams.get('evidence');",
        "      if (evidencePath) af(evidencePath, JSON.stringify(notification) + '\\n');",
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );

    // The fake gateway CLI: ignores its arguments and answers with whatever
    // the test last wrote to the decision file.
    decisionFile = join(home, 'decision.json');
    writeFileSync(decisionFile, JSON.stringify({ decision: null }));
    openclawBin = join(home, 'fake-openclaw');
    writeFileSync(openclawBin, `#!/bin/sh\ncat ${JSON.stringify(decisionFile)}\n`, { mode: 0o755 });
    chmodSync(openclawBin, 0o755);
  });

  afterEach(() => {
    for (const dir of [home, distRoot, jobCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function writeConfig(actionGuard: Record<string, unknown>): void {
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ actionGuard: { enabled: true, enforce: true, ...actionGuard } }),
    );
  }

  function webhookUrl(): string {
    return `http://fake-webhook.invalid/hook?evidence=${encodeURIComponent(evidenceFile)}`;
  }

  /** Retry cards ON, webhook denial sink configured, card channel per arg. */
  function retryConfig(opts: { openclaw?: boolean; digestWindowMs?: number; ttlMs?: number; suppressMs?: number } = {}) {
    return {
      retryCards: true,
      ...(opts.ttlMs ? { retryGrantTtlMs: opts.ttlMs } : {}),
      ...(opts.suppressMs ? { denySuppressionMs: opts.suppressMs } : {}),
      notify: {
        enabled: true,
        webhookUrl: webhookUrl(),
        openclaw: opts.openclaw === true,
        ...(opts.digestWindowMs !== undefined ? { dnpDigestWindowMs: opts.digestWindowMs } : {}),
      },
    };
  }

  function runHook(
    input: Record<string, unknown>,
    opts: { tool?: string; cwd?: string; sessionId?: string; permissionMode?: string } = {},
  ): HookResult {
    const payload = JSON.stringify({
      session_id: opts.sessionId ?? 'retry-session-1',
      cwd: opts.cwd ?? jobCwd,
      hook_event_name: 'PreToolUse',
      // bypassPermissions is how every unattended agent and cron on this fleet
      // runs — the promptless box this whole feature is about.
      permission_mode: opts.permissionMode ?? 'bypassPermissions',
      tool_name: opts.tool ?? 'Bash',
      tool_input: input,
    });
    const run = spawnSync('node', [HOOK], {
      input: payload,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_DIST_ROOT: distRoot,
        SHIELDCORTEX_OPENCLAW_BIN: openclawBin,
      } as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
    });
    const stdout = run.stdout ?? '';
    if (!stdout.trim()) return { stderr: run.stderr ?? '' };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, reason: out.permissionDecisionReason, stderr: run.stderr ?? '' };
  }

  function storePath(): string {
    return join(home, '.shieldcortex', 'approvals', 'retry-control.json');
  }

  function store(): RetryStore | null {
    return existsSync(storePath()) ? (JSON.parse(readFileSync(storePath(), 'utf8')) as RetryStore) : null;
  }

  function evidence(): Array<Record<string, unknown>> {
    if (!existsSync(evidenceFile)) return [];
    return readFileSync(evidenceFile, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  }

  function auditRows(): Array<Record<string, unknown>> {
    const date = new Date().toISOString().slice(0, 10);
    const file = join(home, '.shieldcortex', 'audit', `realtime-${date}.jsonl`);
    return existsSync(file)
      ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      : [];
  }

  function denialRows(): Array<Record<string, unknown>> {
    const file = join(home, '.shieldcortex', 'denials.jsonl');
    return existsSync(file)
      ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      : [];
  }

  /** The waiter is detached; wait for its EFFECT rather than for its pid. */
  function waitFor(predicate: () => boolean, timeoutMs = 15_000): boolean {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (predicate()) return true;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
    }
    return predicate();
  }

  // ── Default OFF (cards) ────────────────────────────────────────────────
  // #378 — the retry *plane* (fingerprint + TTY --denial) is always-on.
  // Cards stay dark until retryCards is exactly true.

  it('cards stay off by default — denial is still terminal, but a fingerprint is left', () => {
    writeConfig({ notify: { enabled: true, webhookUrl: webhookUrl() } });
    const r = runHook(IRREVERSIBLE);

    expect(r.decision).toBe('deny');
    const rows = store()!.rows;
    expect(rows).toHaveLength(1);
    expect(rows[0].grant).toBeUndefined();
    expect(rows[0].claim).toBeUndefined();
    expect(store()!.budget).toBeNull();
    expect(evidence()).toHaveLength(1);
    // Cards off: no budget_exhausted / no card-raised. Digest may still name
    // the terminal one-shot path (operator UX) — that is not a card.
    const body = JSON.stringify(evidence());
    expect(body).not.toContain('budget_exhausted');
    expect(body).toMatch(/held \(headless/i);
    expect(body).toMatch(/No Approve card/i);
    expect(r.stderr).not.toMatch(/retry card raised|Approve-once card raised/);
  });

  it('stays card-dark for a config that merely mentions retryCards without true', () => {
    writeConfig({ retryCards: 'yes', notify: { enabled: true, webhookUrl: webhookUrl() } });
    const r = runHook(IRREVERSIBLE);

    expect(r.decision).toBe('deny');
    const rows = store()!.rows;
    expect(rows).toHaveLength(1);
    expect(rows[0].claim).toBeUndefined();
    expect(rows[0].grant).toBeUndefined();
    expect(r.stderr).not.toMatch(/retry card raised/);
  });

  it('#378 TTY --denial grant is consumable with cards off', () => {
    writeConfig({ notify: { enabled: true, webhookUrl: webhookUrl() } });
    expect(runHook(IRREVERSIBLE).decision).toBe('deny');
    const row = store()!.rows[0];
    expect(row.claim).toBeUndefined();

    const granted = grantRetry({ id: row.id }, { isInteractive: true }, { home });
    expect(granted.ok).toBe(true);

    const retried = runHook(IRREVERSIBLE);
    expect(retried.decision).toBeUndefined();
    expect(retried.stderr).toContain('consumed operator RETRY grant');
    expect(runHook(IRREVERSIBLE).decision).toBe('deny');
  });

  // ── Fingerprint, and only a fingerprint ────────────────────────────────

  it('a denial mints a FINGERPRINT and nothing spendable', () => {
    writeConfig(retryConfig());
    const r = runHook(IRREVERSIBLE);

    expect(r.decision).toBe('deny');
    const rows = store()!.rows;
    expect(rows).toHaveLength(1);
    expect(rows[0].tool).toBe('Bash');
    expect(rows[0].originScope.cwd).toBeTruthy();
    expect(rows[0].originScope.sessionKey).toMatch(/^sc-[a-f0-9]{16}$/);
    expect(rows[0].grant).toBeUndefined();
    expect(rows[0].claim).toBeUndefined();
    // The command itself is never in the control record.
    expect(readFileSync(storePath(), 'utf8')).not.toContain('modprobe');
  });

  it('remints under one identity — same row, same epoch, alias index grows', () => {
    writeConfig(retryConfig());
    runHook(IRREVERSIBLE);
    runHook(IRREVERSIBLE);
    runHook(IRREVERSIBLE);

    const rows = store()!.rows;
    expect(rows).toHaveLength(1);
    expect(rows[0].denyEpoch).toBe(0);
    expect(rows[0].actionIds.length).toBe(3);
  });

  it('a CATASTROPHIC call never reaches the retry plane at all', () => {
    writeConfig(retryConfig({ openclaw: true }));
    const r = runHook(CATASTROPHIC);

    expect(r.decision).toBe('deny');
    expect(r.reason).toContain('Catastrophic-tier');
    expect(store()).toBeNull();
  });

  it('scopes the fingerprint to the HARNESS cwd, never to anything in tool input', () => {
    writeConfig(retryConfig());
    runHook({ command: 'sudo modprobe softdog', cwd: '/etc' });
    const rows = store()!.rows;
    expect(rows[0].originScope.cwd).not.toBe('/etc');
    expect(rows[0].originScope.cwd).toContain('sc-retry-cwd-');
  });

  // ── Suppression first (design B2) ──────────────────────────────────────

  it('suppression is checked BEFORE the digest opens and before any budget is spent', () => {
    writeConfig(retryConfig({ openclaw: true }));
    writeFileSync(decisionFile, JSON.stringify({ decision: 'deny' }));

    // First denial: opens the digest window, spends one card, operator says no.
    runHook(IRREVERSIBLE);
    expect(waitFor(() => (store()?.rows ?? []).some((row) => row.suppression !== undefined))).toBe(true);
    expect(store()!.budget!.cards).toBe(1);
    expect(evidence()).toHaveLength(1);

    // The SAME job flaps again inside the silence window. Its fingerprint is
    // still written — audit truth is never what gets muted — but nobody is
    // paged, the digest window is not touched, and no budget is spent.
    const before = store()!.rows.find((row) => row.suppression)!;
    const evidenceBefore = evidence().length;
    const cardsBefore = store()!.budget!.cards;
    runHook(IRREVERSIBLE, { sessionId: 'cron-tick-2' });

    const after = store()!.rows.find((row) => row.id === before.id)!;
    expect(after.actionIds.length).toBeGreaterThan(before.actionIds.length);
    expect(after.claim).toBeUndefined();
    expect(evidence().length).toBe(evidenceBefore);
    expect(store()!.budget!.cards).toBe(cardsBefore);
    // And the forensics row says WHY nobody was paged, honestly.
    expect(denialRows().some((row) => (row.notify as { status?: string })?.status === 'suppressed')).toBe(true);
  });

  // ── Budget ─────────────────────────────────────────────────────────────

  it('caps cards per window and puts the lost actionIds on the operator copy', () => {
    // Digest OFF so every DNP sends — this test is about the budget, not the
    // digest's volume control.
    writeConfig(retryConfig({ openclaw: true, digestWindowMs: 0 }));
    const commands = [
      { command: 'sudo modprobe softdog' },
      { command: 'sudo rmmod softdog' },
      { command: 'sudo insmod /tmp/one.ko' },
      { command: 'sudo insmod /tmp/two.ko' },
    ];
    for (const c of commands) runHook(c);

    const s = store()!;
    expect(s.budget!.cards).toBe(3);
    expect(s.rows.filter((row) => row.claim).length).toBe(3);

    const body = JSON.stringify(evidence()[evidence().length - 1]);
    expect(body).toContain('budget_exhausted');
    expect(body).toContain('shieldcortex approve --denial');
    // The id that lost its card is NAMED, not merely counted.
    const lostRow = s.rows.find((row) => !row.claim)!;
    expect(body).toContain(lostRow.actionIds[lostRow.actionIds.length - 1]);
  });

  // ── The full loop ──────────────────────────────────────────────────────

  it('deny → card → tap → the SAME job retries once, then is refused again', () => {
    writeConfig(retryConfig({ openclaw: true }));
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));

    const denied = runHook(IRREVERSIBLE);
    expect(denied.decision).toBe('deny');

    expect(waitFor(() => (store()?.rows[0]?.grant ?? null) !== null)).toBe(true);
    const grant = store()!.rows[0].grant!;
    expect(grant.origin.tool).toBe('Bash');
    expect(grant.origin.cwd).toBeTruthy();

    // The next tick of the same job, in the same directory: it passes, and the
    // hook emits NO decision (it defers to the harness's own permissions).
    const retried = runHook(IRREVERSIBLE);
    expect(retried.decision).toBeUndefined();
    expect(retried.stderr).toContain('consumed operator RETRY grant');
    expect(auditRows().some((row) => row.outcome === 'approved' && row.grantKind === 'retry')).toBe(true);

    // One shot. The tick after that is denied again.
    expect(runHook(IRREVERSIBLE).decision).toBe('deny');
  });

  it('a grant from ANOTHER directory is never spent here', () => {
    writeConfig(retryConfig({ openclaw: true }));
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    runHook(IRREVERSIBLE);
    expect(waitFor(() => (store()?.rows[0]?.grant ?? null) !== null)).toBe(true);

    const elsewhere = mkdtempSync(join(tmpdir(), 'sc-retry-other-'));
    try {
      expect(runHook(IRREVERSIBLE, { cwd: elsewhere }).decision).toBe('deny');
      expect(store()!.rows.find((row) => row.grant && !row.grant.consumedAt)).toBeDefined();
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it('a NEW session key still spends the grant — sessionKey is diagnostic only', () => {
    writeConfig(retryConfig({ openclaw: true }));
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    runHook(IRREVERSIBLE, { sessionId: 'cron-tick-1' });
    expect(waitFor(() => (store()?.rows[0]?.grant ?? null) !== null)).toBe(true);

    // The next cron tick is a brand-new Claude session.
    const retried = runHook(IRREVERSIBLE, { sessionId: 'cron-tick-2' });
    expect(retried.decision).toBeUndefined();
    expect(retried.stderr).toContain('consumed operator RETRY grant');
  });

  it('a live unspent grant blocks a second card for the same identity', () => {
    writeConfig(retryConfig({ openclaw: true }));
    writeFileSync(decisionFile, JSON.stringify({ decision: 'allow-once' }));
    runHook(IRREVERSIBLE);
    expect(waitFor(() => (store()?.rows[0]?.grant ?? null) !== null)).toBe(true);
    const cardsAfterFirst = store()!.budget!.cards;

    // The job flaps again before the operator's retry ran.
    runHook(IRREVERSIBLE, { sessionId: 'cron-tick-2' });
    expect(store()!.budget!.cards).toBe(cardsAfterFirst);
    expect(store()!.rows[0].grant).toBeDefined();
  });

  it('a denied card silences the action and leaves no unspent grant behind', () => {
    writeConfig(retryConfig({ openclaw: true }));
    writeFileSync(decisionFile, JSON.stringify({ decision: 'deny' }));
    runHook(IRREVERSIBLE);

    expect(waitFor(() => (store()?.rows ?? []).some((row) => row.suppression))).toBe(true);
    const suppressed = store()!.rows.find((row) => row.suppression)!;
    expect(suppressed.grant).toBeUndefined();
    expect(suppressed.denyEpoch).toBeGreaterThan(0);
  });

  // ── The live-hold path is untouched ────────────────────────────────────

  it('leaves the live-hold (#118/#143) path exactly as it was, with the feature ON', () => {
    writeConfig(retryConfig({ openclaw: true }));
    const r = runHook(IRREVERSIBLE, { permissionMode: 'default' });

    // Unchanged: an answerable session still gets ASK + the #118 hash.
    expect(r.decision).toBe('ask');
    expect(r.reason).toMatch(/shieldcortex approve [0-9a-f]{12}/);
    // No fingerprint, no card, no grant: there was no DNP.
    const s = store();
    expect(s === null || s.rows.length === 0).toBe(true);
    // And the #118 pending record is there, exactly as before.
    const approvals = JSON.parse(
      readFileSync(join(home, '.shieldcortex', 'approvals', 'approvals.json'), 'utf8'),
    ) as { records: Array<{ hash: string; approvedAt?: number }> };
    expect(approvals.records).toHaveLength(1);
    expect(approvals.records[0].approvedAt).toBeUndefined();
  });

  it('never puts a claim nonce anywhere an operator alert or a log can reach', () => {
    writeConfig(retryConfig({ openclaw: true }));
    runHook(IRREVERSIBLE);
    expect(waitFor(() => (store()?.rows[0]?.claim ?? null) !== null)).toBe(true);

    const onDisk = readFileSync(storePath(), 'utf8');
    const row = store()!.rows[0];
    const hmac = row.claim!.nonceHmac;
    expect(hmac).toMatch(/^[0-9a-f]{64}$/);
    // The ONLY 64-hex values on disk are the call hash (which is not spendable
    // — #118 has always printed it) and the nonce HMAC. No raw nonce, and no
    // second secret hiding beside it.
    const hexes = new Set((onDisk.match(/[0-9a-f]{64}/g) ?? []));
    hexes.delete(hmac);
    hexes.delete(row.hash);
    expect([...hexes]).toHaveLength(0);
    // And no spendable token in the alert or the forensics rows.
    expect(JSON.stringify(evidence())).not.toContain(hmac);
    expect(JSON.stringify(denialRows())).not.toContain(hmac);
  });
});
