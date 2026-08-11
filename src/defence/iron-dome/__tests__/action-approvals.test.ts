/**
 * #118 — one-shot exact-command approvals.
 *
 * Acceptance from the issue: blocked → approve → the SAME command passes once
 * → a second run is refused again. Plus the fixtures that keep it honest:
 * expiry, wrong hash, replay, and self-approval by a non-interactive caller.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, readFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  hashToolCall,
  recordPending,
  approveRequest,
  denyRequest,
  consumeApproval,
  listApprovals,
  shortHash,
  DEFAULT_APPROVAL_TTL_MS,
} from '../action-approvals.js';
import { runApprove, isInteractive } from '../../../cli/approve.js';
import { runDeny } from '../../../cli/deny.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const SUDO = { command: 'sudo modprobe softdog' };
const OTHER = { command: 'sudo rmmod softdog' };

describe('action approvals (#118)', () => {
  let home: string;
  const T0 = 1_800_000_000_000; // fixed clock — Date.now() is never used in tests

  const request = (input: unknown = SUDO, now = T0) =>
    recordPending(
      { tool: 'Bash', input, summary: `Bash: ${(input as { command: string }).command}`, signals: ['privilege-escalation'] },
      { home, now },
    );

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-approvals-'));
  });

  afterEach(() => {
    try { rmSync(home, { recursive: true, force: true }); } catch { /* best effort */ }
  });

  describe('hashing', () => {
    it('is stable across calls and insensitive to whitespace noise', () => {
      expect(hashToolCall('Bash', { command: 'sudo  modprobe   softdog' }))
        .toBe(hashToolCall('Bash', { command: 'sudo modprobe softdog' }));
    });

    it('is key-order independent but content sensitive', () => {
      expect(hashToolCall('Bash', { a: '1', b: '2' })).toBe(hashToolCall('Bash', { b: '2', a: '1' }));
      expect(hashToolCall('Bash', SUDO)).not.toBe(hashToolCall('Bash', OTHER));
      expect(hashToolCall('Bash', SUDO)).not.toBe(hashToolCall('Write', SUDO));
    });
  });

  describe('#201 — advisory fields do not move the hash of an exec call', () => {
    // The live failure: every agent retry re-words `description` (and often
    // `timeout`), so the approval id was minted per ATTEMPT and the operator
    // chased a moving target. Neither field changes what executes.
    const CMD = { command: 'sleep 10 && /opt/homebrew/bin/openclaw gateway restart' };

    it('description and timeout are annotation, not action', () => {
      expect(hashToolCall('Bash', { ...CMD, description: 'Restart the gateway after a delay', timeout: 120000 }))
        .toBe(hashToolCall('Bash', { ...CMD, description: 'Restart OpenClaw gateway', timeout: 600000 }));
      expect(hashToolCall('Bash', { ...CMD, description: 'x' })).toBe(hashToolCall('Bash', CMD));
    });

    it('load-bearing fields still move it', () => {
      expect(hashToolCall('Bash', { ...CMD, dangerouslyDisableSandbox: true }))
        .not.toBe(hashToolCall('Bash', CMD));
      expect(hashToolCall('Bash', { ...CMD, run_in_background: true }))
        .not.toBe(hashToolCall('Bash', CMD));
    });

    it('non-exec tools keep full-input hashing — description may be payload there', () => {
      expect(hashToolCall('create_issue', { title: 't', description: 'a' }))
        .not.toBe(hashToolCall('create_issue', { title: 't', description: 'b' }));
    });

    it('the live sequence: approve once, identical command with a re-worded description passes', () => {
      const attempt1 = { ...CMD, description: 'Restart the gateway after a delay' };
      const attempt2 = { ...CMD, description: 'Retry: restart OpenClaw gateway', timeout: 600000 };
      const pending = recordPending(
        { tool: 'Bash', input: attempt1, summary: `Bash: ${CMD.command}`, signals: ['service-restart'] },
        { home, now: T0 },
      );
      expect(approveRequest(shortHash(pending.hash), { home, now: T0 + 1000 }).ok).toBe(true);
      expect(consumeApproval('Bash', attempt2, { home, now: T0 + 2000 })).not.toBeNull();
    });
  });

  describe('the acceptance path', () => {
    it('refused → approved → passes ONCE → refused again', () => {
      const pending = request();
      // Nothing is approved yet, so the guard gets nothing to spend.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();

      const outcome = approveRequest(shortHash(pending.hash), { home, now: T0 + 1000 });
      expect(outcome.ok).toBe(true);

      const spent = consumeApproval('Bash', SUDO, { home, now: T0 + 2000 });
      expect(spent).not.toBeNull();
      expect(spent!.hash).toBe(pending.hash);
      expect(spent!.consumedAt).toBe(T0 + 2000);

      // Single use: the very next identical call finds nothing.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + 2001 })).toBeNull();
    });

    it('approves by full hash as well as short prefix', () => {
      const pending = request();
      expect(approveRequest(pending.hash, { home, now: T0 }).ok).toBe(true);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });
  });

  describe('an approval is bound to the exact call', () => {
    it('does not carry over to a different command', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(consumeApproval('Bash', OTHER, { home, now: T0 })).toBeNull();
      // ...and the original approval is still intact, not collaterally spent.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });

    it('does not carry over to the same command on a different tool', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(consumeApproval('Execute', SUDO, { home, now: T0 })).toBeNull();
    });
  });

  describe('expiry', () => {
    it('refuses an approval past its TTL', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + DEFAULT_APPROVAL_TTL_MS + 1 })).toBeNull();
    });

    it('honours a shorter operator-set TTL', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0, ttlMs: 60_000 });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + 59_000 })).not.toBeNull();

      const second = request(SUDO, T0 + 100_000);
      approveRequest(second.hash, { home, now: T0 + 100_000, ttlMs: 60_000 });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + 161_000 })).toBeNull();
    });

    it('does not let a repeated refusal extend a live approval', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      // The agent retries near the end of the window; the guard re-records.
      request(SUDO, T0 + DEFAULT_APPROVAL_TTL_MS - 1000);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 + DEFAULT_APPROVAL_TTL_MS + 1 })).toBeNull();
    });
  });

  describe('bad input', () => {
    it('reports not-found for an unknown hash', () => {
      request();
      expect(approveRequest('deadbeef', { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
    });

    it('refuses to double-approve a live grant', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(approveRequest(pending.hash, { home, now: T0 })).toEqual({ ok: false, reason: 'already-approved' });
    });

    it('refuses an ambiguous prefix rather than guessing', () => {
      request(SUDO);
      request(OTHER);
      // The empty prefix matches both records — must not approve either.
      expect(approveRequest('', { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
      expect(consumeApproval('Bash', OTHER, { home, now: T0 })).toBeNull();
    });

    it('treats a corrupt store as empty, not as approval', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      rmSync(file);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });
  });

  // ── #143 — deny is exactly as cheap as approve ──────────────────────────────
  // The notification transport (operator-notify.ts) offers BOTH an approve and
  // a deny affordance for the same hash, one tap each. `denyRequest` is the
  // store-level half of "deny": it does not invent a second approval concept —
  // it is the sibling of `approveRequest` on the SAME one-shot record, so every
  // property #118 already proved (exact-hash binding, no self-service, no
  // resurrection) applies to a deny exactly as it does to an approve.
  describe('denyRequest (#143 — deny is as cheap as approve)', () => {
    it('denies a pending request; the exact call is never approved', () => {
      const pending = request();
      const outcome = denyRequest(shortHash(pending.hash), { home, now: T0 });
      expect(outcome.ok).toBe(true);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('a denied hash cannot later be approved — deny is final, not a hold', () => {
      const pending = request();
      denyRequest(pending.hash, { home, now: T0 });
      expect(approveRequest(pending.hash, { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('an approved hash cannot then be denied — the human already spoke', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      expect(denyRequest(pending.hash, { home, now: T0 })).toEqual({ ok: false, reason: 'already-approved' });
      // The approval survives the rejected deny attempt.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });

    it('reports not-found for an unknown hash', () => {
      request();
      expect(denyRequest('deadbeef', { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
    });

    it('refuses an ambiguous prefix rather than guessing which one to deny', () => {
      request(SUDO);
      request(OTHER);
      expect(denyRequest('', { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
      // Neither record was collaterally denied.
      const a = approveRequest(hashToolCall('Bash', SUDO), { home, now: T0 });
      expect(a.ok).toBe(true);
    });

    it('does not carry over to a different command on the same tool', () => {
      request(SUDO);
      const otherPending = request(OTHER, T0 + 1);
      denyRequest(otherPending.hash, { home, now: T0 + 1 });
      // SUDO is untouched — still approvable.
      expect(approveRequest(hashToolCall('Bash', SUDO), { home, now: T0 + 1 }).ok).toBe(true);
    });

    it('a second deny of the same hash reports not-found, not a double-deny', () => {
      const pending = request();
      expect(denyRequest(pending.hash, { home, now: T0 }).ok).toBe(true);
      expect(denyRequest(pending.hash, { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
    });

    it('does not leave a denied record on disk — one-shot, like a consumed one', () => {
      const pending = request();
      denyRequest(pending.hash, { home, now: T0 });
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      expect(JSON.parse(readFileSync(file, 'utf-8')).records).toEqual([]);
    });

    it('a retried request after a deny starts a fresh pending record', () => {
      const pending = request();
      denyRequest(pending.hash, { home, now: T0 });
      // The agent (or operator re-running the same op) tries again later.
      const retried = request(SUDO, T0 + 5_000);
      expect(retried.hash).toBe(pending.hash);
      expect(retried.approvedAt).toBeUndefined();
      expect(listApprovals({ home, now: T0 + 5_000 })).toHaveLength(1);
    });
  });

  describe('storage hygiene', () => {
    it('writes the store 0600 — it names commands the operator ran', () => {
      request();
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      expect(existsSync(file)).toBe(true);
      expect(statSync(file).mode & 0o777).toBe(0o600);
    });

    it('does not accumulate duplicate records for a retried command', () => {
      request();
      request(SUDO, T0 + 5_000);
      request(SUDO, T0 + 10_000);
      expect(listApprovals({ home, now: T0 + 10_000 })).toHaveLength(1);
    });

    it('drops the consumed record from the file', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      consumeApproval('Bash', SUDO, { home, now: T0 });
      const file = join(home, '.shieldcortex', 'approvals', 'approvals.json');
      expect(JSON.parse(readFileSync(file, 'utf-8')).records).toEqual([]);
    });
  });

  describe('CLI gate — an agent cannot approve its own command', () => {
    const sink = () => {
      const lines: string[] = [];
      return { lines, write: (m: string) => { lines.push(m); } };
    };

    it('refuses to grant when stdio is not a TTY', () => {
      const pending = request();
      const out = sink();
      const code = runApprove([pending.hash], { home, now: T0, interactive: false, log: out.write, error: out.write });

      expect(code).toBe(1);
      expect(out.lines.join('\n')).toMatch(/interactive terminal/i);
      // Crucially, nothing was granted.
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('grants when a human is at the keyboard', () => {
      const pending = request();
      const out = sink();
      const code = runApprove([pending.hash], { home, now: T0, interactive: true, log: out.write, error: out.write });

      expect(code).toBe(0);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });

    it('lists outstanding refusals without needing a TTY', () => {
      request();
      const out = sink();
      const code = runApprove([], { home, now: T0, interactive: false, log: out.write, error: out.write });

      expect(code).toBe(0);
      expect(out.lines.join('\n')).toContain('sudo modprobe softdog');
    });

    it('rejects a nonsense --ttl instead of silently defaulting', () => {
      const pending = request();
      const out = sink();
      const code = runApprove([pending.hash, '--ttl', 'soon'], { home, now: T0, interactive: true, log: out.write, error: out.write });

      expect(code).toBe(1);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('isInteractive requires BOTH stdin and stdout to be TTYs', () => {
      expect(isInteractive({ stdin: { isTTY: true }, stdout: { isTTY: true } })).toBe(true);
      expect(isInteractive({ stdin: { isTTY: true }, stdout: { isTTY: false } })).toBe(false);
      expect(isInteractive({ stdin: { isTTY: false }, stdout: { isTTY: true } })).toBe(false);
      expect(isInteractive({})).toBe(false);
    });
  });

  // `shieldcortex deny <hash>` — the CLI half of denyRequest, mirroring
  // approve.ts's TTY gate. An agent that could non-interactively deny its own
  // pending request could wipe a suspicious refusal from the operator's queue
  // before they ever saw it existed — denial is the safe DECISION direction,
  // but self-service erasure of the evidence is not, so the same gate applies.
  describe('CLI deny gate (#143) — one tap, same discipline as approve', () => {
    const sink = () => {
      const lines: string[] = [];
      return { lines, write: (m: string) => { lines.push(m); } };
    };

    it('refuses to deny when stdio is not a TTY', () => {
      const pending = request();
      const out = sink();
      const code = runDeny([pending.hash], { home, now: T0, interactive: false, log: out.write, error: out.write });

      expect(code).toBe(1);
      expect(out.lines.join('\n')).toMatch(/interactive terminal/i);
      // Still there to approve or deny later — the CLI gate didn't touch it.
      expect(approveRequest(pending.hash, { home, now: T0 }).ok).toBe(true);
    });

    it('denies when a human is at the keyboard, one tap', () => {
      const pending = request();
      const out = sink();
      const code = runDeny([pending.hash], { home, now: T0, interactive: true, log: out.write, error: out.write });

      expect(code).toBe(0);
      expect(approveRequest(pending.hash, { home, now: T0 })).toEqual({ ok: false, reason: 'not-found' });
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).toBeNull();
    });

    it('reports a clear error for an unknown hash rather than silently succeeding', () => {
      const out = sink();
      const code = runDeny(['deadbeef'], { home, now: T0, interactive: true, log: out.write, error: out.write });
      expect(code).toBe(1);
      expect(out.lines.join('\n')).toMatch(/no pending/i);
    });

    it('refuses to deny an already-approved request rather than revoking it', () => {
      const pending = request();
      approveRequest(pending.hash, { home, now: T0 });
      const out = sink();
      const code = runDeny([pending.hash], { home, now: T0, interactive: true, log: out.write, error: out.write });
      expect(code).toBe(1);
      expect(consumeApproval('Bash', SUDO, { home, now: T0 })).not.toBeNull();
    });
  });
});

// ── The store must be self-protected (#118 review finding, 31 Jul 2026) ──────
// The TTY gate stops `shieldcortex approve` running non-interactively, but the
// store is a plain 0600 JSON file owned by the same user the agent runs as.
// Without a guard rule, the agent mints its own approval with one benign-looking
// write. Any command naming the store path must reach the operator.
describe('approval store is inside the guard perimeter', () => {
  const gate = (command: string) => evaluateToolCall('Bash', { command });

  it('gates a direct edit of approvals.json', () => {
    const v = gate(`python3 -c "import json;p='/home/u/.shieldcortex/approvals/approvals.json';d=json.load(open(p));d['records'][0]['approvedAt']=1;json.dump(d,open(p,'w'))"`);
    expect(v.action).not.toBe('allow');
    expect(v.signals).toContain('touch-approval-store');
  });

  it('gates shell redirection into the store', () => {
    const v = gate(`echo '{"version":1,"records":[]}' > ~/.shieldcortex/approvals/approvals.json`);
    expect(v.action).not.toBe('allow');
    expect(v.signals).toContain('touch-approval-store');
  });

  it('gates deleting the store (wiping pending evidence)', () => {
    const v = gate('rm ~/.shieldcortex/approvals/approvals.json');
    expect(v.signals).toContain('touch-approval-store');
    expect(v.action).not.toBe('allow');
  });

  it('does not fire on unrelated .shieldcortex reads', () => {
    const v = gate('cat ~/.shieldcortex/config.json');
    expect(v.signals).not.toContain('touch-approval-store');
  });
});

describe('#183 — only reviewed non-exec command surfaces strip advisory fields', () => {
  const SCRIPT = 'await $`git push --force origin main`;';

  it('Workflow.script hashes per command, not per re-worded attempt', () => {
    const first = hashToolCall('Workflow', { script: SCRIPT, description: 'Publish the release branch' });
    const retry = hashToolCall('Workflow', { script: SCRIPT, description: 'Ship the hotfix now' });
    expect(retry).toBe(first);
  });

  it('does not treat Workflow.input as an approved command contract', () => {
    const first = hashToolCall('Workflow', { input: SCRIPT, description: 'Payload A' });
    const changed = hashToolCall('Workflow', { input: SCRIPT, description: 'Payload B' });
    expect(changed).not.toBe(first);
  });

  it('does not infer command semantics from an unknown tool script field', () => {
    const first = hashToolCall('UnknownWidget', { script: SCRIPT, description: 'Payload A' });
    const changed = hashToolCall('UnknownWidget', { script: SCRIPT, description: 'Payload B' });
    expect(changed).not.toBe(first);
  });

  it.each(['code', 'input'] as const)('keeps create_issue description bound beside a %s payload', (field) => {
    const first = hashToolCall('create_issue', { title: 'Bug', [field]: SCRIPT, description: 'Body A' });
    const changed = hashToolCall('create_issue', { title: 'Bug', [field]: SCRIPT, description: 'Body B' });
    expect(changed).not.toBe(first);
  });

  it('the command itself still decides the hash', () => {
    const a = hashToolCall('Workflow', { script: SCRIPT, description: 'x' });
    const b = hashToolCall('Workflow', { script: 'await $`git push origin main`;', description: 'x' });
    expect(b).not.toBe(a);
  });

  it('still strips for a genuinely exec-named tool (#201 unchanged)', () => {
    const a = hashToolCall('Bash', { command: 'git push', description: 'one' });
    const b = hashToolCall('Bash', { command: 'git push', description: 'two' });
    expect(b).toBe(a);
  });

  it('keeps description bound when there is no reviewed command surface', () => {
    // An issue/PR body is the payload: approving one text must never release
    // another. This is the boundary #201 drew and it must survive.
    const a = hashToolCall('create_issue', { title: 'Bug', description: 'Steps to reproduce: A' });
    const b = hashToolCall('create_issue', { title: 'Bug', description: 'Steps to reproduce: B' });
    expect(b).not.toBe(a);
  });

  it('confinement flags still move the hash on a command-carrying tool', () => {
    // An approval for the sandboxed form must not release the unsandboxed one.
    const safe = hashToolCall('Workflow', { script: SCRIPT, dangerouslyDisableSandbox: false });
    const unsafe = hashToolCall('Workflow', { script: SCRIPT, dangerouslyDisableSandbox: true });
    expect(unsafe).not.toBe(safe);
  });

  it('the live store path spends a Workflow.script approval after description is re-worded', () => {
    const now = 1_800_000_000_000;
    const home = mkdtempSync(join(tmpdir(), 'sc-approvals-183-live-'));
    try {
      const first = { script: SCRIPT, description: 'Publish the release branch' };
      const retry = { script: SCRIPT, description: 'Ship the hotfix now' };
      const pending = recordPending(
        { tool: 'Workflow', input: first, summary: 'Workflow: release script', signals: ['exec-like'] },
        { home, now },
      );
      expect(approveRequest(shortHash(pending.hash), { home, now: now + 1000 }).ok).toBe(true);
      expect(consumeApproval('Workflow', retry, { home, now: now + 2000 })).not.toBeNull();
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  });
});
