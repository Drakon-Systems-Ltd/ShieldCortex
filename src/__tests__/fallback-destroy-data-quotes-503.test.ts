/**
 * #503 outage parity (review R2 on #626): the destroy-data-or-infra row counts
 * an opening quote as a command start, so `bash -c '…'` and `ssh host '…'`
 * wrappers are seen. The real guard then drops a match that lies inside a
 * quoted argument of a data command (`grep`, `echo`, `git commit -m`, …); the
 * three outage fallbacks had no such step and gated the first raw match. So
 * `grep -F "<teardown>" RUNBOOK.md` was allowed with the guard up and denied
 * (OpenClaw) or sent for approval (Claude Code) with the guard down.
 *
 * Pins, on the REAL interceptor and the REAL hook with an empty dist:
 *  - wrapper and plain teardowns still gate while degraded;
 *  - inert quoted mentions fail open, exactly as `git status` does;
 *  - the normal guard agrees on every mention.
 *
 * Fixtures are assembled at run time (#444 convention) so this file is not
 * itself a dangerous payload to the guard that protects this repo. Nothing
 * here is executed as a shell command.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../../plugins/openclaw/interceptor.js';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.join(REPO, 'scripts', 'pre-tool-hook.mjs');

const TF = 'terra' + 'form ' + 'des' + 'troy';
const KD = 'kube' + 'ctl ' + 'del' + 'ete namespace prod';
const HU = 'helm ' + 'unin' + 'stall';
const PSQL = 'ps' + 'ql -c ';
const DROP = 'DR' + 'OP TABLE users';

const GATE: Array<[string, string]> = [
  ['plain', `${TF} -auto-approve`],
  ['bash -c wrapper', `bash -c "${TF} -auto-approve"`],
  ['sh -c wrapper, single quotes', `sh -c '${KD}'`],
  ['ssh remote wrapper', `ssh db1 '${KD}'`],
  ['echo piped into a shell', `echo "${TF}" | bash`],
  ['piped into sudo with a flag', `echo "${TF}" | sudo -E bash`],
  ['piped into a quoted shell name', `echo "${TF}" | "bash"`],
  ['piped into an escaped shell name', `echo "${TF}" | b\\ash`],
  ['piped through a filter, then a shell', `echo "${TF}" | tr a a | sh`],
  ['a command word that only starts like a data command', `ptpython -c "${TF}"`],
  ['mention, then a real run', `grep -F "${TF}" RUNBOOK.md; ${TF}`],
  ['quoted mention inside a substitution', `echo "$(${TF})"`],
  ['psql with a quoted statement', `${PSQL}"${DROP}"`],
  ['an unclosed quote is not data', `echo "x; ${TF}`],
  ['eval re-runs the quoted text', `eval "${TF}"`],
];

const PASS: Array<[string, string]> = [
  ['grep a runbook', `grep -F "${TF}" RUNBOOK.md`],
  ['echo a warning', `echo "${TF}"`],
  ['grep for the namespace delete', `grep -F "${KD}" RUNBOOK.md`],
  ['echo helm', `echo "${HU}"`],
  ['commit message', `git commit -m "${KD}: handle the 404"`],
  ['single-quoted grep', `grep -n '${HU}' docs/ops.md`],
  ['a separator inside the quoted text', `echo "step 2; ${TF}"`],
  ['text flag on a non-executor', `gh pr create --title "${TF} runbook"`],
  ['piped into a read-only filter', `grep -F "${TF}" RUNBOOK.md | head -5`],
  ['or-list after the grep', `grep -qF "${TF}" RUNBOOK.md || echo missing`],
  ['control: git status', 'git status'],
];

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

describe('#503 R2 — OpenClaw interceptor fallback: quoted data is not a teardown', () => {
  const run = (command: string) => {
    const entries: InterceptAuditEntry[] = [];
    // No evaluateToolCall wired = guard unavailable. No requireApproval = unattended.
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, { onAuditEntry: (e) => entries.push(e) });
    return { p: i.handleToolCall({ toolName: 'Bash', arguments: { command } }), entries };
  };

  it.each(GATE)('gates %s while degraded', async (_name, command) => {
    const { p, entries } = run(command);
    await expect(p).rejects.toThrow(/blocked|fallback|degraded|policy/i);
    const denied = entries.find((e) => e.outcome === 'auto_denied' || e.outcome === 'failure_denied');
    expect(denied?.firewallResult).toBe('ACTION_GUARD_FALLBACK');
  });

  it.each(PASS)('fails open on %s while degraded', async (_name, command) => {
    const { p, entries } = run(command);
    await expect(p).resolves.toBeUndefined();
    expect(entries.find((e) => e.action === 'gate_degraded')?.outcome).toBe('failure_allowed');
  });
});

describe('#503 R2 — Claude Code hook fallback: quoted data is not a teardown', () => {
  const originalHome = process.env.HOME;
  let tempHome: string;
  let emptyDist: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-503-q-'));
    emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-503-dist-'));
    process.env.HOME = tempHome;
    fs.mkdirSync(path.join(tempHome, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(path.join(tempHome, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });
  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
    fs.rmSync(emptyDist, { recursive: true, force: true });
  });

  function runHook(command: string): Promise<{ stdout: string; code: number }> {
    return new Promise((res, rej) => {
      const child = spawn(process.execPath, [HOOK_PATH], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env,
          HOME: tempHome,
          SHIELDCORTEX_DIST_ROOT: emptyDist,
          SHIELDCORTEX_CONFIG_DIR: path.join(tempHome, '.shieldcortex'),
        },
      });
      let stdout = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.on('error', rej);
      child.on('close', (code) => res({ stdout, code: code ?? 0 }));
      child.stdin.write(JSON.stringify({ permission_mode: 'default', tool_name: 'Bash', tool_input: { command } }));
      child.stdin.end();
    });
  }

  it.each(GATE)('gates %s while degraded', async (_name, command) => {
    const { stdout, code } = await runHook(command);
    expect(code).toBe(0);
    expect(['ask', 'deny']).toContain(JSON.parse(stdout).hookSpecificOutput.permissionDecision);
  });

  it.each(PASS)('fails open on %s while degraded', async (_name, command) => {
    const { stdout, code } = await runHook(command);
    expect(code).toBe(0);
    expect(stdout).toBe('');
  });
});

describe('#503 R2 — the normal guard agrees on every mention', () => {
  it.each(PASS)('%s is not a teardown to the real guard', (_name, command) => {
    expect(evaluateToolCall('Bash', { command }).signals ?? []).not.toContain('destroy-data-or-infra');
  });
});

describe('#503 R2 — the hook and the interceptor carry the same quoted-data rule', () => {
  // The two JS copies are kept in lockstep by hand; the Hermes port is pinned
  // behaviourally by DestroyRowDataQuoteTests on the same cases.
  const consts = (file: string): string[] => fs.readFileSync(path.join(REPO, file), 'utf-8').split('\n')
    .filter((l) => /^const FALLBACK_(?:DATA_COMMAND_RE|TEXT_FLAG_RE|EXEC_WORD_RE|UNSAFE_PIPE_RE|QUOTE_PREFIX_CAP|INERT_MATCH_CAP) =/.test(l));

  it('same constants, and the row is tagged on both', () => {
    const hook = consts('scripts/pre-tool-hook.mjs');
    expect(hook).toHaveLength(6);
    expect(hook).toEqual(consts('plugins/openclaw/interceptor.ts'));
    for (const f of ['scripts/pre-tool-hook.mjs', 'plugins/openclaw/interceptor.ts']) {
      expect(fs.readFileSync(path.join(REPO, f), 'utf-8')).toContain("signal: 'destroy-data-or-infra', dataQuotes: true }");
    }
  });
});
