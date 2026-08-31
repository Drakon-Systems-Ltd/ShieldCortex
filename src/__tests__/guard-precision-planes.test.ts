import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import type { Request, Response } from 'express';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';
import {
  GUARD_PRECISION_CORPUS,
  type GuardCorpusEntry,
} from '../defence/iron-dome/guard-precision-corpus.js';
import { createInterceptor, DEFAULT_CONFIG } from '../../plugins/openclaw/interceptor.js';

/**
 * Phase B / PR 6 — precision corpus across all three planes.
 *
 * #182 already holds evaluateToolCall to 100% allow-on-SAFE / gate-on-DANGEROUS.
 * A fleet with three different gates is three products. This file replays the
 * same corpus through:
 *   - core evaluateToolCall
 *   - Claude pre-tool hook (stdin as PreToolUse delivers it)
 *   - OpenClaw interceptor (before_tool_call payload)
 *   - Hermes REST (POST /api/v1/action-guard — the only evaluateToolCall
 *     surface the Python plugin can call)
 * and fails the build on any decision or signal-set mismatch.
 *
 * The hook's audit writer redacts unknown signal names (SAFE_SIGNALS). The
 * classifier verdict is recovered from the hook's permissionDecision, which
 * is a 1:1 map of evaluateToolCall.decision. Signals are compared on the
 * interceptor wrap and the Hermes REST body, which both see the raw verdict.
 */

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK_PATH = path.join(REPO, 'scripts', 'pre-tool-hook.mjs');
const DIST_GUARD = path.join(REPO, 'dist', 'defence', 'iron-dome', 'tool-action-guard.js');
const HERMES_INIT = path.join(REPO, 'plugins', 'hermes', 'shieldcortex', '__init__.py');
const HERMES_CLIENT = path.join(REPO, 'plugins', 'hermes', 'shieldcortex', 'sc_client.py');

type PlaneDecision = 'allow' | 'require_approval' | 'block';
interface PlaneVerdict {
  decision: PlaneDecision;
  signals: string[];
}

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 },
  sensitivity: { level: 'INTERNAL' },
  fragmentation: null,
  auditId: 1,
});

function summarise(v: { decision: string; signals: string[] }): PlaneVerdict {
  if (v.decision !== 'allow' && v.decision !== 'require_approval' && v.decision !== 'block') {
    throw new Error(`unexpected decision ${v.decision}`);
  }
  return { decision: v.decision, signals: [...v.signals].sort() };
}

function sameSignals(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const as = [...a].sort();
  const bs = [...b].sort();
  return as.every((s, i) => s === bs[i]);
}

async function interceptorPlane(entry: GuardCorpusEntry): Promise<PlaneVerdict> {
  let seen: { decision: string; signals: string[] } | undefined;
  const interceptor = createInterceptor(
    { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] }, logger: { info: () => {}, warn: () => {} } } as never,
    okPipeline as never,
    {
      evaluateToolCall: (tool, args, config, options) => {
        const v = evaluateToolCall(tool, args, config as never, options);
        seen = v;
        return v;
      },
    },
  );
  try {
    await interceptor.handleToolCall({ toolName: entry.tool, arguments: entry.args });
  } catch {
    // deny / unattended require_approval throw; the classifier verdict is `seen`.
  }
  if (!seen) throw new Error(`interceptor did not call evaluateToolCall for ${entry.args.command}`);
  return summarise(seen);
}

function runHook(payload: unknown, env: NodeJS.ProcessEnv): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env,
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += String(c); });
    child.stderr.on('data', (c) => { stderr += String(c); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

async function hookPlane(entry: GuardCorpusEntry, homesRoot: string, distRoot: string): Promise<PlaneVerdict> {
  // Fresh HOME per call. Sharing one tree across 160 hook processes lets
  // pending-approval / session-guard state from an earlier row change a later
  // verdict (observed: `npm install -g` flipped ask → deny).
  const home = fs.mkdtempSync(path.join(homesRoot, 'h-'));
  fs.mkdirSync(path.join(home, '.shieldcortex'), { recursive: true });
  fs.writeFileSync(
    path.join(home, '.shieldcortex', 'config.json'),
    JSON.stringify({ actionGuard: { enabled: true, enforce: true } }),
  );

  const { stdout, code } = await runHook(
    {
      session_id: 'planes-corpus',
      cwd: '/tmp',
      permission_mode: 'default',
      hook_event_name: 'PreToolUse',
      tool_name: entry.tool,
      tool_input: entry.args,
    },
    {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      SHIELDCORTEX_DIST_ROOT: distRoot,
      // Lease/DECISIONS store uses os.homedir() unless this is set — HOME
      // alone still reads the operator's live leases (pid 30065 held `install`).
      SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex'),
    },
  );
  if (code !== 0) {
    throw new Error(`hook exited ${code} for ${entry.args.command}`);
  }

  if (!stdout.trim()) {
    return { decision: 'allow', signals: [] };
  }
  const parsed = JSON.parse(stdout) as {
    hookSpecificOutput?: { permissionDecision?: string };
  };
  const pd = parsed.hookSpecificOutput?.permissionDecision;
  let decision: PlaneDecision;
  if (pd === 'deny') decision = 'block';
  else if (pd === 'ask') decision = 'require_approval';
  else {
    throw new Error(`hook unexpected permissionDecision ${pd} for ${entry.args.command}`);
  }

  // Fallback path is not evaluateToolCall — that is a plane lie, not a match.
  const auditDir = path.join(home, '.shieldcortex', 'audit');
  if (fs.existsSync(auditDir)) {
    const file = fs.readdirSync(auditDir).find((n) => /^realtime-.*\.jsonl$/.test(n));
    if (file) {
      const lines = fs.readFileSync(path.join(auditDir, file), 'utf8').trim().split('\n').filter(Boolean);
      const last = lines.length > 0 ? JSON.parse(lines[lines.length - 1]) as { firewallResult?: string } : null;
      if (last?.firewallResult === 'ACTION_GUARD_FALLBACK') {
        throw new Error(`hook used fallback, not evaluateToolCall, for ${entry.args.command}`);
      }
    }
  }
  return { decision, signals: [] };
}

function mockRes(): { res: Response; body: () => Record<string, unknown> } {
  let payload: Record<string, unknown> = {};
  const json = (j: Record<string, unknown>) => { payload = j; };
  const status = (_code: number) => ({ json: (j: Record<string, unknown>) => { payload = { status: _code, ...j }; } });
  return { res: { status, json } as unknown as Response, body: () => payload };
}

async function hermesPlane(entry: GuardCorpusEntry): Promise<PlaneVerdict> {
  const mod = await import('../api/visualization-server.js');
  const handle = (mod as { handleV1ActionGuard?: (req: Request, res: Response) => void }).handleV1ActionGuard;
  if (typeof handle !== 'function') {
    throw new Error('POST /api/v1/action-guard is missing — Hermes has no evaluateToolCall surface');
  }
  const { res, body } = mockRes();
  handle({ body: { tool: entry.tool, args: entry.args } } as Request, res);
  const got = body();
  if (typeof got.status === 'number' && got.status >= 400) {
    throw new Error(`action-guard HTTP ${got.status} for ${entry.args.command}: ${JSON.stringify(got)}`);
  }
  if (got.decision !== 'allow' && got.decision !== 'require_approval' && got.decision !== 'block') {
    throw new Error(`action-guard returned ${JSON.stringify(got.decision)} for ${entry.args.command}`);
  }
  const signals = Array.isArray(got.signals) ? got.signals.map(String) : [];
  return summarise({ decision: got.decision, signals });
}

describe('three-plane precision — same evaluateToolCall verdict on every runtime', () => {
  let homesRoot: string;

  beforeAll(() => {
    if (!fs.existsSync(DIST_GUARD)) {
      throw new Error(`missing ${DIST_GUARD} — run npm run build:ts before the planes gate`);
    }
    homesRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-planes-'));
  });

  afterAll(() => {
    if (homesRoot) fs.rmSync(homesRoot, { recursive: true, force: true });
  });

  it('Hermes plugin calls Action Guard, not the content scanner, on pre_tool_call', () => {
    const init = fs.readFileSync(HERMES_INIT, 'utf8');
    const client = fs.readFileSync(HERMES_CLIENT, 'utf8');
    expect(client).toMatch(/\/api\/v1\/action-guard/);
    expect(init).toMatch(/evaluate_tool_call/);
    expect(init).not.toMatch(/verdict = scan\(/);
  });

  it('0 decision mismatches and 0 signal-set mismatches across planes', async () => {
    const mismatches: Array<Record<string, unknown>> = [];

    for (const entry of GUARD_PRECISION_CORPUS) {
      const core = summarise(evaluateToolCall(entry.tool, entry.args));
      const interceptor = await interceptorPlane(entry);
      const hook = await hookPlane(entry, homesRoot, path.join(REPO, 'dist'));
      let hermes: PlaneVerdict | { error: string };
      try {
        hermes = await hermesPlane(entry);
      } catch (err) {
        hermes = { error: err instanceof Error ? err.message : String(err) };
      }

      const label = String(entry.args.command ?? JSON.stringify(entry.args));
      if (interceptor.decision !== core.decision || !sameSignals(interceptor.signals, core.signals)) {
        mismatches.push({ plane: 'openclaw-interceptor', command: label, core, interceptor });
      }
      if (hook.decision !== core.decision) {
        mismatches.push({ plane: 'claude-code-hook', command: label, coreDecision: core.decision, hookDecision: hook.decision });
      }
      if ('error' in hermes) {
        mismatches.push({ plane: 'hermes', command: label, core, error: hermes.error });
      } else if (hermes.decision !== core.decision || !sameSignals(hermes.signals, core.signals)) {
        mismatches.push({ plane: 'hermes', command: label, core, hermes });
      }
    }

    // eslint-disable-next-line no-console
    console.log(
      `[planes] corpus=${GUARD_PRECISION_CORPUS.length} mismatches=${mismatches.length}`,
    );
    expect(mismatches).toEqual([]);
  }, 180_000);
});
