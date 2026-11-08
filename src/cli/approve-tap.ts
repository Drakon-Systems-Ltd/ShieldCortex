/**
 * `shieldcortex guard approve-tap` — host the loopback `POST /approve-tap`
 * endpoint for one-tap approve (#815 B), or `--check` whether it can arm.
 *
 *   sudo shieldcortex guard approve-tap --home /home/agent --agent-uid 1001 --bridge-uid 1002
 *
 * ## Why its own tiny server, and why it stays root
 *
 * The only existing local HTTP host is the dashboard API, which runs as the
 * agent's user — and the approve secret must NOT be readable by that user.
 * A process running as the agent's user that holds the key is no better:
 * the agent may signal it, and SIGUSR1 opens Node's inspector inside it.
 *
 * So the process that holds the key stays root for its whole life (the
 * agent cannot signal, trace or debug a root process). It reads the
 * bridge-owned 0600 secret, checks every tap's shape, HMAC and approver
 * itself, and only then hands the AUTHENTICATED request to a short-lived
 * child spawned as the agent's user (`approve-tap-child.js`: uid/gid set by
 * the spawn, empty environment, `--disable-sigusr1`). The child has no key;
 * it does the nonce and grant checks and writes, so every store file stays
 * owned exactly as `shieldcortex approve --denial` would own it.
 *
 * Both uids come from this command line, never from config.json (which the
 * agent can edit): the agent's uid must own `<home>/.shieldcortex`, and the
 * secret's owner must be the bridge's uid.
 *
 * It refuses to start, with a plain-English reason, when not root, when
 * started with any spelling of a Node inspector option (argv or NODE_OPTIONS,
 * parsed as Node parses it), when an inspector is actually open in the
 * process, or when the tap path cannot arm — all before the secret is read.
 */

import { lstatSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  authenticateApproveTap,
  checkApproveTapArming,
  createApproveTapHandler,
  loadApproveTapSecret,
  normaliseApproveTapConfig,
  APPROVE_TAP_PATH,
  type ApproveTapConfig,
  type ApproveTapRequest,
  type TapArmingDeps,
  type TapHandlerAnswer,
  type TapSecretDeps,
} from '../defence/iron-dome/approve-tap.js';
import type { TapChildAnswer, TapChildInput } from '../defence/iron-dome/approve-tap-child.js';

const CHILD_TIMEOUT_MS = 10_000;

function readConfigBlock(configPath: string): { approveTap: ApproveTapConfig; webhookSecret?: string } {
  let raw: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(readFileSync(configPath, 'utf8')) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) raw = parsed as Record<string, unknown>;
  } catch {
    /* missing / unreadable / corrupt → everything off */
  }
  const isBlock = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
  const interceptor = isBlock(raw.interceptor) ? raw.interceptor : {};
  const alias = isBlock(interceptor.actionGuard) ? interceptor.actionGuard : {};
  const top = isBlock(raw.actionGuard) ? raw.actionGuard : {};
  const merged = { ...alias, ...top };
  const notify = isBlock(merged.notify) ? merged.notify : {};
  return {
    approveTap: normaliseApproveTapConfig(merged.approveTap),
    ...(typeof notify.webhookSecret === 'string' ? { webhookSecret: notify.webhookSecret } : {}),
  };
}

/**
 * NODE_OPTIONS split the way Node itself splits it (ParseNodeOptionsEnvVar):
 * a space separates options, a double-quoted run is part of one option,
 * and inside quotes a backslash makes the next character literal. Null when
 * a quote is left open (Node refuses to start on that; so do we).
 */
export function tokeniseNodeOptions(nodeOptions: string): string[] | null {
  const out: string[] = [];
  let cur = '';
  let inString = false;
  let started = false;
  for (let i = 0; i < nodeOptions.length; i += 1) {
    const c = nodeOptions[i];
    if (c === '\\' && inString) {
      if (i + 1 >= nodeOptions.length) return null;
      cur += nodeOptions[i + 1];
      i += 1;
      started = true;
    } else if (c === '"') {
      inString = !inString;
    } else if (c === ' ' && !inString) {
      if (started) out.push(cur);
      cur = '';
      started = false;
    } else {
      cur += c;
      started = true;
    }
  }
  if (inString) return null;
  if (started) out.push(cur);
  return out;
}

/** True for any option Node would read as an inspector/debugger option:
 *  `--inspect`, `--inspect-brk`, `--inspect-wait`, `--inspect-port`,
 *  `--debug-port` and every other `--inspect*` / `--debug*` name, in either
 *  spelling (Node treats `_` and `-` in option names alike). */
function isInspectorOption(token: string): boolean {
  if (!token.startsWith('--')) return false;
  const name = token.slice(2).split('=')[0].replace(/_/g, '-');
  return /^(?:inspect|debug)/.test(name);
}

/** Any way of starting Node that asks for an inspector the agent could reach. */
export function inspectorRequested(execArgv: readonly string[], nodeOptions: string | undefined): boolean {
  if (execArgv.some(isInspectorOption)) return true;
  if (nodeOptions === undefined || nodeOptions === '') return false;
  const tokens = tokeniseNodeOptions(nodeOptions);
  return tokens === null || tokens.some(isInspectorOption);
}

/**
 * Is an inspector actually open in THIS process right now? The ground truth
 * whatever the spelling that opened it. Fails closed: if the inspector
 * module cannot be loaded on a Node that has one, the answer is "open".
 */
export async function inspectorActive(): Promise<boolean> {
  try {
    const inspector = await import('node:inspector');
    return inspector.url() !== undefined;
  } catch {
    return (process as { features?: { inspector?: boolean } }).features?.inspector !== false;
  }
}

export interface TapChildRun {
  uid: number;
  gid: number;
  input: TapChildInput;
  /** Test seam: the built child entry. Default: beside this module in dist. */
  childPath?: string;
}

/** Spawn the keyless child as the agent and return its one-line answer. */
export function spawnTapChild(run: TapChildRun): TapHandlerAnswer {
  const childPath = run.childPath ?? fileURLToPath(new URL('../defence/iron-dome/approve-tap-child.js', import.meta.url));
  const res = spawnSync(process.execPath, ['--disable-sigusr1', childPath], {
    uid: run.uid,
    gid: run.gid,
    input: JSON.stringify(run.input),
    env: {},
    cwd: '/',
    timeout: CHILD_TIMEOUT_MS,
    maxBuffer: 64 * 1024,
    stdio: ['pipe', 'pipe', 'ignore'],
  });
  const fallback: TapHandlerAnswer = { ok: false, reason: 'unwritable', message: 'The approvals store could not be written. Nothing was approved.' };
  if (res.error || res.status !== 0) return fallback;
  try {
    const answer = JSON.parse(String(res.stdout).trim().split('\n').pop() ?? '') as TapChildAnswer;
    if (answer && answer.ok === true && typeof answer.message === 'string' && typeof answer.approver === 'string') {
      return { ok: true, message: answer.message, approver: answer.approver };
    }
    if (answer && answer.ok === false && typeof answer.reason === 'string' && typeof answer.message === 'string') {
      return { ok: false, reason: answer.reason, message: answer.message };
    }
  } catch {
    /* fall through */
  }
  return fallback;
}

export interface ApproveTapCommandDeps {
  log?: (m: string) => void;
  error?: (m: string) => void;
  geteuid?: () => number | null;
  execArgv?: readonly string[];
  nodeOptions?: string;
  /** Test seam: is an inspector open in this process? Default: `inspectorActive`. */
  inspectorActive?: () => boolean | Promise<boolean>;
  /** lstat of `<home>/.shieldcortex`. */
  lstatHome?: (p: string) => { uid: number; gid: number; isDirectory: boolean; isSymbolicLink: boolean };
  /** Arming / loading seams (tests run as one user). */
  armingLstat?: TapArmingDeps['lstat'];
  openSecret?: TapSecretDeps['openSecret'];
  runChild?: (run: TapChildRun) => TapHandlerAnswer;
  /** Test seam: listen and return instead of waiting for the server to close. */
  listen?: (server: Server, port: number) => Promise<void>;
  onServer?: (server: Server) => void;
}

function asUid(v: string | undefined): number | null {
  return v !== undefined && /^[0-9]{1,10}$/.test(v) ? Number(v) : null;
}

export async function runApproveTapCommand(argv: string[], deps: ApproveTapCommandDeps = {}): Promise<number> {
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));
  const homeAt = argv.indexOf('--home');
  const homeArg = homeAt >= 0 ? argv[homeAt + 1] : undefined;
  if (!homeArg || homeArg.startsWith('--') || !homeArg.startsWith('/')) {
    err('--home expects the agent user\'s home directory as an absolute path, e.g. --home /home/agent');
    return 1;
  }
  const agentUidAt = argv.indexOf('--agent-uid');
  const agentUid = asUid(agentUidAt >= 0 ? argv[agentUidAt + 1] : undefined);
  const bridgeUidAt = argv.indexOf('--bridge-uid');
  const bridgeUid = asUid(bridgeUidAt >= 0 ? argv[bridgeUidAt + 1] : undefined);
  if (typeof agentUid !== 'number' || typeof bridgeUid !== 'number') {
    err('--agent-uid <uid> and --bridge-uid <uid> are required: the user the agent runs as, and the notify '
      + 'bridge\'s own user that owns the approve secret. They are read from this command line, never from config.');
    return 1;
  }
  if (agentUid === 0 || bridgeUid === 0 || agentUid === bridgeUid) {
    err('--agent-uid and --bridge-uid must be two different unprivileged users. If the agent and the bridge share a '
      + 'user, one-tap approve cannot be made safe; use the #501 OS lock (`sudo shieldcortex protect`) and approve '
      + 'from a terminal: `shieldcortex approve --denial <actionId>`.');
    return 1;
  }

  const scHome = join(homeArg, '.shieldcortex');
  let agentGid: number;
  try {
    const st = (deps.lstatHome ?? ((p: string) => {
      const s = lstatSync(p);
      return { uid: s.uid, gid: s.gid, isDirectory: s.isDirectory(), isSymbolicLink: s.isSymbolicLink() };
    }))(scHome);
    if (st.isSymbolicLink || !st.isDirectory) {
      err(`${scHome} is not a real directory; refusing.`);
      return 1;
    }
    if (st.uid !== agentUid) {
      err(`${scHome} is owned by uid ${st.uid}, not --agent-uid ${agentUid}; refusing.`);
      return 1;
    }
    agentGid = st.gid;
  } catch {
    err(`No ShieldCortex home at ${scHome}.`);
    return 1;
  }

  const { approveTap, webhookSecret } = readConfigBlock(join(scHome, 'config.json'));
  const arming = checkApproveTapArming(approveTap, { agentUid, ...(deps.armingLstat ? { lstat: deps.armingLstat } : {}) });
  if (argv.includes('--check')) {
    (arming.armed ? log : err)(arming.message);
    return arming.armed ? 0 : 1;
  }
  if (!arming.armed) {
    err(arming.message);
    return 1;
  }

  const euid = (deps.geteuid ?? (() => (typeof process.geteuid === 'function' ? process.geteuid() : null)))();
  if (euid !== 0) {
    err('The tap endpoint must be started as root: it keeps the approve secret in a process the agent\'s user cannot '
      + 'signal or debug, and runs each grant as the agent\'s user.');
    return 1;
  }
  // Both checks come BEFORE the secret is opened.
  if (inspectorRequested(deps.execArgv ?? process.execArgv, deps.nodeOptions ?? process.env.NODE_OPTIONS)) {
    err('Refusing to hold the approve secret in a process started with a Node inspector flag.');
    return 1;
  }
  if (await (deps.inspectorActive ?? inspectorActive)()) {
    err('Refusing to hold the approve secret: a Node inspector is open in this process.');
    return 1;
  }

  const loaded = loadApproveTapSecret(approveTap, {
    agentUid,
    bridgeUid,
    ...(webhookSecret !== undefined ? { webhookSecret } : {}),
    ...(deps.openSecret ? { openSecret: deps.openSecret } : {}),
  });
  if (!loaded.ok) {
    err(loaded.message);
    return 1;
  }
  const key = loaded.key;
  const runChild = deps.runChild ?? spawnTapChild;

  const handler = createApproveTapHandler({
    verify: (body): TapHandlerAnswer => {
      const auth = authenticateApproveTap(body, {
        config: approveTap, key, agentUid, ...(deps.armingLstat ? { lstat: deps.armingLstat } : {}),
      });
      if (!auth.ok) return auth.refusal;
      const request: ApproveTapRequest = auth.request;
      return runChild({ uid: agentUid, gid: agentGid, input: { request, home: homeArg, expectUid: agentUid, expectGid: agentGid } });
    },
    log: (line) => err(`[shieldcortex] ${new Date().toISOString()} ${line}`),
  });
  const server = createServer(handler);
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  deps.onServer?.(server);
  const listen = deps.listen ?? ((s: Server, port: number) => new Promise<void>((resolve, reject) => {
    s.once('error', reject);
    s.listen(port, '127.0.0.1', () => resolve());
  }));
  try {
    await listen(server, approveTap.port);
  } catch {
    err(`Could not listen on 127.0.0.1:${approveTap.port} (is something else already using it?).`);
    return 1;
  }
  log(`[shieldcortex] one-tap approve listening on http://127.0.0.1:${approveTap.port}${APPROVE_TAP_PATH} (loopback only); grants run as uid ${agentUid}.`);
  if (deps.listen) return 0;
  await new Promise<void>((resolve) => server.once('close', () => resolve()));
  return 0;
}
