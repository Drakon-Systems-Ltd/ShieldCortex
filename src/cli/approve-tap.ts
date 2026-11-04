/**
 * `shieldcortex guard approve-tap` — host the loopback `POST /approve-tap`
 * endpoint for one-tap approve (#815 B), or `--check` whether it can arm.
 *
 * Why its own tiny server, not the dashboard API: the API server runs as the
 * agent's user, and the approve secret must NOT be readable by that user (a
 * same-UID agent could read the key and approve itself). So the endpoint
 * starts as root, opens the bridge-owned 0600 secret, then drops to the
 * agent's user — the owner of `<home>/.shieldcortex`, so the grant it writes
 * is owned exactly as `shieldcortex approve --denial` would own it — and only
 * then listens, on 127.0.0.1 only. After the drop the key exists only in this
 * process's memory; Linux marks a process that changed uid non-dumpable, so
 * the agent's user cannot ptrace it or read its memory.
 *
 * It refuses to start, with a plain-English reason, when:
 *   - the tap path cannot arm (same-UID secret, mode wider than 0600, no
 *     approver, root agent, …) — see `checkApproveTapArming`;
 *   - it is not root and so cannot both read the secret and write the
 *     agent's grant store.
 */

import { readFileSync, statSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { homedir } from 'node:os';
import { join } from 'node:path';

import { getConfigDir } from '../cloud/config.js';
import {
  checkApproveTapArming,
  createApproveTapHandler,
  loadApproveTapSecret,
  normaliseApproveTapConfig,
  verifyApproveTap,
  APPROVE_TAP_PATH,
  type ApproveTapConfig,
} from '../defence/iron-dome/approve-tap.js';

export interface ProcessIdentityOps {
  geteuid: () => number;
  getuid: () => number;
  setgroups: (groups: number[]) => void;
  setgid: (gid: number) => void;
  setuid: (uid: number) => void;
}

export type TapPrivilegePlan =
  | { action: 'drop'; uid: number; gid: number }
  | { action: 'refuse'; message: string };

/**
 * What the endpoint must do with its own identity before it listens. Only
 * one shape is allowed to serve: started as root, dropping to the agent.
 */
export function planTapServerPrivileges(input: { euid: number | null; agentUid: number; agentGid: number }): TapPrivilegePlan {
  if (input.euid === null) {
    return { action: 'refuse', message: 'This host has no user ids; the tap endpoint cannot run here.' };
  }
  if (input.agentUid === 0) {
    return { action: 'refuse', message: 'The ShieldCortex home is owned by root, so the agent runs as root. One-tap approve cannot be made safe there.' };
  }
  if (input.euid === 0) return { action: 'drop', uid: input.agentUid, gid: input.agentGid };
  if (input.euid === input.agentUid) {
    return {
      action: 'refuse',
      message: 'The tap endpoint is running as the agent\'s own user. If this process can read the approve secret, '
        + 'so can the agent. Start it as root; it drops to the agent\'s user after reading the secret.',
    };
  }
  return {
    action: 'refuse',
    message: `The tap endpoint is running as uid ${input.euid}, which cannot write the agent's grant store. `
      + 'Start it as root; it drops to the agent\'s user after reading the secret.',
  };
}

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

export interface ApproveTapCommandDeps {
  log?: (m: string) => void;
  error?: (m: string) => void;
  proc?: ProcessIdentityOps;
  /** Test seam: start nothing, return the server instead of waiting on it. */
  listen?: (server: Server, port: number) => Promise<void>;
}

function defaultProc(): ProcessIdentityOps | undefined {
  if (typeof process.geteuid !== 'function' || typeof process.setuid !== 'function'
    || typeof process.setgid !== 'function' || typeof process.setgroups !== 'function'
    || typeof process.getuid !== 'function') return undefined;
  return {
    geteuid: () => process.geteuid!(),
    getuid: () => process.getuid!(),
    setgroups: (g) => process.setgroups!(g),
    setgid: (g) => process.setgid!(g),
    setuid: (u) => process.setuid!(u),
  };
}

export async function runApproveTapCommand(argv: string[], deps: ApproveTapCommandDeps = {}): Promise<number> {
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));
  const homeAt = argv.indexOf('--home');
  const homeArg = homeAt >= 0 ? argv[homeAt + 1] : undefined;
  if (homeAt >= 0 && (!homeArg || homeArg.startsWith('--'))) {
    err('--home expects the agent user\'s home directory, e.g. --home /home/agent');
    return 1;
  }
  const home = homeArg ?? homedir();
  const configPath = homeArg ? join(homeArg, '.shieldcortex', 'config.json') : join(getConfigDir(), 'config.json');
  const { approveTap, webhookSecret } = readConfigBlock(configPath);

  // The agent's uid is the owner of its ShieldCortex home: that is the user
  // the guard hook runs as and the owner of the grant store.
  let agentUid: number;
  let agentGid: number;
  try {
    const st = statSync(join(home, '.shieldcortex'));
    agentUid = st.uid;
    agentGid = st.gid;
  } catch {
    err(`No ShieldCortex home at ${join(home, '.shieldcortex')}. Pass --home <the agent user's home>.`);
    return 1;
  }

  const arming = checkApproveTapArming(approveTap, { agentUid });
  if (argv.includes('--check')) {
    (arming.armed ? log : err)(arming.message);
    return arming.armed ? 0 : 1;
  }
  if (!arming.armed) {
    err(arming.message);
    return 1;
  }

  const proc = deps.proc ?? defaultProc();
  const plan = planTapServerPrivileges({ euid: proc ? proc.geteuid() : null, agentUid, agentGid });
  if (plan.action === 'refuse') {
    err(plan.message);
    return 1;
  }

  const loaded = loadApproveTapSecret(approveTap, { agentUid, ...(webhookSecret !== undefined ? { webhookSecret } : {}) });
  if (!loaded.ok) {
    err(loaded.message);
    return 1;
  }
  const key = loaded.key;

  // Drop BEFORE listening and before touching the grant store.
  try {
    proc!.setgroups([agentGid]);
    proc!.setgid(agentGid);
    proc!.setuid(agentUid);
  } catch {
    err('Could not drop to the agent\'s user; refusing to serve.');
    return 1;
  }
  if (proc!.geteuid() !== agentUid || proc!.getuid() !== agentUid) {
    err('The privilege drop did not take effect; refusing to serve.');
    return 1;
  }

  const handler = createApproveTapHandler({
    verify: (body) => verifyApproveTap(body, { config: approveTap, key, home, agentUid }),
    log: (line) => err(`[shieldcortex] ${new Date().toISOString()} ${line}`),
  });
  const server = createServer(handler);
  server.headersTimeout = 5_000;
  server.requestTimeout = 5_000;
  const listen = deps.listen ?? ((s: Server, port: number) => new Promise<void>((resolve, reject) => {
    s.once('error', reject);
    s.listen(port, '127.0.0.1', () => resolve());
  }));
  try {
    await listen(server, approveTap.port);
  } catch {
    err(`Could not listen on 127.0.0.1:${approveTap.port}.`);
    return 1;
  }
  log(`[shieldcortex] one-tap approve listening on http://127.0.0.1:${approveTap.port}${APPROVE_TAP_PATH} (loopback only), as uid ${agentUid}.`);
  if (deps.listen) return 0;
  await new Promise<void>((resolve) => server.once('close', () => resolve()));
  return 0;
}
