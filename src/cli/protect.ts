/**
 * `shieldcortex protect` — write the OS-owned policy lock (#501).
 *
 * The one privileged act in ShieldCortex, and deliberately the only one: a
 * human, once, as root, pins the security-critical subset of the config to a
 * file the agent uid cannot write. Everything after that is ordinary
 * unprivileged operation reading a file it cannot change.
 *
 * Refusing without root is not a formality. The whole value of the lock is that
 * the process which writes it is not the process which reads it; a `protect`
 * that fell back to writing somewhere the agent could reach would produce an
 * artefact that looks like a lock, reads like a lock, and protects nothing.
 */
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join } from 'path';
import { randomBytes } from 'crypto';

import {
  DEFAULT_DEFENCE_MODE,
  DEFAULT_PROTECTED_ROOT,
  POLICY_LOCK_FILENAME,
  PROTECT_HINT,
  PROTECTED_POLICY_KEYS_V1,
  describePolicyLock,
  readPolicyLock,
  type LockedPolicy,
} from '../defence/iron-dome/policy-lock.js';
import { normaliseReviewedScripts } from '../defence/iron-dome/reviewed-scripts.js';
import {
  defaultProtectedFsSeam,
  resolveProtectedRoot,
  verifyProtectedDirectoryChain,
  verifyProtectedFile,
  type ProtectedFileVerdict,
  type ProtectedFsSeam,
  type ProtectedRootResolution,
} from '../defence/iron-dome/protected-root.js';

export interface ProtectOptions {
  /** Print what would be written and exit without touching the filesystem. */
  dryRun: boolean;
  /**
   * Pin exactly what config.json says, including an Action Guard that is OFF.
   *
   * Without it, `protect` does not read config.json AT ALL and pins the safe
   * posture (#522, GPT-6 round-6, item 3): a command called `protect` that
   * quietly froze the guard in the OFF position because that happened to be
   * today's config would be a trap — and one that carried today's same-UID
   * `autoApprove`, broker, `defenceMode` or memory values into the root-owned
   * lock would let the agent uid choose its own future ceiling. The lock is a
   * FLOOR — pinning the safe posture never stops an operator making it stricter.
   */
  fromConfig: boolean;
  /** Read the source config from here instead of the resolved default. */
  sourceConfig?: string;
  /**
   * The uid the AGENT runs as, stated explicitly (`--agent-uid <uid>`).
   *
   * Every check in this file is judged as that uid. `SUDO_UID` supplies it when
   * present; a privileged invocation without `SUDO_UID` (a system service, or
   * an already-privileged shell) has no source for it, and `protect` refuses
   * rather than guess (#522, Tars r7, P1). Kept as the raw argument so a
   * malformed value is refused by name.
   */
  agentUid?: string;
}

export function parseProtectArgs(args: string[]): ProtectOptions {
  const idx = args.indexOf('--config');
  const uidIdx = args.indexOf('--agent-uid');
  return {
    dryRun: args.includes('--dry-run'),
    fromConfig: args.includes('--from-config'),
    sourceConfig: idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('--') ? args[idx + 1] : undefined,
    // A missing value (a trailing `--agent-uid`) is kept as '' so it is refused
    // as malformed rather than silently ignored.
    agentUid: uidIdx !== -1 ? (args[uidIdx + 1] ?? '') : undefined,
  };
}

function isBlock(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Where to read the operator's current config from.
 *
 * A privileged run gives us the superuser's HOME, so the default resolution
 * would read that account's config — almost always absent. The operator means
 * THEIR config, and `SUDO_USER` is how the shell tells us whose. An explicit
 * `--config` always wins, and `SHIELDCORTEX_CONFIG_DIR` is honoured ahead of
 * the guess because an operator who set it meant it.
 */
export function resolveSourceConfigPath(opts: ProtectOptions): string {
  if (opts.sourceConfig) return opts.sourceConfig;
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  if (override) return join(override, 'config.json');
  const invokingUser = process.env.SUDO_USER?.trim();
  if (invokingUser && invokingUser !== 'root') {
    // No getpwnam in Node; the conventional home is the right guess, and a
    // missing file falls through to defaults rather than to junk.
    for (const base of ['/home', '/Users']) {
      const candidate = join(base, invokingUser, '.shieldcortex', 'config.json');
      if (existsSync(candidate)) return candidate;
    }
  }
  return join(homedir(), '.shieldcortex', 'config.json');
}

/**
 * The policy a flag-less `shieldcortex protect` pins, with no config consulted.
 *
 * #522 (GPT-6 round-6, item 3). Item A had already stopped the default run
 * carrying a same-UID `reviewedScripts` list into the lock; the same argument
 * applied to every other pinned key and the code only made it for that one.
 * `autoApprove` and `broker.enabled` came straight out of config.json, and so
 * did `defenceMode` and the memory posture — so a same-UID process that
 * seeded a dangerous `autoApprove` entry and `broker.enabled: true` before the
 * operator's one privileged run got those values into a root-owned file
 * whose whole purpose is to be the thing that uid cannot choose.
 *
 * Every value here is the tighter end of its key's own order: the guard on
 * and enforcing, both ceilings empty, the broker off, the `defenceMode` FLOOR
 * at the product default (config may still raise it to `strict`). `memory` is
 * deliberately NOT pinned: it has no tightness order, only one legal posture
 * value, and an `inject.mode` pin of `off` would be a behaviour change rather
 * than a floor — so a lock that invented one would be pinning a value the
 * operator never chose. `--from-config` is the only path that pins it.
 */
export function safeDefaultPolicy(): LockedPolicy {
  return {
    version: 1,
    actionGuard: { enabled: true, enforce: true, autoApprove: [], broker: { enabled: false }, reviewedScripts: [] },
    defenceMode: DEFAULT_DEFENCE_MODE,
  };
}

/**
 * Build the policy to pin.
 *
 * Without `--from-config` the raw config is ignored entirely — see
 * {@link safeDefaultPolicy}. With it, the config's own values are pinned for
 * every protected key, including an Action Guard that is OFF. Keys the config
 * never mentions are left out: a lock does not have to have an opinion about
 * everything, and one that invented a `memory` posture nobody configured would
 * be pinning a value the operator never chose.
 */
export function buildLockedPolicy(raw: Record<string, unknown>, opts: ProtectOptions): LockedPolicy {
  if (!opts.fromConfig) return safeDefaultPolicy();

  const guardTop = isBlock(raw.actionGuard) ? raw.actionGuard : {};
  const alias = isBlock(raw.interceptor) && isBlock(raw.interceptor.actionGuard) ? raw.interceptor.actionGuard : {};
  // The same #209 merge every other surface applies: top-level wins, alias gap-fills.
  const guard = { ...alias, ...guardTop };

  const actionGuard: NonNullable<LockedPolicy['actionGuard']> = {
    enabled: guard.enabled === true,
    enforce: guard.enforce !== false,
    autoApprove: Array.isArray(guard.autoApprove)
      ? (guard.autoApprove as unknown[]).filter((e): e is string => typeof e === 'string')
      : [],
    broker: { enabled: isBlock(guard.broker) ? guard.broker.enabled === true : false },
    // #522 item A: a reviewed-script entry is a path+hash pair pinning trust in
    // a FILE'S CONTENTS; it reaches the lock only through this explicit opt-in.
    reviewedScripts: normaliseReviewedScripts(guard.reviewedScripts),
  };
  const policy: LockedPolicy = { version: 1, actionGuard };

  if (typeof raw.defenceMode === 'string' && ['strict', 'balanced', 'permissive'].includes(raw.defenceMode)) {
    policy.defenceMode = raw.defenceMode as LockedPolicy['defenceMode'];
  }

  const memory = isBlock(raw.memory) ? raw.memory : null;
  const posture = memory && isBlock(memory.hostContract) ? memory.hostContract.posture : undefined;
  const injectMode = memory && isBlock(memory.inject) ? memory.inject.mode : undefined;
  if (typeof posture === 'string' || typeof injectMode === 'string') {
    policy.memory = {};
    if (typeof posture === 'string') policy.memory.hostContract = { posture };
    if (typeof injectMode === 'string') policy.memory.inject = { mode: injectMode };
  }

  return policy;
}

function coversKey(policy: LockedPolicy, key: (typeof PROTECTED_POLICY_KEYS_V1)[number]): boolean {
  switch (key) {
    case 'actionGuard.enabled': return policy.actionGuard?.enabled !== undefined;
    case 'actionGuard.enforce': return policy.actionGuard?.enforce !== undefined;
    case 'actionGuard.autoApprove': return policy.actionGuard?.autoApprove !== undefined;
    case 'actionGuard.broker.enabled': return policy.actionGuard?.broker?.enabled !== undefined;
    case 'actionGuard.reviewedScripts': return policy.actionGuard?.reviewedScripts !== undefined;
    case 'defenceMode': return policy.defenceMode !== undefined;
    case 'memory.hostContract.posture': return policy.memory?.hostContract?.posture !== undefined;
    case 'memory.inject.mode': return policy.memory?.inject?.mode !== undefined;
  }
}

export interface ProtectResult {
  /** Process exit code. */
  code: number;
  lines: string[];
}

/**
 * Which uid the lock is FOR — resolved, never guessed (#522, Tars r7, P1).
 *
 * A privileged process is the wrong reader: the real verifier answers
 * `running-as-root` for every path, which is correct for a running agent and
 * useless as a check of the lock we are writing. So every check in this file
 * runs against a seam reporting the unprivileged uid the lock is for — and that
 * uid has to be KNOWN. The previous seam fell back to `nobody` (65534) when
 * `SUDO_UID` was absent, which is exactly the state a system service or an
 * already-privileged shell is in. Judged as nobody, an agent-owned 0755
 * directory is "owned by another uid": the lock was written there, reported
 * protected, and the directory's owner could replace it.
 *
 * Precedence: `--agent-uid` (explicit), then `SUDO_UID` (which records who
 * invoked the privileged run), then — only when this process is itself
 * unprivileged, i.e. a `--dry-run` by the agent user — this process's own uid.
 * Privileged with no source is refused before anything is resolved or written;
 * a uid of 0 from any source is refused too, because an agent with no
 * same-host boundary cannot be locked.
 */
export type AgentUidResolution =
  | { ok: true; uid: number; source: 'flag' | 'env' | 'self'; via: string }
  | { ok: false; detail: string };

function parseUid(raw: string): number | null {
  return /^\d{1,10}$/.test(raw) ? Number.parseInt(raw, 10) : null;
}

function currentEuid(): number | null {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

export function resolveAgentUid(
  opts: Pick<ProtectOptions, 'agentUid'>,
  env: NodeJS.ProcessEnv = process.env,
  euid: number | null = currentEuid(),
): AgentUidResolution {
  if (opts.agentUid !== undefined) {
    const uid = parseUid(opts.agentUid);
    if (uid === null) {
      return { ok: false, detail: `--agent-uid ${JSON.stringify(opts.agentUid)} is not a uid (expected a non-negative integer).` };
    }
    if (uid === 0) {
      return { ok: false, detail: '--agent-uid 0 names uid 0; an agent with no same-host boundary cannot be locked.' };
    }
    return { ok: true, uid, source: 'flag', via: 'from --agent-uid' };
  }
  // The env var can name whoever launched this run rather than this run's own
  // identity — a targeted launch, or a value inherited from an unrelated
  // earlier context, leaves it set while this process is really someone else.
  // It only means what it says while this process's own identity is elevated
  // and so cannot answer the question itself. When this process's own identity
  // is already ordinary, that direct reading always outranks the env var
  // (review of #522 Tars r7).
  if (euid !== null && euid !== 0) {
    return { ok: true, uid: euid, source: 'self', via: "this process's own uid; pass --agent-uid if the agent runs as another user" };
  }
  if (env.SUDO_UID !== undefined) {
    const uid = parseUid(env.SUDO_UID);
    if (uid === null) {
      return { ok: false, detail: `SUDO_UID=${JSON.stringify(env.SUDO_UID)} is not a uid; pass --agent-uid <uid> explicitly.` };
    }
    if (uid === 0) {
      return { ok: false, detail: 'SUDO_UID is 0 (the invoking shell was already elevated), which says nothing about the agent; pass --agent-uid <uid>.' };
    }
    return { ok: true, uid, source: 'env', via: 'from SUDO_UID' };
  }
  return {
    ok: false,
    detail: euid === null
      ? 'this runtime exposes no effective uid, and neither SUDO_UID nor --agent-uid names one.'
      : 'running with no SUDO_UID (a system service, or an already-elevated shell), so nothing says which uid ' +
        "the agent runs as; pass --agent-uid <uid> with the agent user's numeric uid.",
  };
}

/** The seam every check in this file is judged through: the agent's uid, not ours. */
function agentSeam(agentUid: number): ProtectedFsSeam {
  return { ...defaultProtectedFsSeam(), geteuid: () => agentUid };
}

function verifyAsAgent(path: string, agentUid: number): ReturnType<typeof verifyProtectedFile> {
  return verifyProtectedFile(path, agentSeam(agentUid));
}

/**
 * Verify the DESTINATION before anything is created there (#522, GPT-6
 * round-6, item 2).
 *
 * `protect` used to mkdir, chmod, write and rename first and ask
 * {@link verifyAsAgent} afterwards. The post-write check is honest about the
 * result, but by then a privileged process had already created directories,
 * dropped a file and chmodded a directory at a path whose ancestry the AGENT
 * uid controls — on that uid's terms (a symlinked or agent-writable root is
 * exactly the shape `verifyProtectedDirectoryChain` exists to refuse). The
 * lock cannot yet be verified as a file, because it does not exist; what CAN
 * be verified is the directory chain it will land in, from the deepest
 * ancestor that exists up to `/`, under the same rules the runtime reader
 * applies. A chain that fails here would fail the post-write check too, so
 * refusing now loses nothing and touches nothing.
 *
 * Judged as the agent, like every other check in this file. The CLI passes the
 * seam built from the resolved agent uid; the unit tests inject their own.
 */
export function preflightLockDestination(lockPath: string, seam: ProtectedFsSeam): ProtectedFileVerdict {
  const euid = seam.geteuid();
  if (euid === null) {
    return { ok: false, reason: 'euid-unavailable', detail: 'This runtime exposes no effective uid, so ownership cannot be compared.' };
  }
  const existing = seam.lstat(lockPath);
  if (existing !== null && existing.isDirectory) {
    return { ok: false, reason: 'not-regular-file', detail: `${lockPath} is a directory; refusing to replace it.` };
  }
  // The deepest EXISTING directory on the lexical chain. `protect` may be
  // creating the protected root itself, in which case the chain that decides
  // who could replace it starts at the root's first existing ancestor.
  let dir = dirname(lockPath);
  for (;;) {
    if (seam.lstat(dir) !== null) break;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return verifyProtectedDirectoryChain(dir, euid, seam);
}

/**
 * Resolve the root the AGENT will read — which is the only root worth writing.
 *
 * Same seam, same reason as {@link verifyAsAgent}, and the #501 review's
 * SHOULD-FIX-6. `protect`'s real mode is privileged, and privileged is exactly
 * the mode in which `resolveProtectedRoot()` answers `running-as-root`, so the
 * old code fell through to `DEFAULT_PROTECTED_ROOT` every time and never
 * consulted the pointer file. `readPolicyLockInner` DOES honour the pointer,
 * unconditionally and in preference to the default — so on a pointer host a
 * privileged `shieldcortex protect` wrote `/etc/shieldcortex/policy.json`,
 * printed uid/mode evidence and a green verify, and the runtime went on reading
 * the old lock at the pointed-to path. The new lock was inert and the operator
 * was told it was not.
 *
 * The unprivileged (`--dry-run`) path resolves through the same function, so
 * what the dry run prints is what the privileged write does.
 */
function resolveRootForProtect(seam: ProtectedFsSeam): ProtectedRootResolution {
  return resolveProtectedRoot(seam);
}

/**
 * The source config, read for `--from-config` only — and only if it is
 * actually there, a plain file the same account wrote, and parseable.
 *
 * This read runs with elevated rights, at a path built from the operator's
 * OWN account (`resolveSourceConfigPath`) — an account that fully controls
 * what lands there. Reading it unconditionally would follow a symlink dropped
 * at that same path to any other file readable by this process, elevated
 * rights included, and a parse failure's message can surface a fragment of
 * whatever got read. `lstat`, not `stat`: refusing before the link is ever
 * opened, not after. The failure text below never repeats what the parser
 * said, so nothing read from an unexpected target reaches the operator either
 * way.
 */
function readSourceConfig(sourcePath: string): { ok: true; raw: Record<string, unknown> } | { ok: false; detail: string } {
  let st: ReturnType<typeof lstatSync>;
  try {
    st = lstatSync(sourcePath);
  } catch {
    return { ok: false, detail: 'there is no config there.' };
  }
  if (st.isSymbolicLink()) {
    return { ok: false, detail: 'it is a symlink, and an elevated read only follows a plain file the operator actually wrote.' };
  }
  if (!st.isFile()) {
    return { ok: false, detail: 'it is not a plain file.' };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(sourcePath, 'utf-8'));
  } catch {
    return { ok: false, detail: 'it could not be parsed as JSON.' };
  }
  if (!isBlock(parsed)) return { ok: false, detail: 'it is not a JSON object.' };
  return { ok: true, raw: parsed };
}

export function runProtect(args: string[] = []): ProtectResult {
  const opts = parseProtectArgs(args);
  const lines: string[] = [];

  // #522 (Tars r7, P1): who the lock is for is decided first, and decided
  // explicitly. Nothing below is resolved, judged or written for a guessed uid.
  const agent = resolveAgentUid(opts);
  if (!agent.ok) {
    lines.push(`Refusing to write the policy lock: cannot tell which uid the agent runs as — ${agent.detail}`);
    if (!opts.dryRun) lines.push('Nothing was written.');
    lines.push("The lock is judged for the AGENT's uid; judged for a guessed one, an agent-owned directory reads as protected.");
    return { code: 1, lines };
  }
  const seam = agentSeam(agent.uid);

  const root = resolveRootForProtect(seam);
  if (!root.supported && root.reason !== 'running-as-root') {
    // Running privileged is the NORMAL state for `protect` itself. The resolver
    // refuses that state because an AGENT running privileged has no boundary,
    // which is a different question. Only win32 / no-euid genuinely block us.
    lines.push(`Cannot write a policy lock here: ${root.detail}`);
    return { code: 1, lines };
  }
  const protectedRoot = root.supported ? root.root : DEFAULT_PROTECTED_ROOT;
  const lockPath = join(protectedRoot, POLICY_LOCK_FILENAME);

  // #522 (GPT-6 round-6, item 3): the same-UID config is read ONLY when the
  // operator asked for its values. A flag-less run pins the safe posture and
  // never opens the file, so nothing in it can reach the lock.
  //
  // And when it IS asked for, it has to be there (#522, Tars r7, P2). With the
  // source absent or unparseable the old code carried on with `{}`, and an
  // empty config maps to an Action Guard that is OFF — so a privileged run
  // printed "pinning defaults" and froze the guard off. The safe posture is
  // one flag away; an explicit request for values that do not exist is refused.
  let raw: Record<string, unknown> = {};
  if (opts.fromConfig) {
    const sourcePath = resolveSourceConfigPath(opts);
    const source = readSourceConfig(sourcePath);
    if (!source.ok) {
      lines.push(`Refusing to write the policy lock: --from-config pins the values in ${sourcePath}, and ${source.detail}`);
      if (!opts.dryRun) lines.push('Nothing was written.');
      lines.push(
        'A config that says nothing has the Action Guard OFF, so "defaults" here would freeze it off. ' +
        'Run protect without --from-config to pin the safe posture instead.',
      );
      return { code: 1, lines };
    }
    raw = source.raw;
    lines.push(`Pinning the values in ${sourcePath} verbatim (--from-config).`);
  } else {
    lines.push('Pinning the safe posture; config.json is not read (add --from-config to pin its values instead).');
    if (opts.sourceConfig) lines.push('Note: --config is only read together with --from-config.');
  }

  const policy = buildLockedPolicy(raw, opts);
  const body = `${JSON.stringify(policy, null, 2)}\n`;
  const pinned = PROTECTED_POLICY_KEYS_V1.filter((k) => coversKey(policy, k)).join(', ');

  lines.push(`Judging the destination as agent uid ${agent.uid} (${agent.via}).`);

  if (opts.dryRun) {
    lines.push(`Would write ${lockPath}, owned by uid 0, mode 0644, in a uid-0 0755 directory:`);
    lines.push(body.trimEnd());
    lines.push('');
    lines.push(`Pinned keys: ${pinned}`);
    lines.push('config.json may only TIGHTEN these; it can never loosen them.');
    const preflight = preflightLockDestination(lockPath, seam);
    lines.push(preflight.ok
      ? `Destination ${dirname(lockPath)} verifies for the agent: ${preflight.detail}`
      : `WARNING: the real write would be REFUSED — ${dirname(lockPath)} would not verify for the agent: ${preflight.detail}`);
    return { code: 0, lines };
  }

  const euid = typeof process.geteuid === 'function' ? process.geteuid() : null;
  if (euid !== 0) {
    lines.push('Refusing to write the policy lock: this process is not privileged.');
    lines.push(
      "The lock only means anything because the agent's uid cannot write it. Writing it as uid " +
      `${euid ?? 'unknown'} would produce a file that looks like a lock and protects nothing.`,
    );
    lines.push(`${PROTECT_HINT}. Add --dry-run to see exactly what it would write first.`);
    return { code: 1, lines };
  }

  // #522 (GPT-6 round-6, item 2): the destination is judged BEFORE the first
  // mutation. Everything below this line creates, chmods, writes or renames.
  const preflight = preflightLockDestination(lockPath, seam);
  if (!preflight.ok) {
    lines.push(`Refusing to write the policy lock: ${dirname(lockPath)} would not verify for the agent — ${preflight.detail}`);
    lines.push(
      'Nothing was written. A lock in a directory chain the agent uid could replace would protect nothing; ' +
      'make that chain root-owned, not group- or other-writable, with no agent-owned symlinks, and re-run.',
    );
    return { code: 1, lines };
  }

  try {
    if (!existsSync(protectedRoot)) mkdirSync(protectedRoot, { recursive: true, mode: 0o755 });
    chmodSync(protectedRoot, 0o755);
  } catch (err) {
    lines.push(`Could not create ${protectedRoot}: ${(err as Error).message}`);
    return { code: 1, lines };
  }

  // Atomic replace, like writeRawConfig: a reader must never see a half-written
  // policy, and a failed write must leave the previous lock intact.
  const tmp = `${lockPath}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  try {
    writeFileSync(tmp, body, { mode: 0o644 });
    chmodSync(tmp, 0o644);
    renameSync(tmp, lockPath);
  } catch (err) {
    try { if (existsSync(tmp)) rmSync(tmp, { force: true }); } catch { /* best-effort */ }
    lines.push(`Could not write ${lockPath}: ${(err as Error).message}`);
    return { code: 1, lines };
  }

  const verdict = verifyAsAgent(lockPath, agent.uid);
  if (!verdict.ok) {
    // Written, but it will not verify for the agent — say so loudly rather than
    // report success. An unverifiable lock forces the strict posture, so the box
    // is safe; it is the operator's expectation that would be wrong.
    lines.push(`WROTE ${lockPath}, but it will NOT verify for the agent: ${verdict.detail}`);
    lines.push('The agent falls back to the strict fail-closed posture. Fix the ownership or permissions and re-run.');
    return { code: 1, lines };
  }

  const fileStat = statSync(lockPath);
  const dirStat = statSync(dirname(lockPath));
  lines.push(`Policy lock written: ${lockPath}`);
  lines.push(
    `  owner uid ${fileStat.uid}, mode 0${(fileStat.mode & 0o777).toString(8)}; ` +
    `directory ${dirname(lockPath)} owner uid ${dirStat.uid}, mode 0${(dirStat.mode & 0o777).toString(8)}`,
  );
  lines.push(`  pinned: ${pinned}`);
  lines.push('');
  lines.push('config.json may only TIGHTEN these keys from now on. A loosening write is refused, and a lock that is');
  lines.push('later corrupted or replaced by a same-user file forces the strict fail-closed posture.');
  lines.push('Check it any time with `shieldcortex config --policy-status` or `shieldcortex doctor`.');
  return { code: 0, lines };
}

/** `shieldcortex config --policy-status` — what the lock is, in words. */
export function policyStatusLines(): string[] {
  const state = readPolicyLock({ audit: false, warn: false });
  const summary = describePolicyLock(state);
  const lines = [`Policy lock: ${summary.headline}`];
  if (summary.path) lines.push(`  file: ${summary.path}`);
  if (summary.covered.length > 0) {
    lines.push('  pinned:');
    for (const { key, value } of summary.covered) lines.push(`    ${key} = ${JSON.stringify(value)}`);
  }
  switch (summary.status) {
    case 'locked':
      lines.push('  config.json may TIGHTEN these keys; it cannot loosen them.');
      break;
    case 'unverifiable':
      lines.push('  The strict fail-closed posture is in force: Action Guard on + enforcing, no auto-approve,');
      lines.push('  broker off, defence mode strict.');
      lines.push(`  ${PROTECT_HINT} to write a valid lock, or remove the file to run unlocked.`);
      break;
    case 'absent':
      lines.push('  Any process running as this user can switch the Action Guard off by editing config.json.');
      lines.push(`  ${PROTECT_HINT} to pin the security-critical keys to a file this user cannot write.`);
      break;
    case 'unsupported':
      lines.push('  Nothing to configure: a same-host ownership boundary does not exist here.');
      break;
  }
  return lines;
}
