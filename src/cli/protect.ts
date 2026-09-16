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
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { dirname, join } from 'path';
import { randomBytes } from 'crypto';

import {
  DEFAULT_PROTECTED_ROOT,
  POLICY_LOCK_FILENAME,
  PROTECT_HINT,
  PROTECTED_POLICY_KEYS_V1,
  describePolicyLock,
  readPolicyLock,
  type LockedPolicy,
} from '../defence/iron-dome/policy-lock.js';
import {
  defaultProtectedFsSeam,
  resolveProtectedRoot,
  verifyProtectedFile,
  type ProtectedFsSeam,
} from '../defence/iron-dome/protected-root.js';

export interface ProtectOptions {
  /** Print what would be written and exit without touching the filesystem. */
  dryRun: boolean;
  /**
   * Pin exactly what config.json says, including an Action Guard that is OFF.
   *
   * Without it, `protect` pins `enabled: true, enforce: true` regardless: a
   * command called `protect` that quietly froze the guard in the OFF position
   * because that happened to be today's config would be a trap, and the lock is
   * a FLOOR — pinning the guard on never stops an operator making it stricter.
   */
  fromConfig: boolean;
  /** Read the source config from here instead of the resolved default. */
  sourceConfig?: string;
}

export function parseProtectArgs(args: string[]): ProtectOptions {
  const idx = args.indexOf('--config');
  return {
    dryRun: args.includes('--dry-run'),
    fromConfig: args.includes('--from-config'),
    sourceConfig: idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith('--') ? args[idx + 1] : undefined,
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
 * Build the policy to pin from a raw config object.
 *
 * Reads the config's own values for every protected key, then — unless
 * `--from-config` — forces the two Action Guard master switches on. Keys the
 * config never mentions are left out: a lock does not have to have an opinion
 * about everything, and one that invented a `memory` posture nobody configured
 * would be pinning a value the operator never chose.
 */
export function buildLockedPolicy(raw: Record<string, unknown>, opts: ProtectOptions): LockedPolicy {
  const guardTop = isBlock(raw.actionGuard) ? raw.actionGuard : {};
  const alias = isBlock(raw.interceptor) && isBlock(raw.interceptor.actionGuard) ? raw.interceptor.actionGuard : {};
  // The same #209 merge every other surface applies: top-level wins, alias gap-fills.
  const guard = { ...alias, ...guardTop };

  const actionGuard: NonNullable<LockedPolicy['actionGuard']> = {
    enabled: opts.fromConfig ? guard.enabled === true : true,
    enforce: opts.fromConfig ? guard.enforce !== false : true,
    autoApprove: Array.isArray(guard.autoApprove)
      ? (guard.autoApprove as unknown[]).filter((e): e is string => typeof e === 'string')
      : [],
    broker: { enabled: isBlock(guard.broker) ? guard.broker.enabled === true : false },
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
 * Verify the artefact we just wrote the way the AGENT will read it.
 *
 * A privileged process is the wrong reader: the real verifier answers
 * `running-as-root` for every path, which is correct for a running agent and
 * useless as a post-write check. So the check runs against a seam reporting the
 * unprivileged uid this lock is FOR (`SUDO_UID`, else nobody). That is not a
 * weakened check — it is the only way to assert the property that matters, that
 * the file just written will verify for the user the agent runs as.
 */
function verifyAsAgent(path: string): ReturnType<typeof verifyProtectedFile> {
  const invokingUid = Number.parseInt(process.env.SUDO_UID ?? '', 10);
  const asUid = Number.isInteger(invokingUid) && invokingUid > 0 ? invokingUid : 65534;
  const base = defaultProtectedFsSeam();
  const seam: ProtectedFsSeam = { ...base, geteuid: () => asUid };
  return verifyProtectedFile(path, seam);
}

export function runProtect(args: string[] = []): ProtectResult {
  const opts = parseProtectArgs(args);
  const lines: string[] = [];

  const root = resolveProtectedRoot();
  if (!root.supported && root.reason !== 'running-as-root') {
    // Running privileged is the NORMAL state for `protect` itself. The resolver
    // refuses that state because an AGENT running privileged has no boundary,
    // which is a different question. Only win32 / no-euid genuinely block us.
    lines.push(`Cannot write a policy lock here: ${root.detail}`);
    return { code: 1, lines };
  }
  const protectedRoot = root.supported ? root.root : DEFAULT_PROTECTED_ROOT;
  const lockPath = join(protectedRoot, POLICY_LOCK_FILENAME);

  const sourcePath = resolveSourceConfigPath(opts);
  let raw: Record<string, unknown> = {};
  if (existsSync(sourcePath)) {
    try {
      const parsed: unknown = JSON.parse(readFileSync(sourcePath, 'utf-8'));
      if (isBlock(parsed)) raw = parsed;
    } catch {
      lines.push(`Warning: ${sourcePath} could not be parsed — pinning defaults instead of its values.`);
    }
  } else {
    lines.push(`No config at ${sourcePath} — pinning defaults.`);
  }

  const policy = buildLockedPolicy(raw, opts);
  const body = `${JSON.stringify(policy, null, 2)}\n`;
  const pinned = PROTECTED_POLICY_KEYS_V1.filter((k) => coversKey(policy, k)).join(', ');

  if (opts.dryRun) {
    lines.push(`Would write ${lockPath}, owned by uid 0, mode 0644, in a uid-0 0755 directory:`);
    lines.push(body.trimEnd());
    lines.push('');
    lines.push(`Pinned keys: ${pinned}`);
    lines.push('config.json may only TIGHTEN these; it can never loosen them.');
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

  const verdict = verifyAsAgent(lockPath);
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
