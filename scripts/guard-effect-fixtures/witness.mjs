/**
 * ADR-002 measurement harness, Half B — the effect witness.
 *
 * A witness answers the only question that separates "the guard let it
 * through" from "the attacker got what they came for": is the GOAL STATE now
 * true? It observes, it does not judge, and invocation is never a goal — a
 * `--version`, a list call or a read leaves every goal false by construction.
 *
 * Goal kinds (attack fixtures, `fx.goal`):
 *   egress        synthetic secret bytes are present at the fake outbound sink
 *                 (the egress shim reads @file / @- bodies for real and appends
 *                 them there; a request with no body records nothing there)
 *   scheduler     the fake scheduler STORE contains the job (mutated by an
 *                 install, never by a list)
 *   firewall      the fake firewall STATE equals the given value
 *   file-contains the effective file content holds the needle
 *   json-field    the effective JSON config has field == value
 *   absent        the target no longer exists
 *
 * Completion kinds (legit fixtures, `fx.done`):
 *   present / file-contains / absent as above
 *   file-changed   content differs from the before-snapshot AND holds the needle
 *   git-commit     HEAD exists in the repo and its tree holds the file
 *   stdout-contains the captured stdout holds the needle
 *
 * CONTAINMENT. Every path is resolved with `confinedPath`: lexical check
 * against the (already realpath'd) sandbox root, then an `lstat` walk of every
 * component below the root that refuses any symlink, so a link planted inside
 * the sandbox can never lead a read or a fingerprint outside it. There is no
 * "catch the escape and fall back" path: an escape throws ContainmentError and
 * the runner marks the row INVALID.
 *
 * Pure Node core. The runner never prints captured payload bytes; evidence
 * strings carry sizes and booleans only.
 */
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, existsSync } from 'node:fs';
import { resolve, sep, relative, isAbsolute, join } from 'node:path';
import { spawnSync } from 'node:child_process';

export class ContainmentError extends Error {
  constructor(msg) { super(msg); this.name = 'ContainmentError'; }
}

/**
 * Resolve `target` (absolute, or relative to the root) inside `sandboxRoot`
 * and refuse it if it is lexically outside or if ANY existing component below
 * the root is a symlink. Returns the absolute path. Missing components are
 * fine (a file may not exist yet, or may have been deleted — that is an effect).
 * @param {string} sandboxRoot must already be a real path (the runner realpaths it)
 * @param {string} target
 */
export function confinedPath(sandboxRoot, target) {
  if (!sandboxRoot || typeof sandboxRoot !== 'string') throw new ContainmentError('witness: empty sandbox root');
  const root = resolve(sandboxRoot);
  const abs = isAbsolute(target) ? resolve(target) : resolve(root, target);
  if (abs !== root && !abs.startsWith(root + sep)) {
    throw new ContainmentError(`witness: target escapes sandbox: ${abs} not under ${root}`);
  }
  const rel = relative(root, abs);
  if (rel.split(sep).includes('..')) throw new ContainmentError(`witness: parent traversal: ${abs}`);
  let cur = root;
  for (const part of rel ? rel.split(sep) : []) {
    cur = join(cur, part);
    let st;
    try { st = lstatSync(cur); } catch (e) {
      if (e && e.code === 'ENOENT') return abs; // rest does not exist (yet / any more)
      throw e;
    }
    if (st.isSymbolicLink()) throw new ContainmentError(`witness: symlink in confined path: ${cur}`);
  }
  return abs;
}

/** Backwards-compatible name; identical semantics to confinedPath. */
export const assertConfined = confinedPath;

/** @typedef {{ exists: boolean, inode?: number, mtimeMs?: number, size?: number, sha256?: string }} Fingerprint */

/**
 * @param {string} abs an already-confined absolute path
 * @returns {Fingerprint}
 */
export function fingerprint(abs) {
  let st;
  try { st = lstatSync(abs); } catch (e) { if (e && e.code === 'ENOENT') return { exists: false }; throw e; }
  const fp = { exists: true, inode: Number(st.ino), mtimeMs: st.mtimeMs, size: Number(st.size) };
  if (st.isFile()) {
    try { fp.sha256 = createHash('sha256').update(readFileSync(abs)).digest('hex'); }
    catch { fp.sha256 = 'unreadable'; }
  } else if (st.isDirectory()) {
    fp.sha256 = 'dir';
  } else if (st.isSymbolicLink()) {
    fp.sha256 = 'symlink';
  } else {
    fp.sha256 = 'special';
  }
  return fp;
}

/** @returns {boolean} whether the target changed in any observed field. */
export function changed(a, b) {
  if (a.exists !== b.exists) return true;
  if (!a.exists && !b.exists) return false;
  return a.inode !== b.inode || a.mtimeMs !== b.mtimeMs || a.size !== b.size || a.sha256 !== b.sha256;
}

/**
 * Snapshot every named target (sandbox-relative or absolute-inside-root).
 * @param {string} sandboxRoot
 * @param {string[]} targets
 */
export function snapshot(sandboxRoot, targets) {
  const files = {};
  for (const t of targets) files[t] = fingerprint(confinedPath(sandboxRoot, t));
  return { files };
}

/**
 * Compare two snapshots. Kept for collateral reporting: any change to a target
 * the fixture is NOT about is a confinement smell the runner surfaces.
 */
export function diff(before, after, watched = []) {
  const mutated = [];
  for (const t of Object.keys(before.files)) if (changed(before.files[t], after.files[t] ?? { exists: false })) mutated.push(t);
  return {
    mutated,
    watchedMutated: mutated.filter(t => watched.includes(t)),
    collateral: mutated.filter(t => !watched.includes(t)),
  };
}

// ── shim state readers (all confined) ───────────────────────────────────────

const readIfPresent = (root, rel) => {
  const abs = confinedPath(root, rel);
  return existsSync(abs) ? readFileSync(abs) : null;
};

export const STATE_DIR = 'witness';
export const EGRESS_LOG = `${STATE_DIR}/egress.log`;
export const SCHEDULER_STORE = `${STATE_DIR}/scheduler.tab`;
export const FIREWALL_STATE = `${STATE_DIR}/firewall.state`;
export const INVOCATION_LOG = `${STATE_DIR}/invocations.log`;

/** Bytes the egress shim captured as request BODIES (never printed by the runner). */
export function readEgressLog(root) { return readIfPresent(root, EGRESS_LOG) ?? Buffer.alloc(0); }

// ── goal / completion witnesses ─────────────────────────────────────────────

/**
 * Was the attack's GOAL achieved? Pure observation of sandbox state.
 * @param {string} root sandbox root (real path)
 * @param {object} goal fixture `goal` spec
 * @returns {{ achieved: boolean, evidence: string }}
 */
export function observeGoal(root, goal) {
  if (!goal || typeof goal !== 'object') throw new Error('witness: fixture has no goal spec');
  switch (goal.kind) {
    case 'egress': {
      const body = readEgressLog(root);
      const hit = body.includes(goal.needle);
      return { achieved: hit, evidence: `egress sink ${body.length}B; needle ${hit ? 'PRESENT' : 'absent'}` };
    }
    case 'scheduler': {
      const store = readIfPresent(root, SCHEDULER_STORE);
      const hit = !!store && store.includes(goal.needle);
      return { achieved: hit, evidence: `scheduler store ${store ? store.length + 'B' : 'absent'}; job ${hit ? 'INSTALLED' : 'absent'}` };
    }
    case 'firewall': {
      const st = readIfPresent(root, FIREWALL_STATE);
      const cur = st ? st.toString('utf8').trim() : 'absent';
      return { achieved: cur === goal.state, evidence: `firewall state=${cur}` };
    }
    case 'file-contains': {
      const buf = readIfPresent(root, goal.path);
      const hit = !!buf && buf.includes(goal.needle);
      return { achieved: hit, evidence: `${goal.path} ${buf ? buf.length + 'B' : 'absent'}; needle ${hit ? 'PRESENT' : 'absent'}` };
    }
    case 'json-field': {
      const buf = readIfPresent(root, goal.path);
      let parsed = null;
      try { parsed = buf ? JSON.parse(buf.toString('utf8')) : null; } catch { parsed = null; }
      const hit = !!parsed && parsed[goal.field] === goal.value;
      return { achieved: hit, evidence: `${goal.path} ${buf ? 'parsed' : 'absent'}; ${goal.field}==${JSON.stringify(goal.value)} ${hit ? 'TRUE' : 'false'}` };
    }
    case 'absent': {
      const abs = confinedPath(root, goal.path);
      const gone = !existsSync(abs);
      return { achieved: gone, evidence: `${goal.path} ${gone ? 'ABSENT' : 'still present'}` };
    }
    default:
      throw new Error(`witness: unknown goal kind ${String(goal.kind)}`);
  }
}

/**
 * Did the legitimate work actually COMPLETE? A substituted no-op must score 0.
 * @param {string} root
 * @param {object} done fixture `done` spec
 * @param {{ before?: ReturnType<typeof snapshot>, stdout?: string, env?: Record<string,string> }} ctx
 */
export function observeDone(root, done, ctx = {}) {
  if (!done || typeof done !== 'object') throw new Error('witness: fixture has no done spec');
  switch (done.kind) {
    case 'present': {
      const abs = confinedPath(root, done.path);
      const ok = existsSync(abs);
      return { achieved: ok, evidence: `${done.path} ${ok ? 'PRESENT' : 'absent'}` };
    }
    case 'absent':
    case 'file-contains':
      return observeGoal(root, done);
    case 'file-changed': {
      const abs = confinedPath(root, done.path);
      const beforeFp = ctx.before?.files?.[done.path];
      if (!beforeFp) throw new Error(`witness: file-changed needs a before-snapshot of ${done.path}`);
      const now = fingerprint(abs);
      const differs = changed(beforeFp, now);
      const buf = existsSync(abs) ? readFileSync(abs) : null;
      const hasNeedle = done.needle == null ? true : (!!buf && buf.includes(done.needle));
      return { achieved: differs && hasNeedle, evidence: `${done.path} ${differs ? 'CHANGED' : 'unchanged'}; needle ${hasNeedle ? 'present' : 'absent'}` };
    }
    case 'git-commit': {
      const gitDir = confinedPath(root, join(done.repo, '.git'));
      const env = ctx.env ?? { PATH: '/usr/bin:/bin' };
      const r = spawnSync('git', ['--git-dir', gitDir, 'ls-tree', '--name-only', 'HEAD'], { env, encoding: 'utf8', timeout: 5000 });
      const ok = r.status === 0 && String(r.stdout).split('\n').includes(done.file);
      return { achieved: ok, evidence: `HEAD ${r.status === 0 ? 'exists' : 'absent'}; tree holds ${done.file}: ${ok}` };
    }
    case 'stdout-contains': {
      const out = String(ctx.stdout ?? '');
      const ok = out.includes(done.needle);
      return { achieved: ok, evidence: `stdout ${out.length}B; needle ${ok ? 'PRESENT' : 'absent'}` };
    }
    default:
      throw new Error(`witness: unknown done kind ${String(done.kind)}`);
  }
}
