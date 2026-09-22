/**
 * ADR-002 measurement harness, Half B — the effect witness.
 *
 * An effect witness answers the only question that separates "the guard let it
 * through" from "damage was done": did the action actually CHANGE a protected
 * target, or actually PUT bytes on the wire? It observes, it does not judge.
 *
 * Two observation channels:
 *   1. Filesystem targets — for each protected path, a fingerprint of
 *      { exists, inode, mtimeMs, size, sha256 }. A change in any field between
 *      the before- and after-snapshot is an effect. Inode + mtime catch a
 *      delete-and-recreate that leaves an identical hash; sha256 catches an
 *      in-place edit that preserves inode and (on a coarse clock) mtime.
 *   2. A fake outbound sink — a file the shimmed network binaries (curl/wget/…)
 *      append to instead of touching the network. Growth between snapshots means
 *      data "left" the host (into the sink, never the wire). The recorded bytes
 *      are what WOULD have been sent, kept only so a test can assert a secret
 *      was in the payload; the runner never prints them.
 *
 * Pure Node core. No path here is ever the real host: the runner passes only
 * sandbox paths, and `assertConfined` refuses anything outside the sandbox root.
 */
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, existsSync, realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';

/** @typedef {{ exists: boolean, inode?: number, mtimeMs?: number, size?: number, sha256?: string }} Fingerprint */

/**
 * Refuse any target that is not inside `sandboxRoot`. The witness must never be
 * pointed at a real host path — this is the last line before an fs read.
 * @param {string} sandboxRoot
 * @param {string} target
 */
export function assertConfined(sandboxRoot, target) {
  if (!sandboxRoot || typeof sandboxRoot !== 'string') throw new Error('witness: empty sandbox root');
  const root = resolve(sandboxRoot);
  const abs = resolve(target);
  if (abs !== root && !abs.startsWith(root + sep)) {
    throw new Error(`witness: target escapes sandbox: ${abs} not under ${root}`);
  }
  return abs;
}

/**
 * @param {string} target
 * @returns {Fingerprint}
 */
export function fingerprint(target) {
  if (!existsSync(target)) return { exists: false };
  const st = lstatSync(target);
  const fp = { exists: true, inode: Number(st.ino), mtimeMs: st.mtimeMs, size: Number(st.size) };
  if (st.isFile()) {
    try { fp.sha256 = createHash('sha256').update(readFileSync(target)).digest('hex'); }
    catch { fp.sha256 = 'unreadable'; }
  } else if (st.isDirectory()) {
    fp.sha256 = 'dir';
  } else {
    fp.sha256 = 'special';
  }
  return fp;
}

/**
 * @param {Fingerprint} a
 * @param {Fingerprint} b
 * @returns {boolean} whether the target changed in any observed field.
 */
export function changed(a, b) {
  if (a.exists !== b.exists) return true;
  if (!a.exists && !b.exists) return false;
  return a.inode !== b.inode || a.mtimeMs !== b.mtimeMs || a.size !== b.size || a.sha256 !== b.sha256;
}

/**
 * Snapshot every protected target plus the sink's current size.
 * @param {string} sandboxRoot
 * @param {string[]} targets protected filesystem paths (must be confined)
 * @param {string} sinkPath the fake outbound sink file (confined)
 */
export function snapshot(sandboxRoot, targets, sinkPath) {
  const under = (rel) => (rel.startsWith(sandboxRoot) ? rel : resolve(sandboxRoot, rel));
  const files = {};
  for (const t of targets) {
    const abs = assertConfined(sandboxRoot, under(t));
    files[t] = fingerprint(abs);
  }
  const sinkAbs = assertConfined(sandboxRoot, under(sinkPath));
  const sink = existsSync(sinkAbs) ? Number(lstatSync(sinkAbs).size) : 0;
  return { files, sink };
}

/**
 * Compare two snapshots and report what the action actually did.
 * @param {ReturnType<typeof snapshot>} before
 * @param {ReturnType<typeof snapshot>} after
 * @param {string[]} watched the subset of targets this fixture claims to affect
 */
export function diff(before, after, watched) {
  const mutated = [];
  for (const t of Object.keys(before.files)) {
    if (changed(before.files[t], after.files[t])) mutated.push(t);
  }
  const sinkGrew = after.sink > before.sink;
  const sinkBytes = Math.max(0, after.sink - before.sink);
  const watchedMutated = mutated.filter(t => watched.includes(t));
  return {
    mutated,
    watchedMutated,
    sinkGrew,
    sinkBytes,
    // An effect on a target this fixture is ABOUT (watched) or any outbound bytes.
    effectAchieved: watchedMutated.length > 0 || sinkGrew,
    // Any change at all, including collateral outside the watched set — a
    // confinement smell the runner surfaces even when the fixture "passed".
    collateral: mutated.filter(t => !watched.includes(t)),
  };
}

/** Read what the sink captured (for a test asserting a secret was in flight). */
export function readSink(sandboxRoot, sinkPath) {
  const abs = assertConfined(sandboxRoot, sinkPath);
  return existsSync(abs) ? readFileSync(abs, 'utf8') : '';
}

/** Best-effort: confirm a path really resolves inside the sandbox after symlinks. */
export function realConfined(sandboxRoot, target) {
  try { return assertConfined(sandboxRoot, realpathSync(target)); }
  catch { return assertConfined(sandboxRoot, target); }
}
