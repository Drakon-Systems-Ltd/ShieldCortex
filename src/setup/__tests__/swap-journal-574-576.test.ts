import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  clearJournal,
  journalledSwap,
  journalPath,
  readJournal,
  recoverInterruptedSwap,
  writeJournal,
  type RefreshJournal,
} from '../swap-journal.js';

/**
 * #574 / #576 round 2, blocker 1 — the two-rename swap could leave a host with
 * NO installed copy. A SIGKILL after `target → backup` and before
 * `staged → target` is not something a `catch` can clean up: the process that
 * would run the `catch` is gone. So the swap is journalled and the next run
 * recovers.
 *
 * These cases construct the post-crash state on disk directly, which is the
 * only way to model a process that never came back.
 */
let root: string;
let target: string;
let backupRoot: string;
let backup: string;
let stagingRoot: string;
let staged: string;

beforeEach(() => {
  root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-swap-journal-'));
  target = path.join(root, 'live', 'thing');
  backupRoot = path.join(root, 'backups', 'thing-preupdate-x');
  backup = path.join(backupRoot, 'thing');
  stagingRoot = path.join(root, '.shieldcortex-staging-x');
  staged = path.join(stagingRoot, 'thing');
  fs.mkdirSync(path.dirname(target), { recursive: true });
});

afterEach(() => {
  fs.rmSync(root, { recursive: true, force: true });
});

function tree(dir: string, marker: string): void {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'marker'), marker);
}

function journal(phase: 'moving-old' | 'publishing'): RefreshJournal {
  return {
    version: 1,
    kind: 'hermes-plugin',
    root,
    target,
    backup,
    staged,
    stagingRoot,
    packagedVersion: '5.2.0',
    phase,
    startedAt: '2026-09-24T12:00:00.000Z',
    pid: 4242,
  };
}

/** The complete-staged-tree predicate the real callers pass. */
const complete = (dir: string): boolean => fs.readFileSync(path.join(dir, 'marker'), 'utf-8') === 'new';

describe('the journal itself', () => {
  it('refuses to overwrite an unresolved one', () => {
    writeJournal(journal('moving-old'));
    expect(() => writeJournal(journal('moving-old'))).toThrow(/EEXIST/);
  });

  it('survives a read as the shape it was written in', () => {
    writeJournal(journal('publishing'));
    const read = readJournal(root);
    expect('journal' in read && read.journal.target).toBe(target);
    expect('journal' in read && read.journal.packagedVersion).toBe('5.2.0');
    expect('journal' in read && read.journal.phase).toBe('publishing');
  });

  it('keeps "not there" and "could not read" apart', () => {
    expect(readJournal(root)).toEqual({ absent: true });
    fs.writeFileSync(journalPath(root), '{ not json');
    expect('error' in readJournal(root)).toBe(true);
  });

  it('is gone once cleared', () => {
    writeJournal(journal('moving-old'));
    clearJournal(root);
    expect(fs.existsSync(journalPath(root))).toBe(false);
  });
});

describe('recovery from a crash after rename 1 (the state with no installed copy)', () => {
  beforeEach(() => {
    // Exactly what a SIGKILL between the renames leaves: target gone, the old
    // copy sitting in backups/, the staged replacement still staged.
    tree(backup, 'old');
    tree(staged, 'new');
    writeJournal(journal('publishing'));
    expect(fs.existsSync(target)).toBe(false);
  });

  it('restores the previous copy — the one this host was demonstrably running', () => {
    const outcome = recoverInterruptedSwap(root, { stagedIsComplete: complete });

    expect(outcome.status).toBe('restored');
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('old');
    // Journal and staging are both gone: the swap is resolved, and a second
    // run must not try to finish it again.
    expect(fs.existsSync(journalPath(root))).toBe(false);
    expect(fs.existsSync(stagingRoot)).toBe(false);
    // And the reservation the interrupted run made for that backup, now empty,
    // is given back rather than left under `backups/` saying nothing.
    expect(fs.existsSync(backupRoot)).toBe(false);
    expect(outcome.detail.join('\n')).toMatch(/previous copy was restored/);
  });

  it('is idempotent — a second pass finds nothing left to do', () => {
    recoverInterruptedSwap(root, { stagedIsComplete: complete });
    expect(recoverInterruptedSwap(root, { stagedIsComplete: complete }).status).toBe('none');
  });

  it('publishes the VERIFIED staged copy only when no previous copy is left', () => {
    fs.rmSync(backup, { recursive: true, force: true });

    const outcome = recoverInterruptedSwap(root, { stagedIsComplete: complete });

    expect(outcome.status).toBe('published');
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('new');
    expect(fs.existsSync(journalPath(root))).toBe(false);
  });

  it('refuses to publish a staged copy that does not verify, and keeps the journal', () => {
    fs.rmSync(backup, { recursive: true, force: true });
    fs.writeFileSync(path.join(staged, 'marker'), 'half-written');

    const outcome = recoverInterruptedSwap(root, { stagedIsComplete: complete });

    expect(outcome.status).toBe('blocked');
    expect(fs.existsSync(target)).toBe(false);
    // Nothing destroyed, nothing published, and the journal is still there for
    // the operator and for the next attempt.
    expect(fs.existsSync(journalPath(root))).toBe(true);
    expect(fs.existsSync(staged)).toBe(true);
  });

  it('refuses when there is neither a previous nor a staged copy', () => {
    fs.rmSync(backup, { recursive: true, force: true });
    fs.rmSync(stagingRoot, { recursive: true, force: true });

    const outcome = recoverInterruptedSwap(root, { stagedIsComplete: complete });

    expect(outcome.status).toBe('blocked');
    expect(outcome.detail.join('\n')).toMatch(/is gone/);
    expect(fs.existsSync(journalPath(root))).toBe(true);
  });
});

describe('recovery from a crash after rename 2, or before rename 1', () => {
  it('clears the journal and LEAVES the backup where it is', () => {
    tree(target, 'new');
    tree(backup, 'old');
    tree(staged, 'new');
    writeJournal(journal('publishing'));

    const outcome = recoverInterruptedSwap(root, { stagedIsComplete: complete });

    expect(outcome.status).toBe('cleaned');
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('new');
    // Never deleted: the old copy is the operator's, and `backups/` is where
    // both the #569 repair and this refresh agree to keep it.
    expect(fs.readFileSync(path.join(backup, 'marker'), 'utf-8')).toBe('old');
    expect(fs.existsSync(journalPath(root))).toBe(false);
    // The staging tree is ours and this run created it; that one does go.
    expect(fs.existsSync(stagingRoot)).toBe(false);
  });

  it('refuses on a journal it cannot parse rather than guessing', () => {
    fs.writeFileSync(journalPath(root), '{ truncated');
    const outcome = recoverInterruptedSwap(root, { stagedIsComplete: complete });
    expect(outcome.status).toBe('blocked');
    expect(fs.existsSync(journalPath(root))).toBe(true);
  });

  it('does nothing at all, and says nothing, with no journal', () => {
    expect(recoverInterruptedSwap(root, { stagedIsComplete: complete })).toEqual({
      status: 'none',
      detail: [],
      journal: null,
    });
  });
});

describe('journalledSwap — what it leaves for recovery', () => {
  it('publishes and deletes the journal LAST', () => {
    tree(target, 'old');
    tree(staged, 'new');
    fs.mkdirSync(backupRoot, { recursive: true });

    const outcome = journalledSwap({
      kind: 'hermes-plugin',
      root,
      target,
      backup,
      staged,
      stagingRoot,
      packagedVersion: '5.2.0',
      now: new Date('2026-09-24T12:00:00.000Z'),
    });

    expect(outcome.ok).toBe(true);
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('new');
    expect(fs.readFileSync(path.join(backup, 'marker'), 'utf-8')).toBe('old');
    expect(fs.existsSync(journalPath(root))).toBe(false);
  });

  it('refuses outright when a previous refresh is still unresolved', () => {
    tree(target, 'old');
    tree(staged, 'new');
    fs.mkdirSync(backupRoot, { recursive: true });
    writeJournal(journal('publishing'));

    const outcome = journalledSwap({
      kind: 'hermes-plugin',
      root,
      target,
      backup,
      staged,
      stagingRoot,
      packagedVersion: '5.2.0',
      now: new Date(),
    });

    expect(outcome).toMatchObject({ ok: false, stage: 'journal', targetMissing: false });
    // And it moved nothing: the unresolved swap is recovered first, by a
    // caller that knows how to verify a staged tree.
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('old');
  });

  it('clears the journal when the FIRST rename fails, because nothing moved', () => {
    tree(target, 'old');
    tree(staged, 'new');
    // No backup parent: rename(2) fails ENOENT on the destination.
    const outcome = journalledSwap({
      kind: 'hermes-plugin',
      root,
      target,
      backup,
      staged,
      stagingRoot,
      packagedVersion: '5.2.0',
      now: new Date(),
    });

    expect(outcome).toMatchObject({ ok: false, stage: 'moving-old', targetMissing: false });
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('old');
    expect(fs.existsSync(journalPath(root))).toBe(false);
  });
});
