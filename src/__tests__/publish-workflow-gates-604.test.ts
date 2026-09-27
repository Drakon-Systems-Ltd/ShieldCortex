import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from '@jest/globals';

/**
 * #604 — the publish workflow's release / ClawHub steps run behind ONE failure
 * only: the npm propagation wait. Review on the first patch found the gate
 * `steps.publish_*.outcome != 'failure'` let ClawHub run after a red `npm test`
 * (both publishes *skipped*, which is not `failure`) and after a plugin
 * version-check failure (root published, plugin skipped).
 *
 * Actions' status functions cannot be executed here, so this test does two
 * things: (1) pins the exact `if:` expressions in publish.yml, and (2) models
 * those expressions as functions of the step outcomes and evaluates them over
 * every scenario the review named. If (1) drifts, (2) proves nothing — which is
 * why both are in one file.
 */

type Outcome = 'success' | 'failure' | 'skipped' | 'cancelled';
type Steps = Record<string, Outcome>;

const ORDER = [
  'ci_wait', 'build', 'test', 'version_check', 'publish_root', 'tag', 'tag_check',
  'plugin_version_check', 'publish_plugin', 'release_ready', 'npm_propagation', 'npm_shape',
  'release', 'clawhub_cli', 'clawhub_sync',
] as const;

/** `name` → `if:` for every step of the publish job, read straight from the file (no YAML dependency). */
function readWorkflow(): Record<string, string> {
  const file = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '.github', 'workflows', 'publish.yml');
  const byName: Record<string, string> = {};
  let current: string | null = null;
  for (const raw of readFileSync(file, 'utf-8').split('\n')) {
    const name = raw.match(/^      - name: (.+?)\s*$/);
    if (name) { current = name[1]; byName[current] = ''; continue; }
    if (raw.startsWith('      - ')) { current = null; continue; }
    const cond = raw.match(/^        if: (.+?)\s*$/);
    if (cond && current) byName[current] = cond[1];
  }
  return byName;
}

const IFS = readWorkflow();

describe('#604 publish.yml — the exact gate expressions are pinned', () => {
  it('release readiness is an ordinary success()-chained step with no condition of its own', () => {
    expect(IFS['Release readiness — every pre-publish gate passed']).toBe('');
  });
  it('Create GitHub Release', () => {
    expect(IFS['Create GitHub Release']).toBe(
      "${{ !cancelled() && steps.release_ready.outcome == 'success' && (success() || steps.npm_propagation.outcome == 'failure') }}",
    );
  });
  it('Install ClawHub CLI', () => {
    expect(IFS['Install ClawHub CLI']).toBe(
      "${{ !cancelled() && env.HAS_CLAWHUB_TOKEN == 'true' && steps.release_ready.outcome == 'success' && (success() || steps.npm_propagation.outcome == 'failure') }}",
    );
  });
  it('Sync + verify ClawHub', () => {
    expect(IFS['Sync + verify ClawHub']).toBe(
      "${{ !cancelled() && env.HAS_CLAWHUB_TOKEN == 'true' && steps.release_ready.outcome == 'success' && steps.clawhub_cli.outcome == 'success' && (success() || steps.npm_propagation.outcome == 'failure') }}",
    );
  });
  it('the propagation wait and the tarball-shape check are separate steps', () => {
    expect(IFS).toHaveProperty('Verify both packages landed on npm at the expected version');
    expect(IFS).toHaveProperty('Verify plugin tarball shape');
  });
});

/**
 * Model of the pinned expressions. `success()` is true iff no earlier step in
 * the job has failed or been cancelled (skipped steps do not count); `cancelled()`
 * iff the job was cancelled. A step whose `if:` is false is `skipped`.
 */
function successSoFar(steps: Steps, upTo: string): boolean {
  for (const id of ORDER) {
    if (id === upTo) break;
    const o = steps[id] ?? 'skipped';
    if (o === 'failure' || o === 'cancelled') return false;
  }
  return true;
}
const cancelled = (steps: Steps) => Object.values(steps).includes('cancelled');
const outcome = (steps: Steps, id: string): Outcome => steps[id] ?? 'skipped';

const gates = {
  release: (s: Steps) => !cancelled(s) && outcome(s, 'release_ready') === 'success'
    && (successSoFar(s, 'release') || outcome(s, 'npm_propagation') === 'failure'),
  clawhub_cli: (s: Steps) => !cancelled(s) && outcome(s, 'release_ready') === 'success'
    && (successSoFar(s, 'clawhub_cli') || outcome(s, 'npm_propagation') === 'failure'),
  clawhub_sync: (s: Steps) => !cancelled(s) && outcome(s, 'release_ready') === 'success'
    && outcome(s, 'clawhub_cli') === 'success'
    && (successSoFar(s, 'clawhub_sync') || outcome(s, 'npm_propagation') === 'failure'),
};

/** Run the job model: each step's outcome comes from `script`, or is derived from the gate. */
function job(script: Partial<Steps>): Steps {
  const s: Steps = {};
  for (const id of ORDER) {
    if (id === 'release') { s[id] = gates.release(s) ? (script[id] ?? 'success') : 'skipped'; continue; }
    if (id === 'clawhub_cli') { s[id] = gates.clawhub_cli(s) ? (script[id] ?? 'success') : 'skipped'; continue; }
    if (id === 'clawhub_sync') { s[id] = gates.clawhub_sync(s) ? (script[id] ?? 'success') : 'skipped'; continue; }
    if (id === 'release_ready') { s[id] = successSoFar(s, id) && !cancelled(s) ? 'success' : 'skipped'; continue; }
    if (id === 'npm_propagation' || id === 'npm_shape') {
      s[id] = successSoFar(s, id) && !cancelled(s) ? (script[id] ?? 'success') : 'skipped';
      continue;
    }
    s[id] = script[id] ?? 'success';
  }
  return s;
}

describe('#604 publish.yml — release and ClawHub run behind a propagation timeout and nothing else', () => {
  it('normal publish: everything runs', () => {
    const s = job({});
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['success', 'success', 'success']);
  });
  it('already-published rerun (both publishes skipped by their own checks): release + ClawHub still run', () => {
    const s = job({ publish_root: 'skipped', publish_plugin: 'skipped' });
    expect(s.release_ready).toBe('success');
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['success', 'success', 'success']);
  });
  it('propagation timeout: the ONE failure they run behind', () => {
    const s = job({ npm_propagation: 'failure' });
    expect(s.npm_shape).toBe('skipped');
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['success', 'success', 'success']);
  });
  it('earlier gate failure (red npm test): both publishes skipped is NOT readiness — nothing runs', () => {
    const s = job({ test: 'failure', publish_root: 'skipped', publish_plugin: 'skipped' });
    expect(s.release_ready).toBe('skipped');
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('tag guard failure: nothing runs', () => {
    const s = job({ tag_check: 'failure', publish_plugin: 'skipped' });
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('plugin version-check failure after the root published: nothing runs', () => {
    const s = job({ plugin_version_check: 'failure', publish_plugin: 'skipped' });
    expect(s.release_ready).toBe('skipped');
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('root publish failure: nothing runs', () => {
    const s = job({ publish_root: 'failure' });
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('plugin publish failure: nothing runs', () => {
    const s = job({ publish_plugin: 'failure' });
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('tarball-shape failure is NOT propagation: nothing runs', () => {
    const s = job({ npm_shape: 'failure' });
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('cancellation: nothing runs', () => {
    const s = job({ npm_propagation: 'cancelled' });
    expect([s.release, s.clawhub_cli, s.clawhub_sync]).toEqual(['skipped', 'skipped', 'skipped']);
  });
  it('ClawHub CLI install failure: sync does not run, even behind a propagation timeout', () => {
    const s = job({ npm_propagation: 'failure', clawhub_cli: 'failure' });
    expect(s.release).toBe('success');
    expect(s.clawhub_sync).toBe('skipped');
  });
});
