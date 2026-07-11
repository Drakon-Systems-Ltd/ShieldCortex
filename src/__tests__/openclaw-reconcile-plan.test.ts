import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';
import {
  reconcilePluginState,
  planReconcileActions,
  REALTIME_PLUGIN_ID,
  type ReconcileInput,
} from '../integrations/openclaw-plugin-index.js';

/**
 * Proves the reconciler ROUTES the three remediation paths that failed on
 * aiquant (#74) to the correct commands — without executing anything:
 *   1. source-not-found  → OpenClaw-tracked plugins go through `plugins update`,
 *      not `shieldcortex openclaw install` (which skips them).
 *   2. registered-but-inactive → every plan ends with a gateway reload + a
 *      honest-state self-check step.
 *   3. version-regression → reinstall PINS the exact expected version, never a
 *      floating `@latest` that re-resolved to 4.25.4.
 */
const thisFile = fileURLToPath(import.meta.url);
const fixturesDir = path.resolve(path.dirname(thisFile), '..', '__fixtures__', 'openclaw-plugin-index');
const PKG = '@drakon-systems/shieldcortex-realtime';

function verdictFor(name: string) {
  const fx = JSON.parse(fs.readFileSync(path.join(fixturesDir, `${name}.json`), 'utf-8')) as {
    input: ReconcileInput;
  };
  return { verdict: reconcilePluginState(fx.input), input: fx.input };
}

function planFor(name: string, extra: { duplicateDirsToPrune?: string[] } = {}) {
  const { verdict } = verdictFor(name);
  return planReconcileActions(verdict, {
    pluginId: REALTIME_PLUGIN_ID,
    packageName: PKG,
    expectedVersion: '4.47.2',
    ...extra,
  });
}

function joinCmd(step: { command?: string[] } | undefined): string {
  return step?.command ? `openclaw ${step.command.join(' ')}` : '';
}

describe('planReconcileActions — command routing per #74 state', () => {
  it('silent-drop routes OpenClaw-tracked plugin through `plugins update` (NOT install)', () => {
    const plan = planFor('enabled-not-loaded');
    const update = plan.find((s) => s.kind === 'openclaw-update');
    expect(update).toBeTruthy();
    expect(joinCmd(update)).toBe(`openclaw plugins update ${PKG}`);
    // The failing path on aiquant was `shieldcortex openclaw install` → source
    // not found. There must be no plain (non-pinned, non-forced) install here.
    expect(plan.some((s) => s.kind === 'openclaw-install')).toBe(false);
  });

  it('version regression reinstalls PINNED to the expected version, never @latest', () => {
    const plan = planFor('version-regressed');
    const pinned = plan.find((s) => s.kind === 'openclaw-install-pinned');
    expect(pinned).toBeTruthy();
    expect(joinCmd(pinned)).toBe(`openclaw plugins install --force ${PKG}@4.47.2`);
    expect(joinCmd(pinned)).not.toMatch(/@latest/);
  });

  it('every remediation plan ends with a gateway reload followed by a self-check', () => {
    for (const name of ['enabled-not-loaded', 'version-regressed', 'conflicted-metadata', 'duplicate-install']) {
      const plan = planFor(name, { duplicateDirsToPrune: ['dup-dir'] });
      const kinds = plan.map((s) => s.kind);
      expect(kinds[kinds.length - 1]).toBe('self-check');
      expect(kinds).toContain('gateway-reload');
      expect(kinds.indexOf('gateway-reload')).toBeLessThan(kinds.indexOf('self-check'));
    }
  });

  it('duplicate-install prunes the stale dirs BEFORE reloading', () => {
    const plan = planFor('duplicate-install', { duplicateDirsToPrune: ['stale-dir'] });
    const prune = plan.find((s) => s.kind === 'prune-duplicate-dirs');
    expect(prune).toBeTruthy();
    expect(plan.findIndex((s) => s.kind === 'prune-duplicate-dirs'))
      .toBeLessThan(plan.findIndex((s) => s.kind === 'gateway-reload'));
  });

  it('healthy state plans only a self-check (verify, do not churn the install)', () => {
    const plan = planFor('healthy');
    expect(plan.map((s) => s.kind)).toEqual(['self-check']);
  });

  it('not-installed plans a pinned install then reload + self-check', () => {
    const plan = planFor('not-installed');
    const install = plan.find((s) => s.kind === 'openclaw-install');
    expect(joinCmd(install)).toBe(`openclaw plugins install ${PKG}@4.47.2`);
    expect(plan[plan.length - 1].kind).toBe('self-check');
  });
});
