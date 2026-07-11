import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * #74 deliverable 2 requires the honest-state self-check wired into the install
 * and repair flows. setup/openclaw.ts trips Jest's ESM loader (same reason the
 * gateway-restart suite uses source analysis), so we assert the wiring at source
 * level: the self-check must run after the gateway restart, must hard-fail
 * (exitCode 1) when the plugin is not in the roster, and must never print an
 * "active/protected" all-clear without both proofs.
 */
const thisFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
const openclawSrc = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw.ts'), 'utf-8');
const repairSrc = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'repair.ts'), 'utf-8');

describe('install flow wires the honest-state self-check', () => {
  it('imports and runs runPluginSelfCheck in installOpenClawHook', () => {
    expect(openclawSrc).toMatch(/openclaw-selfcheck(?:\.js)?['"]/);
    expect(openclawSrc).toMatch(/runPluginSelfCheck/);
  });

  it('hard-fails (exitCode = 1) when the roster proof is missing', () => {
    const body = openclawSrc.slice(openclawSrc.indexOf('runPluginSelfCheck'));
    expect(body).toMatch(/!check\.rosterProof/);
    expect(body).toMatch(/process\.exitCode\s*=\s*1/);
  });

  it('only prints the confirmed all-clear when check.ok is true', () => {
    expect(openclawSrc).toMatch(/if\s*\(check\.ok\)/);
    expect(openclawSrc).toMatch(/confirmed loaded/i);
  });

  it('the self-check runs after the gateway restart, not before', () => {
    const restartIdx = openclawSrc.indexOf('restartOpenClawGateway');
    const selfCheckIdx = openclawSrc.indexOf('runPluginSelfCheck');
    expect(restartIdx).toBeGreaterThan(-1);
    expect(selfCheckIdx).toBeGreaterThan(restartIdx);
  });
});

describe('repair flow wires the metadata reconciler', () => {
  it('shieldcortex repair runs reconcileOpenClawPluginState + formatReconcileReport', () => {
    expect(repairSrc).toMatch(/reconcileOpenClawPluginState/);
    expect(repairSrc).toMatch(/formatReconcileReport/);
  });

  it('shieldcortex repair hard-fails when an applied remediation did not pass the self-check', () => {
    expect(repairSrc).toMatch(/result\.applied\s*&&\s*!result\.ok/);
    expect(repairSrc).toMatch(/process\.exitCode\s*=\s*1/);
  });

  it('openclaw repair also routes through the reconciler as a first concern', () => {
    expect(openclawSrc).toMatch(/openclaw-reconcile(?:\.js)?['"]/);
    expect(openclawSrc).toMatch(/reconcileOpenClawPluginState/);
  });
});
