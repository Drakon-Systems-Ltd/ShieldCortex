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
    // Both ways of failing the roster proof must be handled, and each must
    // hard-fail. #152: `absent` (the gateway booted without us — proven
    // fail-open) and `unproven` (the boot roster could not be read) are
    // different facts and must not be reported as one another, but neither is
    // a pass.
    expect(body).toMatch(/rosterState\s*===\s*'absent'/);
    expect(body).toMatch(/rosterState\s*===\s*'unproven'/);
    expect(body.match(/process\.exitCode\s*=\s*1/g)?.length ?? 0).toBeGreaterThanOrEqual(2);
  });

  it('never accuses the host of being unprotected on an unreadable roster', () => {
    // The #142 false alarm: "UNPROTECTED" printed off absence of evidence.
    // Only what the OPERATOR sees counts here — comments may discuss the word.
    const body = openclawSrc.slice(openclawSrc.indexOf('runPluginSelfCheck'));
    const unprovenBranch = body.slice(body.indexOf("rosterState === 'unproven'"));
    const branchText = unprovenBranch.slice(0, unprovenBranch.indexOf('} else if'));
    const printed = [...branchText.matchAll(/console\.(?:warn|log|error)\((['"])(.*?)\1\)/g)]
      .map(m => m[2])
      .join(' ');
    expect(printed).not.toBe('');
    expect(printed).not.toMatch(/booted WITHOUT|UNPROTECTED|is NOT loaded/i);
    expect(printed).toMatch(/INCONCLUSIVE|could not read/i);
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

describe('#154 — `openclaw status` actually runs the load/enforcement check', () => {
  // Field evidence, 1 Aug 2026: doctor sent an operator to
  // `SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1 shieldcortex openclaw status` for the
  // live canary. That command listed install paths, accepted the env var, and
  // silently ignored it — the one question its name promises to answer went
  // unanswered. These pin the wiring so the printed command and the code path
  // cannot diverge again.
  it('the status flow reaches runPluginSelfCheck', () => {
    const statusBody = openclawSrc.slice(openclawSrc.indexOf('export async function openClawHookStatus'));
    expect(statusBody).toMatch(/reportLoadAndEnforcement\(\)/);
    const reporter = openclawSrc.slice(openclawSrc.indexOf('async function reportLoadAndEnforcement'));
    expect(reporter).toMatch(/runPluginSelfCheck/);
  });

  it('status reports load state in all three honest flavours', () => {
    const reporter = openclawSrc.slice(openclawSrc.indexOf('async function reportLoadAndEnforcement'));
    expect(reporter).toMatch(/rosterState === 'loaded'/);
    expect(reporter).toMatch(/rosterState === 'absent'/);
    // The unproven branch must not accuse; it must say unproven.
    expect(reporter).toMatch(/UNPROVEN/);
  });

  it('doctor names the canary command from the single shared constant, never a literal', () => {
    const doctorSrc = fs.readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'cli', 'doctor.ts'),
      'utf-8',
    );
    expect(doctorSrc).toMatch(/LIVE_CANARY_COMMAND/);
    // The two-different-commands bug: no hardcoded canary invocation may remain.
    const literals = doctorSrc.match(/ALLOW_GATEWAY_CANARY=1 shieldcortex [a-z ]+/g) ?? [];
    expect(literals).toEqual([]);
  });
});
