/**
 * #216 — doctor plugin-loaded must attribute hot-reload registrations to the
 * running gateway PID.
 *
 * Case #213: after stanza restore the plugin hot-reloaded into the running
 * gateway (registration line PID-attributable), but doctor only read the boot
 * roster snapshot → false absent. Conversely a previous-boot roster line must
 * never mask a currently-dead plugin (already bounded by process start).
 *
 * Contract:
 * - gateway-PID registration after boot ⇒ loaded / healthy
 * - CLI-PID or anonymous registration after boot ⇒ still load-unproven (#142)
 * - no registration + absent from boot ⇒ enabled-not-loaded
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  findGatewayAttributedRegistrationSince,
  parseRegistrationsSince,
} from '../integrations/openclaw-gateway-roster.js';
import {
  reconcilePluginState,
  classifyLiveLoadEvidence,
  type ReconcileInput,
} from '../integrations/openclaw-plugin-index.js';
import { evaluateSelfCheck } from '../setup/openclaw-selfcheck.js';
import { renderPluginLoadVerdict } from '../cli/doctor.js';

const PLUGIN = 'shieldcortex-realtime';
const GW_PID = 4242;
const CLI_PID = 9999;

const base: ReconcileInput = {
  pluginId: PLUGIN,
  expectedVersion: '4.47.23',
  config: { enabled: true, inAllow: true },
  installsJson: null,
  index: {
    installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.23' } },
    plugins: [{ pluginId: PLUGIN, enabled: true }],
    warning: null,
  },
  onDiskVersion: '4.47.23',
  projectDirs: [],
  liveRoster: ['telegram'], // boot snapshot missed us
};

function regLine(iso: string, version: string, pid: number | null): string {
  if (pid == null) {
    return JSON.stringify({
      time: iso,
      message: `[shieldcortex] v${version} registered (llm_input + before_tool_call)`,
    });
  }
  return JSON.stringify({
    time: iso,
    pid,
    message: `[shieldcortex] v${version} registered (llm_input + before_tool_call)`,
  });
}

describe('#216 findGatewayAttributedRegistrationSince', () => {
  it('returns only sightings whose pid matches the gateway', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-216-log-'));
    try {
      const text = [
        regLine('2026-08-08T14:04:00.000Z', '4.47.32', CLI_PID),
        regLine('2026-08-08T14:04:33.000Z', '4.47.32', GW_PID),
      ].join('\n');
      fs.writeFileSync(path.join(dir, 'openclaw-2026-08-08.log'), text);
      const since = Date.parse('2026-08-08T14:00:00.000Z');
      const got = findGatewayAttributedRegistrationSince(since, GW_PID, { logDir: dir });
      expect(got).not.toBeNull();
      expect(got!.pid).toBe(GW_PID);
      expect(got!.version).toBe('4.47.32');
      expect(findGatewayAttributedRegistrationSince(since, CLI_PID, { logDir: dir })!.pid).toBe(CLI_PID);
      // Unknown pid → null
      expect(findGatewayAttributedRegistrationSince(since, 1, { logDir: dir })).toBeNull();
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('ignores anonymous (no pid) registration lines — those stay #142-ambiguous', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-216-anon-'));
    try {
      fs.writeFileSync(
        path.join(dir, 'openclaw-x.log'),
        regLine('2026-08-08T14:04:33.000Z', '4.47.32', null),
      );
      const since = Date.parse('2026-08-08T14:00:00.000Z');
      expect(findGatewayAttributedRegistrationSince(since, GW_PID, { logDir: dir })).toBeNull();
      // parseRegistrationsStill sees it for the ambiguous path
      expect(parseRegistrationsSince(fs.readFileSync(path.join(dir, 'openclaw-x.log'), 'utf8'), since)).toHaveLength(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('#216 reconciler — gateway-PID hot-reload is live load', () => {
  it('boot-miss + gateway-PID registration ⇒ healthy (not enabled-not-loaded)', () => {
    const v = reconcilePluginState({
      ...base,
      liveRoster: ['telegram'],
      liveLoadEvidence: 'gateway-pid-registration',
      registrationSeenAfterBoot: false,
    });
    expect(v.state).toBe('healthy');
    expect(v.loadedInLiveRoster).toBe(true);
    expect(v.reasons.join(' ')).toMatch(/RUNNING gateway PID after boot|hot-reload/i);
  });

  it('boot-miss + CLI/anonymous registration only ⇒ still load-unproven (#142)', () => {
    const v = reconcilePluginState({
      ...base,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: true,
      liveLoadEvidence: null,
    });
    expect(v.state).toBe('load-unproven');
    expect(v.severity).toBe('warn');
  });

  it('boot-miss + no registration ⇒ enabled-not-loaded fail', () => {
    const v = reconcilePluginState({
      ...base,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: false,
      liveLoadEvidence: null,
    });
    expect(v.state).toBe('enabled-not-loaded');
    expect(v.severity).toBe('fail');
  });

  it('promoting plugin id into liveRoster (gather path) also yields healthy', () => {
    const v = reconcilePluginState({
      ...base,
      liveRoster: ['telegram', PLUGIN],
      liveLoadEvidence: 'gateway-pid-registration',
    });
    expect(v.state).toBe('healthy');
    expect(v.loadedInLiveRoster).toBe(true);
  });
});

describe('#216 self-check — gateway-PID registration grants roster proof', () => {
  const canaryPassed = { ran: true, denied: true, auditEntryFound: true };

  it('boot-miss + gateway-PID reg ⇒ loaded + rosterProof', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: false,
      gatewayPidRegistrationSeenAfterBoot: true,
      canary: canaryPassed,
    });
    expect(v.rosterState).toBe('loaded');
    expect(v.rosterProof).toBe(true);
    expect(v.reasons.join(' ')).toMatch(/RUNNING gateway PID after boot|hot-reload/i);
  });

  it('boot-miss + CLI-only reg still unproven (does not grant proof)', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: true,
      gatewayPidRegistrationSeenAfterBoot: false,
      canary: canaryPassed,
    });
    expect(v.rosterState).toBe('unproven');
    expect(v.rosterProof).toBe(false);
  });
});

describe('#216 classifyLiveLoadEvidence — production decision tree (pure)', () => {
  const pluginId = PLUGIN;
  const gw = (atMs: number) => ({ atMs, pid: GW_PID, version: '4.47.32' });
  const cli = (atMs: number) => ({ atMs, pid: CLI_PID, version: '4.50.0' });
  const anon = (atMs: number) => ({ atMs, pid: null, version: '4.47.32' });

  it('boot roster hit ⇒ boot-roster evidence, no registration scan needed', () => {
    const r = classifyLiveLoadEvidence({
      pluginId,
      liveRoster: [PLUGIN, 'telegram'],
      gatewayPid: GW_PID,
      bootAtMs: 100,
      processStartedAtMs: 50,
      findGatewayReg: () => {
        throw new Error('must not scan');
      },
      findAnyReg: () => {
        throw new Error('must not scan');
      },
    });
    expect(r.liveLoadEvidence).toBe('boot-roster');
    expect(r.registrationSeenAfterBoot).toBe(false);
  });

  it('boot-miss + gateway-PID reg (bootAtMs bound only; processStartedAtMs null) ⇒ gateway-pid-registration', () => {
    // SOL dual-review blocker: must not require processStartedAtMs.
    const r = classifyLiveLoadEvidence({
      pluginId,
      liveRoster: ['telegram'],
      gatewayPid: GW_PID,
      bootAtMs: 100,
      processStartedAtMs: null,
      findGatewayReg: (since, pid) => {
        expect(since).toBe(100);
        expect(pid).toBe(GW_PID);
        return gw(150);
      },
      findAnyReg: () => cli(160),
    });
    expect(r.liveLoadEvidence).toBe('gateway-pid-registration');
    expect(r.liveRoster).toContain(PLUGIN);
    expect(r.registrationSeenAfterBoot).toBe(false);
  });

  it('boot-miss + gateway-PID reg (processStartedAtMs bound only; bootAtMs null) ⇒ gateway-pid-registration', () => {
    const r = classifyLiveLoadEvidence({
      pluginId,
      liveRoster: null,
      gatewayPid: GW_PID,
      bootAtMs: null,
      processStartedAtMs: 200,
      findGatewayReg: (since) => {
        expect(since).toBe(200);
        return gw(250);
      },
      findAnyReg: () => {
        throw new Error('no boot ⇒ no #142 path');
      },
    });
    expect(r.liveLoadEvidence).toBe('gateway-pid-registration');
    expect(r.liveRoster).toEqual([PLUGIN]);
  });

  it('#142 preserved when processStartedAtMs is null: CLI/anon reg still marks registrationSeenAfterBoot', () => {
    const r = classifyLiveLoadEvidence({
      pluginId,
      liveRoster: ['telegram'],
      gatewayPid: GW_PID,
      bootAtMs: 100,
      processStartedAtMs: null,
      findGatewayReg: () => null,
      findAnyReg: (since) => {
        expect(since).toBe(100);
        return anon(120);
      },
    });
    expect(r.liveLoadEvidence).toBeNull();
    expect(r.registrationSeenAfterBoot).toBe(true);
    expect(r.liveRoster).not.toContain(PLUGIN);
  });

  it('CLI-PID reg alone never grants gateway-pid-registration', () => {
    const r = classifyLiveLoadEvidence({
      pluginId,
      liveRoster: ['telegram'],
      gatewayPid: GW_PID,
      bootAtMs: 100,
      processStartedAtMs: 50,
      findGatewayReg: () => null,
      findAnyReg: () => cli(150),
    });
    expect(r.liveLoadEvidence).toBeNull();
    expect(r.registrationSeenAfterBoot).toBe(true);
  });

  it('invalid gatewayPid does not call findGatewayReg; #142 still works', () => {
    let gwCalls = 0;
    const r = classifyLiveLoadEvidence({
      pluginId,
      liveRoster: ['telegram'],
      gatewayPid: 0,
      bootAtMs: 100,
      processStartedAtMs: 50,
      findGatewayReg: () => {
        gwCalls++;
        return gw(150);
      },
      findAnyReg: () => anon(120),
    });
    expect(gwCalls).toBe(0);
    expect(r.liveLoadEvidence).toBeNull();
    expect(r.registrationSeenAfterBoot).toBe(true);
  });
});

describe('#216 doctor render — names hot-reload evidence', () => {
  it('healthy + hot-reload reason → gateway-PID message', () => {
    const verdict = reconcilePluginState({
      ...base,
      liveRoster: ['telegram', PLUGIN],
      liveLoadEvidence: 'gateway-pid-registration',
    });
    const r = renderPluginLoadVerdict(verdict);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/gateway-PID registration after boot|hot-reload/i);
  });

  it('healthy + boot roster only → classic roster-confirmed message', () => {
    const verdict = reconcilePluginState({
      ...base,
      liveRoster: [PLUGIN, 'telegram'],
      liveLoadEvidence: 'boot-roster',
    });
    const r = renderPluginLoadVerdict(verdict);
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/roster-confirmed/i);
    expect(r.message).not.toMatch(/hot-reload/i);
  });
});
