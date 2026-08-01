import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  evaluateSelfCheck,
  runPluginSelfCheck,
  type CanaryResult,
} from '../setup/openclaw-selfcheck.js';
import type { PluginIndexRow } from '../integrations/openclaw-plugin-index.js';

/**
 * Honest-state self-check (#74 deliverable 2). A security plugin must NEVER
 * report success unless BOTH proofs hold:
 *   (a) the RUNNING gateway's boot roster names the plugin, AND
 *   (b) a live enforcement canary confirms the interceptor is denying + audited.
 * Absence of either proof is a hard fail — silence is never success.
 *
 * These fixtures were once named `loadedRoster` / `droppedRoster` while holding
 * INSTALL-index rows, which is the misconception #152 was made of: the index
 * records what is installed and enabled, never what the gateway loaded. They
 * are named for what they actually are now, and every case supplies the live
 * roster separately — because that is the only thing that can grant the proof.
 */
const PLUGIN = 'shieldcortex-realtime';

const indexEnabled: PluginIndexRow = {
  installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2' } },
  plugins: [{ pluginId: PLUGIN, enabled: true, origin: 'npm' }],
  warning: null,
};
const indexMissing: PluginIndexRow = {
  installRecords: { [PLUGIN]: { source: 'npm', version: '4.47.2' } },
  plugins: [{ pluginId: 'brave', enabled: true, origin: 'npm' }],
  warning: 'conflicting plugin install metadata for: shieldcortex-realtime',
};
const passingCanary: CanaryResult = { ran: true, denied: true, auditEntryFound: true };

/** The gateway's own boot line — the authoritative roster (#152). */
const liveLoaded = [PLUGIN, 'anthropic'];
const liveAbsent = ['anthropic', 'brave'];

describe('evaluateSelfCheck — both-proofs-or-fail', () => {
  it('passes only when roster shows loaded AND canary denied + audited', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: indexEnabled, liveRoster: liveLoaded, canary: passingCanary });
    expect(v.ok).toBe(true);
    expect(v.rosterProof).toBe(true);
    expect(v.canaryProof).toBe(true);
  });

  it('FAILS when the plugin is loaded but the canary never ran (headless/no-consent)', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: indexEnabled, liveRoster: liveLoaded, canary: { ran: false, denied: false, auditEntryFound: false } });
    expect(v.ok).toBe(false);
    expect(v.rosterProof).toBe(true);
    expect(v.canaryProof).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/canary|enforcement/i);
  });

  it('FAILS (the #74 drop) when the canary passes but the roster omits the plugin', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: indexMissing, liveRoster: liveAbsent, canary: passingCanary });
    expect(v.ok).toBe(false);
    expect(v.rosterProof).toBe(false);
    expect(v.reasons.join(' ')).toMatch(/roster|loaded/i);
  });

  it('FAILS when the canary ran but the op was NOT denied (interceptor lenient)', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: indexEnabled, liveRoster: liveLoaded, canary: { ran: true, denied: false, auditEntryFound: false } });
    expect(v.ok).toBe(false);
    expect(v.canaryProof).toBe(false);
  });

  it('FAILS when denied but no audit entry appeared (cannot prove the interceptor fired)', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: indexEnabled, liveRoster: liveLoaded, canary: { ran: true, denied: true, auditEntryFound: false } });
    expect(v.ok).toBe(false);
    expect(v.canaryProof).toBe(false);
  });

  it('FAILS when the index is unreadable (null) — no roster proof', () => {
    const v = evaluateSelfCheck({ pluginId: PLUGIN, index: null, canary: passingCanary });
    expect(v.ok).toBe(false);
    expect(v.rosterProof).toBe(false);
  });
});

describe('runPluginSelfCheck — never touches the live gateway under Jest', () => {
  let tmpHome: string;
  beforeEach(() => {
    tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-selfcheck-'));
  });
  afterEach(() => {
    fs.rmSync(tmpHome, { recursive: true, force: true });
  });

  it('returns ok:false with a not-run canary under a Jest worker (no exec, no live probe)', async () => {
    expect(process.env.JEST_WORKER_ID).toBeDefined();
    const v = await runPluginSelfCheck(tmpHome, { pluginId: PLUGIN });
    expect(v.ok).toBe(false);
    expect(v.canary.ran).toBe(false);
    // Must clearly say WHY it could not confirm — never a silent pass.
    expect(v.reasons.join(' ')).toMatch(/canary|not (run|executed)/i);
  });

  it('accepts an injected canary probe so the flow is testable without the gateway', async () => {
    // Inject a passing probe + a synthetic loaded roster reader.
    const v = await runPluginSelfCheck(tmpHome, {
      pluginId: PLUGIN,
      readIndex: () => indexEnabled,
      readLiveRoster: () => liveLoaded,
      canaryProbe: async () => passingCanary,
    });
    expect(v.ok).toBe(true);
    expect(v.rosterProof).toBe(true);
    expect(v.canaryProof).toBe(true);
  });
});

describe('self-check source-shape: the live canary is guarded like a gateway restart', () => {
  it('guards the real canary on JEST_WORKER_ID and an explicit consent env before any live probe', () => {
    const thisFile = fileURLToPath(import.meta.url);
    const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw-selfcheck.ts'), 'utf-8');
    expect(src).toMatch(/JEST_WORKER_ID/);
    expect(src).toMatch(/SHIELDCORTEX_ALLOW_GATEWAY_CANARY/);
  });
});
