/**
 * Failing-first specs for #150 and #142 — no log artifact may be treated as
 * authoritative for process state.
 *
 * Three defects in one week were the same mistake wearing different clothes:
 * #142 read a boot-time roster snapshot as a live roster; #150 read a
 * months-stale log as the running version (a Mac reported v4.14.10 "running"
 * off a line written in May); #145 echoed a pre-remediation snapshot as the
 * post-remediation state. The rule pinned here: evidence about the running
 * gateway must postdate that gateway's process start, and evidence that cannot
 * be dated cannot be called fresh.
 */
import { describe, it, expect } from '@jest/globals';
import { readRunningGatewayProcess } from '../integrations/openclaw-gateway-process.js';
import {
  parseRegistrationsSince,
  findRegistrationSince,
} from '../integrations/openclaw-gateway-roster.js';
import { evaluateSelfCheck } from '../setup/openclaw-selfcheck.js';
import { reconcilePluginState, type ReconcileInput } from '../integrations/openclaw-plugin-index.js';
import {
  parseRunningPluginVersionSince,
  checkOpenClawRunningPluginVersion,
} from '../cli/doctor.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

const PLUGIN = 'shieldcortex-realtime';

// ── The process-start fact ──────────────────────────────────────────────────

describe('readRunningGatewayProcess — a recorded boot is only evidence while its pid lives', () => {
  it('returns the boot row when the pid is alive', () => {
    const proc = readRunningGatewayProcess('/nonexistent-home', {
      readLatestBootRow: () => ({ pid: 4242, started_at_ms: 1_700_000_000_000 }),
      isPidAlive: (pid) => pid === 4242,
    });
    expect(proc).toEqual({ pid: 4242, startedAtMs: 1_700_000_000_000 });
  });

  it('returns null when the recorded pid is dead — a past boot proves nothing about now', () => {
    const proc = readRunningGatewayProcess('/nonexistent-home', {
      readLatestBootRow: () => ({ pid: 4242, started_at_ms: 1_700_000_000_000 }),
      isPidAlive: () => false,
    });
    expect(proc).toBeNull();
  });

  it('returns null when there is no lifecycle row at all', () => {
    const proc = readRunningGatewayProcess('/nonexistent-home', {
      readLatestBootRow: () => null,
      isPidAlive: () => true,
    });
    expect(proc).toBeNull();
  });
});

// ── Registration sightings (#142) ───────────────────────────────────────────

describe('parseRegistrationsSince — dated lines only, bounded below', () => {
  const line = (iso: string, v: string) =>
    JSON.stringify({ time: iso, message: `[shieldcortex] v${v} registered (llm_input + before_tool_call)` });

  it('returns sightings at/after the bound and drops older ones', () => {
    const text = [
      line('2026-05-07T10:00:00.000Z', '4.14.10'),
      line('2026-08-01T05:52:55.000Z', '4.47.22'),
    ].join('\n');
    const since = Date.parse('2026-08-01T05:52:00.000Z');
    const got = parseRegistrationsSince(text, since);
    expect(got).toHaveLength(1);
    expect(got[0].version).toBe('4.47.22');
  });

  it('skips registration lines that carry no parseable timestamp', () => {
    // A line that cannot be dated cannot be called fresh.
    const text = '[shieldcortex] v9.9.9 registered (llm_input)';
    expect(parseRegistrationsSince(text, 0)).toHaveLength(0);
  });

  it('#214 — attributes a journald unit[pid] so a CLI line is not the gateway', () => {
    const iso = '2026-08-08T14:04:00.000Z';
    const text = [
      JSON.stringify({ time: iso, pid: 4242, message: '[shieldcortex] v4.47.32 registered (llm_input)' }),
      `2026-08-08T14:04:01.000Z host shieldcortex[9999]: [shieldcortex] v4.50.0 registered (llm_input)`,
      `2026-08-08T14:04:02.000Z host openclaw-gateway[4242]: [shieldcortex] v4.47.32 registered (llm_input)`,
    ].join('\n');
    const got = parseRegistrationsSince(text, Date.parse('2026-08-08T14:00:00.000Z'));
    expect(got.map((s) => s.pid)).toEqual([4242, 9999, 4242]);
    expect(got.map((s) => s.version)).toEqual(['4.47.32', '4.50.0', '4.47.32']);
  });

  it('#214 — running version ignores a registration whose pid is not the gateway', () => {
    const iso = '2026-08-08T14:04:00.000Z';
    const text = [
      `${iso} host openclaw-gateway[111]: [shieldcortex] v4.47.32 registered (llm_input)`,
      `${iso} host shieldcortex[999]: [shieldcortex] v4.50.0 registered (llm_input)`,
    ].join('\n');
    expect(parseRunningPluginVersionSince(text, Date.parse('2026-08-08T14:00:00.000Z'), 111)).toBe('4.47.32');
    expect(parseRunningPluginVersionSince(text, Date.parse('2026-08-08T14:00:00.000Z'), 111)).not.toBe('4.50.0');
  });

  it('findRegistrationSince returns null when the log dir is unreadable', () => {
    expect(findRegistrationSince(0, { logDir: '/definitely/not/a/dir' })).toBeNull();
  });
});

// ── #142 in the self-check ─────────────────────────────────────────────────

describe('#142 — a post-snapshot registration downgrades absent to unproven', () => {
  const canaryPassed = { ran: true, denied: true, auditEntryFound: true };

  it('absent WITHOUT a later sighting stays absent (the aiquant genuine skip)', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: false,
      canary: canaryPassed,
    });
    expect(v.rosterState).toBe('absent');
  });

  it('absent WITH a later sighting becomes unproven — the snapshot cannot convict', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: true,
      canary: canaryPassed,
    });
    expect(v.rosterState).toBe('unproven');
    expect(v.reasons.join(' ')).toMatch(/registration was sighted after/i);
    // And it must not accuse.
    expect(v.reasons.join(' ')).not.toMatch(/host unprotected/i);
  });

  it('a later sighting never GRANTS the roster proof — CLI lines are identical', () => {
    const v = evaluateSelfCheck({
      pluginId: PLUGIN,
      index: null,
      liveRoster: ['telegram'],
      registrationSeenAfterBoot: true,
      canary: canaryPassed,
    });
    expect(v.rosterProof).toBe(false);
    expect(v.ok).toBe(false);
  });
});

// ── #142 in the reconciler ─────────────────────────────────────────────────

describe('#142 — the reconciler withholds UNPROTECTED when registration raced the snapshot', () => {
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
    liveRoster: ['telegram'],
  };

  it('without a sighting: the confident fail stands (rule 2 unchanged)', () => {
    const v = reconcilePluginState({ ...base, registrationSeenAfterBoot: false });
    expect(v.state).toBe('enabled-not-loaded');
    expect(v.severity).toBe('fail');
  });

  it('with a sighting: warn + unproven, pointing at the canary — never a fail', () => {
    const v = reconcilePluginState({ ...base, registrationSeenAfterBoot: true });
    expect(v.state).toBe('load-unproven');
    expect(v.severity).toBe('warn');
    expect(v.reasons.join(' ')).toMatch(/canary/i);
  });
});

// ── #150 in doctor ─────────────────────────────────────────────────────────

describe('#150 — the running version is bounded by the gateway process start', () => {
  const journalLine = (iso: string, v: string) =>
    JSON.stringify({ time: iso, message: `[shieldcortex] v${v} registered (llm_input)` });

  it('parseRunningPluginVersionSince ignores lines older than the bound', () => {
    const journal = [
      journalLine('2026-05-07T10:00:00.000Z', '4.14.10'),
      journalLine('2026-08-01T05:52:55.000Z', '4.47.22'),
    ].join('\n');
    expect(parseRunningPluginVersionSince(journal, Date.parse('2026-08-01T00:00:00Z'))).toBe('4.47.22');
    expect(parseRunningPluginVersionSince(journal, Date.parse('2026-08-02T00:00:00Z'))).toBeNull();
  });

  it("the Mac's exact state: a May line + an August process start yields UNKNOWN, not v4.14.10", async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-150-'));
    try {
      fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
      // Fake an installed plugin so the check proceeds to the journal.
      const pluginDir = path.join(
        home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-x__openclaw-generation__g-1',
        'node_modules', '@drakon-systems', 'shieldcortex-realtime',
      );
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(path.join(pluginDir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '4.47.23' }));
      fs.writeFileSync(path.join(pluginDir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '4.47.23' }));

      const result = await checkOpenClawRunningPluginVersion(home, {
        readGatewayJournal: () => ({ text: journalLine('2026-05-07T10:00:00.000Z', '4.14.10'), preBounded: false }),
        readGatewayProcessStartMs: () => Date.parse('2026-08-01T05:00:00.000Z'),
      });
      expect(result.status).toBe('info');
      expect(result.message).toMatch(/UNKNOWN/);
      // The stale figure may be mentioned as historical, never asserted as running.
      expect(result.message).not.toMatch(/v4\.14\.10 running/);
      expect(result.message).toMatch(/predates this process/i);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('reports honestly when the process start cannot be established', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-150b-'));
    try {
      fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
      const pluginDir = path.join(
        home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-x__openclaw-generation__g-1',
        'node_modules', '@drakon-systems', 'shieldcortex-realtime',
      );
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(path.join(pluginDir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '4.47.23' }));
      fs.writeFileSync(path.join(pluginDir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '4.47.23' }));

      const result = await checkOpenClawRunningPluginVersion(home, {
        readGatewayJournal: () => ({ text: journalLine('2026-08-01T05:52:55.000Z', '4.47.23'), preBounded: false }),
        readGatewayProcessStartMs: () => null,
      });
      expect(result.status).toBe('info');
      expect(result.message).toMatch(/start time could not be established/i);
      // Never a confident "running" claim off unbounded evidence.
      expect(result.message).not.toMatch(/running v4\.47\.23 matches/);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });

  it('still passes when a fresh registration matches disk', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-150c-'));
    try {
      fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
      const pluginDir = path.join(
        home, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-x__openclaw-generation__g-1',
        'node_modules', '@drakon-systems', 'shieldcortex-realtime',
      );
      fs.mkdirSync(pluginDir, { recursive: true });
      fs.writeFileSync(path.join(pluginDir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '4.47.23' }));
      fs.writeFileSync(path.join(pluginDir, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '4.47.23' }));

      const result = await checkOpenClawRunningPluginVersion(home, {
        readGatewayJournal: () => ({ text: journalLine('2026-08-01T05:52:55.000Z', '4.47.23'), preBounded: false }),
        readGatewayProcessStartMs: () => Date.parse('2026-08-01T05:00:00.000Z'),
      });
      expect(result.status).toBe('pass');
      expect(result.message).toMatch(/running v4\.47\.23 matches/);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
    }
  });
});
