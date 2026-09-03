import { describe, expect, it } from '@jest/globals';
import {
  parseBootRosterLine,
  parseLatestBootRoster,
  readLatestBootRoster,
  rosterContains,
} from '../integrations/openclaw-gateway-roster.js';
import { reconcilePluginState, type ReconcileInput } from '../integrations/openclaw-plugin-index.js';

/**
 * Regression suite for field incident #103 (veronica, 19–26 Jul 2026).
 *
 * `shieldcortex repair` printed "enabled, loaded in roster, versions agree"
 * for six days while the running gateway had booted WITHOUT the plugin. The
 * reconciler was reading the SQLite install index and calling it the roster.
 * These tests pin the distinction: install state ≠ load state.
 */

// Real lines, copied from clawdbot1 and veronica gateway logs.
const JARVIS_LINE =
  '2026-07-26T10:28:52.378+00:00 [gateway] http server listening (14 plugins: acpx, anthropic, browser, codex, ekho-adapter, elevenlabs, google, memory-core, microsoft, multi-clawd, openai, shieldcortex-realtime, telegram, xai; 4.0s)';
/** clawdbot1 OpenClaw 2026.8.2 journal, issue #459. Consent-inactive is in the registration line, not the listen list. */
const JARVIS_2026_09_LINE =
  '2026-09-02T06:12:47.000Z [gateway] http server listening (14 plugins: acpx, anthropic, browser, codex, ekho-adapter, elevenlabs, memory-core, microsoft, multi-clawd, openai, shieldcortex-realtime, signal, telegram, xai; 5.1s)';
const VERONICA_LINE =
  '2026-07-20T00:16:51.758+01:00 [gateway] http server listening (11 plugins: anthropic, browser, canvas, device-pair, ekho-adapter, file-transfer, memory-core, ollama, phone-control, talk-voice, telegram; 1.1s)';

describe('parseBootRosterLine', () => {
  it('parses a roster line into ids, declared count and timestamp', () => {
    const r = parseBootRosterLine(JARVIS_LINE);
    expect(r).not.toBeNull();
    expect(r!.declaredCount).toBe(14);
    expect(r!.plugins).toHaveLength(14);
    expect(r!.plugins).toContain('shieldcortex-realtime');
    expect(r!.atMs).toBe(Date.parse('2026-07-26T10:28:52.378+00:00'));
  });

  it('parses the veronica line and does NOT find the plugin', () => {
    const r = parseBootRosterLine(VERONICA_LINE);
    expect(r!.declaredCount).toBe(11);
    expect(r!.plugins).toHaveLength(11);
    expect(rosterContains(r!, 'shieldcortex-realtime')).toBe(false);
  });

  it('handles the zero-plugin shape with no id list', () => {
    const r = parseBootRosterLine('2026-07-20T00:00:00.000Z [gateway] http server listening (0 plugins; 1.2s)');
    expect(r).not.toBeNull();
    expect(r!.declaredCount).toBe(0);
    expect(r!.plugins).toEqual([]);
  });

  it('parses the JSON-per-line file format the gateway also writes', () => {
    const json = JSON.stringify({
      message: 'http server listening (2 plugins: telegram, shieldcortex-realtime; 0.9s)',
      time: '2026-07-26T10:28:52.378+00:00',
    });
    const r = parseBootRosterLine(json);
    expect(r!.plugins).toEqual(['telegram', 'shieldcortex-realtime']);
  });

  it('returns null for unrelated lines', () => {
    expect(parseBootRosterLine('[gateway] ready')).toBeNull();
    expect(parseBootRosterLine('')).toBeNull();
  });

  it('declaredCount and parsed ids agree on real lines (guards list truncation)', () => {
    for (const line of [JARVIS_LINE, VERONICA_LINE, JARVIS_2026_09_LINE]) {
      const r = parseBootRosterLine(line)!;
      expect(r.plugins).toHaveLength(r.declaredCount);
    }
  });

  it('#459: the 2026-09-02 clawdbot1 listen line names shieldcortex-realtime', () => {
    const r = parseBootRosterLine(JARVIS_2026_09_LINE)!;
    expect(r.declaredCount).toBe(14);
    expect(rosterContains(r, 'shieldcortex-realtime')).toBe(true);
    expect(r.plugins).toContain('signal');
  });
});

describe('parseLatestBootRoster', () => {
  it('takes the LAST roster line — a log spans many boots, only the newest is live', () => {
    const text = [VERONICA_LINE, '[gateway] ready', JARVIS_LINE, 'noise'].join('\n');
    const r = parseLatestBootRoster(text)!;
    expect(r.declaredCount).toBe(14);
    expect(rosterContains(r, 'shieldcortex-realtime')).toBe(true);
  });

  it('returns null when no roster line is present', () => {
    expect(parseLatestBootRoster('nothing\nto\nsee')).toBeNull();
  });
});

describe('readLatestBootRoster', () => {
  const files: Record<string, string> = {
    'openclaw-2026-07-25.log': VERONICA_LINE,
    'openclaw-2026-07-26.log': JARVIS_LINE,
    'not-a-log.txt': JARVIS_LINE,
  };
  const mtimes: Record<string, number> = {
    'openclaw-2026-07-25.log': 1000,
    'openclaw-2026-07-26.log': 2000,
  };
  const io = {
    logDir: '/tmp/openclaw',
    readDir: () => Object.keys(files),
    readFile: (f: string) => files[f.split('/').pop()!],
    statMtimeMs: (f: string) => mtimes[f.split('/').pop()!] ?? 0,
  };

  it('reads the newest log file and reports its source', () => {
    const r = readLatestBootRoster(io)!;
    expect(r.declaredCount).toBe(14);
    expect(r.source).toBe('/tmp/openclaw/openclaw-2026-07-26.log');
  });

  it('returns null when the log dir cannot be read', () => {
    expect(
      readLatestBootRoster({
        readDir: () => {
          throw new Error('ENOENT');
        },
      }),
    ).toBeNull();
  });

  it('returns null when no openclaw-*.log files exist', () => {
    expect(readLatestBootRoster({ ...io, readDir: () => ['other.txt'] })).toBeNull();
  });

  it('SAFETY: rejects a roster line older than the running process', () => {
    // A line from a previous boot proves nothing about the process running now.
    const stale = readLatestBootRoster({
      ...io,
      processStartedAtMs: Date.parse('2026-07-26T10:28:52.378+00:00') + 1,
    });
    expect(stale).toBeNull();
  });

  it('accepts a roster line at or after the process start', () => {
    const live = readLatestBootRoster({
      ...io,
      processStartedAtMs: Date.parse('2026-07-26T10:28:52.378+00:00'),
    });
    expect(live).not.toBeNull();
  });

  it('#459: journal text is consulted before /tmp/openclaw when injected', () => {
    const r = readLatestBootRoster({
      ...io,
      readDir: () => ['other.txt'],
      processStartedAtMs: Date.parse('2026-09-02T06:12:26.000Z'),
      readJournalText: () => JARVIS_2026_09_LINE,
    });
    expect(r).not.toBeNull();
    expect(rosterContains(r!, 'shieldcortex-realtime')).toBe(true);
    expect(r!.source).toBe('journal');
  });
});

describe('reconcilePluginState — #103 live roster overrides the install index', () => {
  /** Veronica's exact state on 26 Jul: installed, enabled, allow-listed, index
   * says enabled — and the running gateway booted without it. */
  const veronica: ReconcileInput = {
    pluginId: 'shieldcortex-realtime',
    expectedVersion: '4.47.10',
    config: { enabled: true, inAllow: true },
    installsJson: { version: '4.47.10', installPath: '/home/mike/.openclaw/npm/projects/x' },
    index: {
      installRecords: {
        'shieldcortex-realtime': {
          source: 'npm',
          version: '4.47.10',
          installPath: '/home/mike/.openclaw/npm/projects/x',
        },
      },
      plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true }],
    },
    onDiskVersion: '4.47.10',
    projectDirs: ['drakon-systems-shieldcortex-realtime-6e7e2e7717'],
    liveRoster: parseBootRosterLine(VERONICA_LINE)!.plugins,
  };

  it('SECURITY: the #103 false positive is now a hard fail, not healthy', () => {
    const v = reconcilePluginState(veronica);
    expect(v.state).toBe('enabled-not-loaded');
    expect(v.severity).toBe('fail');
    expect(v.loadedInIndex).toBe(true); // install index still says enabled…
    expect(v.loadedInLiveRoster).toBe(false); // …but the gateway never loaded it.
    expect(v.reasons.join(' ')).toMatch(/ABSENT from the RUNNING gateway boot roster/);
  });

  it('says out loud that the index disagrees, so the operator can see why', () => {
    const v = reconcilePluginState(veronica);
    expect(v.reasons.join(' ')).toMatch(/install state, not load state/);
  });

  it('is healthy when the live roster DOES name the plugin', () => {
    const v = reconcilePluginState({
      ...veronica,
      expectedVersion: '4.47.16',
      onDiskVersion: '4.47.16',
      liveRoster: parseBootRosterLine(JARVIS_LINE)!.plugins,
    });
    expect(v.state).toBe('healthy');
    expect(v.loadedInLiveRoster).toBe(true);
    expect(v.reasons.join(' ')).toMatch(/present on the running gateway boot roster/);
  });

  it('HONESTY: an unreadable live roster must not be reported as "loaded"', () => {
    const v = reconcilePluginState({ ...veronica, liveRoster: null });
    expect(v.loadedInLiveRoster).toBeNull();
    expect(v.reasons.join(' ')).toMatch(/could NOT be read/);
    expect(v.reasons.join(' ')).not.toMatch(/present on the running gateway boot roster/);
  });

  it('a live roster proving load survives an unreadable SQLite index', () => {
    const v = reconcilePluginState({
      ...veronica,
      expectedVersion: '4.47.16',
      onDiskVersion: '4.47.16',
      index: null,
      liveRoster: parseBootRosterLine(JARVIS_LINE)!.plugins,
    });
    expect(v.state).not.toBe('index-unreadable');
    expect(v.loadedInLiveRoster).toBe(true);
  });
});
