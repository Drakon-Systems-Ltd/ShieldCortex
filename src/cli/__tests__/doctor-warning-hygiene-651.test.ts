import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  checkHermesPluginFreshness,
  checkHermesPluginShadowing,
  doctorExitCode,
  hermesConfirmedAbsent,
  readHostGatePlanes,
  readHostGatePlanesWithPosture,
  renderPluginLoadVerdict,
  withDuplicateInstallEvidence,
} from '../doctor.js';
import { formatDoctorReport } from '../doctor-report.js';
import { reconcilePluginState, type ReconcileInput } from '../../integrations/openclaw-plugin-index.js';
import {
  resolveHermesInterpreter,
  scanHermesPluginCopies,
  searchHermesInterpreter,
} from '../../setup/hermes-plugins.js';
import { formatHostTable, scanHostTable } from '../../setup/host-table.js';
import { clearCloudConfigCache } from '../../cloud/config.js';

/**
 * #651 — doctor warning hygiene.
 *
 * Hermes cases either force the interpreter seam (`null` = none found, a
 * nonexistent path = found but cannot run) or, in the r2 block, run the real
 * resolver with PATH pinned to a fixture bin dir — so no case asks this box's
 * real Hermes, and every home is a fresh fixture under `os.tmpdir()`.
 */
const NO_INTERPRETER = { interpreter: null } as const;

let home: string;
let hermes: string;
const savedHermesHome = process.env.HERMES_HOME;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-651-'));
  hermes = path.join(home, '.hermes');
  delete process.env.HERMES_HOME;
});

afterEach(() => {
  try {
    fs.chmodSync(hermes, 0o755);
  } catch {
    /* not every case changes it */
  }
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
});

/** The issue's host: `~/.hermes` exists, holding only a leftover state dir. */
function leftoverOnly(): void {
  fs.mkdirSync(path.join(hermes, 'ekho-state'), { recursive: true });
}

describe('#651 item 1 — an absent Hermes is INFO, not WARN', () => {
  it('copies row is INFO "not detected" when the home holds no agent home and no plugins', async () => {
    leftoverOnly();
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row.status).toBe('info');
    expect(row.message).toMatch(/^skipped \(Hermes not detected/);
    expect(row.message).toContain('no plugins/ directory');
    expect(row.fix).toBeUndefined();
    expect(doctorExitCode([row], { strict: true })).toBe(0);
  });

  it('freshness row draws the same verdict as the copies row', async () => {
    leftoverOnly();
    const row = await checkHermesPluginFreshness(home, NO_INTERPRETER);
    expect(row.status).toBe('info');
    expect(row.message).toMatch(/^skipped \(Hermes not detected/);
    expect(row.message).not.toMatch(/could not determine/);
  });

  it('writes nothing while deciding', async () => {
    leftoverOnly();
    const before = fs.readdirSync(hermes).sort();
    await checkHermesPluginShadowing(home, NO_INTERPRETER);
    await checkHermesPluginFreshness(home, NO_INTERPRETER);
    expect(fs.readdirSync(hermes).sort()).toEqual(before);
  });
});

describe('#651 item 1 negative controls — uncertainty keeps its WARN', () => {
  it.each(['config.yaml', 'config.yml', 'SOUL.md'])(
    'an agent home with no interpreter still WARNs (marker %s)',
    async (marker) => {
      leftoverOnly();
      fs.writeFileSync(path.join(hermes, marker), 'x\n');
      const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
      expect(row.status).toBe('warn');
      expect(row.message).toContain('could not determine which copy Hermes loads');
      const fresh = await checkHermesPluginFreshness(home, NO_INTERPRETER);
      expect(fresh.message).toMatch(/could not determine which copy Hermes loads/);
    },
  );

  it('a profiles/ dir with no interpreter still WARNs', async () => {
    fs.mkdirSync(path.join(hermes, 'profiles', 'work'), { recursive: true });
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row.status).toBe('warn');
  });

  it('an empty plugins/ dir with no interpreter still WARNs', async () => {
    fs.mkdirSync(path.join(hermes, 'plugins'), { recursive: true });
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row.status).toBe('warn');
  });

  it('a plugin copy with no agent-home marker still WARNs and names it as a hint', async () => {
    const copy = path.join(hermes, 'plugins', 'shieldcortex');
    fs.mkdirSync(copy, { recursive: true });
    fs.writeFileSync(path.join(copy, 'plugin.yaml'), 'name: shieldcortex\n');
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row.status).toBe('warn');
    expect(row.message).toContain('Possible copies (unverified');
  });

  it('an interpreter that was found but cannot run is not absence', async () => {
    leftoverOnly();
    const opts = { interpreter: path.join(home, 'no-such-python') };
    const scan = scanHermesPluginCopies({ home, hermesHome: null }, opts);
    expect(scan.noInterpreter).toBe(false);
    const row = await checkHermesPluginShadowing(home, opts);
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/probe failed to run/);
  });

  it('HERMES_HOME set by the operator is not absence', async () => {
    leftoverOnly();
    process.env.HERMES_HOME = hermes;
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row.status).toBe('warn');
  });

  const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;
  (IS_ROOT ? it.skip : it)('a home whose entries cannot be statted is not absence', async () => {
    leftoverOnly();
    // Readable, not searchable: the home stats, its children do not (EACCES).
    fs.chmodSync(hermes, 0o644);
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row.status).not.toBe('info');
  });

  it('the predicate reads the structured flag, never the reason text', () => {
    leftoverOnly();
    const scan = scanHermesPluginCopies({ home, hermesHome: null }, NO_INTERPRETER);
    expect(scan.noInterpreter).toBe(true);
    expect(hermesConfirmedAbsent(scan, { home, hermesHome: null })).toBe(true);
    // Same reason string, flag cleared: no longer absent.
    expect(hermesConfirmedAbsent({ ...scan, noInterpreter: false }, { home, hermesHome: null })).toBe(false);
    expect(
      hermesConfirmedAbsent(
        { ...scan, undetermined: [{ path: hermes, error: 'EACCES' }] },
        { home, hermesHome: null },
      ),
    ).toBe(false);
  });

  it('no Hermes home at all is still the plain "not detected" INFO', async () => {
    const row = await checkHermesPluginShadowing(home, NO_INTERPRETER);
    expect(row).toEqual({ label: 'Hermes plugin copies', status: 'info', message: 'skipped (Hermes not detected)' });
  });
});

/**
 * #651 r2 finding 3: these go through the REAL interpreter resolver (no
 * `interpreter` seam). PATH is pinned to a fixture bin dir and the home is a
 * fixture, so nothing on this box is discovered and no interpreter is ever
 * found (so nothing is spawned). Only a search that met nothing but
 * ENOENT/ENOTDIR may read as "no interpreter".
 */
describe('#651 r2 — interpreter discovery uncertainty is not absence', () => {
  const IS_ROOT = typeof process.getuid === 'function' && process.getuid() === 0;
  const savedPath = process.env.PATH;
  let bin: string;
  const locked: string[] = [];

  beforeEach(() => {
    bin = path.join(home, 'bin');
    fs.mkdirSync(bin);
    process.env.PATH = bin;
  });

  afterEach(() => {
    for (const p of locked.splice(0)) {
      try { fs.chmodSync(p, 0o755); } catch { /* already gone */ }
    }
    process.env.PATH = savedPath;
  });

  function lock(p: string): void {
    fs.chmodSync(p, 0o000);
    locked.push(p);
  }

  function launcher(body: string): string {
    const p = path.join(bin, 'hermes');
    fs.writeFileSync(p, body, { mode: 0o755 });
    return p;
  }

  it('a search that found nothing anywhere is confirmed absence (INFO)', async () => {
    leftoverOnly();
    const search = searchHermesInterpreter(hermes);
    expect(search).toEqual({ kind: 'absent' });
    expect(resolveHermesInterpreter(hermes)).toBeNull();
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.noInterpreter).toBe(true);
    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('info');
    expect(row.message).toMatch(/^skipped \(Hermes not detected/);
  });

  (IS_ROOT ? it.skip : it)('an untraversable hermes-agent/ is not absence — copies and freshness keep WARN', async () => {
    leftoverOnly();
    const agent = path.join(hermes, 'hermes-agent');
    fs.mkdirSync(path.join(agent, '.venv', 'bin'), { recursive: true });
    lock(agent);
    const search = searchHermesInterpreter(hermes);
    expect(search.kind).toBe('undetermined');
    if (search.kind === 'undetermined') expect(search.path.startsWith(home)).toBe(true);
    expect(resolveHermesInterpreter(hermes)).toBeNull();
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.noInterpreter).toBe(false);
    expect(hermesConfirmedAbsent(scan, { home, hermesHome: null })).toBe(false);
    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(doctorExitCode([row], { strict: true })).toBe(1);
    const fresh = await checkHermesPluginFreshness(home);
    expect(fresh.message).not.toMatch(/Hermes not detected/);
  });

  it('a `hermes` launcher with an unsupported (env) shebang is not absence', async () => {
    leftoverOnly();
    const p = launcher('#!/usr/bin/env python3\nprint(1)\n');
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: p });
    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
  });

  it('a `hermes` launcher shebanged to a python that does not exist is not absence', async () => {
    leftoverOnly();
    const p = launcher(`#!${path.join(home, 'gone', 'python3')}\n`);
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: p });
    expect((await checkHermesPluginShadowing(home)).status).toBe('warn');
  });

  (IS_ROOT ? it.skip : it)('an unreadable `hermes` launcher is not absence', async () => {
    leftoverOnly();
    const p = launcher(`#!${path.join(home, 'gone', 'python3')}\n`);
    lock(p);
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: p });
    expect((await checkHermesPluginShadowing(home)).status).toBe('warn');
  });

  (IS_ROOT ? it.skip : it)('an unsearchable PATH entry is not absence', async () => {
    leftoverOnly();
    const hidden = path.join(home, 'hidden-bin');
    fs.mkdirSync(hidden);
    lock(hidden);
    process.env.PATH = [bin, hidden].join(path.delimiter);
    const search = searchHermesInterpreter(hermes);
    expect(search).toEqual({ kind: 'undetermined', path: path.join(hidden, 'hermes') });
    expect((await checkHermesPluginShadowing(home)).status).toBe('warn');
  });

  // #651 r3: `stat` follows links, so a broken link reads as ENOENT. A broken
  // launcher or venv is something the user has, never confirmed absence.
  it('a dangling venv python3 symlink is not absence — copies and freshness keep WARN', async () => {
    leftoverOnly();
    const venvBin = path.join(hermes, 'hermes-agent', '.venv', 'bin');
    fs.mkdirSync(venvBin, { recursive: true });
    const py = path.join(venvBin, 'python3');
    fs.symlinkSync(path.join(home, 'gone', 'python3.12'), py);
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: py });
    expect(resolveHermesInterpreter(hermes)).toBeNull();
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.noInterpreter).toBe(false);
    expect(hermesConfirmedAbsent(scan, { home, hermesHome: null })).toBe(false);
    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(doctorExitCode([row], { strict: true })).toBe(1);
    expect((await checkHermesPluginFreshness(home)).message).not.toMatch(/Hermes not detected/);
  });

  it('a dangling `hermes` symlink on PATH is not absence', async () => {
    leftoverOnly();
    const p = path.join(bin, 'hermes');
    fs.symlinkSync(path.join(home, 'gone', 'hermes'), p);
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'undetermined', path: p });
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.noInterpreter).toBe(false);
    const row = await checkHermesPluginShadowing(home);
    expect(row.status).toBe('warn');
    expect(doctorExitCode([row], { strict: true })).toBe(1);
  });

  it('a dangling ancestor (hermes-agent/ itself is a broken link) is not absence', async () => {
    leftoverOnly();
    fs.symlinkSync(path.join(home, 'moved-away', 'hermes-agent'), path.join(hermes, 'hermes-agent'));
    const search = searchHermesInterpreter(hermes);
    expect(search).toEqual({
      kind: 'undetermined',
      path: path.join(hermes, 'hermes-agent', '.venv', 'bin', 'python3'),
    });
    const scan = scanHermesPluginCopies({ home, hermesHome: null });
    expect(scan.noInterpreter).toBe(false);
    expect((await checkHermesPluginShadowing(home)).status).toBe('warn');
  });

  it('control: a venv python3 symlink to a real file is still found, first in order', () => {
    leftoverOnly();
    const venvBin = path.join(hermes, 'hermes-agent', '.venv', 'bin');
    fs.mkdirSync(venvBin, { recursive: true });
    const real = path.join(home, 'real-python3');
    fs.writeFileSync(real, '', { mode: 0o755 });
    const py = path.join(venvBin, 'python3');
    fs.symlinkSync(real, py);
    fs.writeFileSync(path.join(venvBin, 'python'), '', { mode: 0o755 });
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'found', interpreter: py });
    expect(resolveHermesInterpreter(hermes)).toBe(py);
  });

  it('control: a missing PATH dir and a missing venv stay confirmed absence', () => {
    leftoverOnly();
    process.env.PATH = [bin, path.join(home, 'no-such-dir')].join(path.delimiter);
    expect(searchHermesInterpreter(hermes)).toEqual({ kind: 'absent' });
  });
});

/**
 * #651 r2 finding 4: the HOSTS legend checked against planes READ FROM fixture
 * config (signed config dir, openclaw.json, Claude settings) by the real
 * `readHostGatePlanes`, not a hand-picked enum. Every path is under `home`.
 */
describe('#651 r2 — HOSTS legend matches the configuration that produced the row', () => {
  const saved = { cfg: process.env.SHIELDCORTEX_CONFIG_DIR, oc: process.env.OPENCLAW_HOME };
  let cfgDir: string;

  beforeEach(() => {
    cfgDir = path.join(home, 'sc-config');
    fs.mkdirSync(cfgDir);
    process.env.SHIELDCORTEX_CONFIG_DIR = cfgDir;
    process.env.OPENCLAW_HOME = home;
    jest.spyOn(os, 'homedir').mockReturnValue(home);
    clearCloudConfigCache();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    if (saved.cfg === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = saved.cfg;
    if (saved.oc === undefined) delete process.env.OPENCLAW_HOME;
    else process.env.OPENCLAW_HOME = saved.oc;
    clearCloudConfigCache();
  });

  function signed(actionGuard: Record<string, unknown>): void {
    fs.writeFileSync(path.join(cfgDir, 'config.json'), JSON.stringify({ actionGuard }));
    clearCloudConfigCache();
  }

  function openclawEntry(entry: Record<string, unknown>): void {
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
      plugins: { entries: { 'shieldcortex-realtime': entry } },
    }));
  }

  function claudeHookWired(): void {
    fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
    fs.writeFileSync(path.join(home, '.claude', 'settings.json'), JSON.stringify({
      hooks: { PreToolUse: [{ hooks: [{ type: 'command', command: 'npx shieldcortex hook pre-tool-use' }] }] },
    }));
  }

  function hostsText(): string {
    // #922: the header doctor prints carries the posture row's verdict.
    const planes = readHostGatePlanesWithPosture(home);
    const table = scanHostTable(home, { openclawBinaryPresent: () => true });
    return formatHostTable(table, '0.0.0', planes).join('\n');
  }

  it.each([
    ['actionGuard.enabled:false', { enabled: true, config: { actionGuard: { enabled: false } } }],
    ['interceptor.enabled:false', { enabled: true, config: { interceptor: { enabled: false } } }],
    ['enforce:false', { enabled: true, config: { actionGuard: { enabled: true, enforce: false } } }],
  ])('a plugin with %s shows observe-only, and the legend says that includes a disarmed gate', (_n, entry) => {
    signed({ enabled: false });
    openclawEntry(entry);
    expect(readHostGatePlanes(home).openclaw).toBe('observe-only');
    const text = hostsText();
    expect(text).toMatch(/OpenClaw.*observe-only/);
    expect(text).toContain('Guard off');
    expect(text).toMatch(/observe-only = entry not disabled but not\s+armed to block \(enforce false, or actionGuard\/interceptor disabled\)/);
    expect(text).not.toMatch(/observe-only = enabled/);
    expect(text).toMatch(/configured posture, not a live check/);
  });

  it('Claude Code enforcing beside an observe-only plugin is "Guard mixed", and the legend defines mixed', () => {
    signed({ enabled: true, enforce: true });
    claudeHookWired();
    openclawEntry({ enabled: true, config: { actionGuard: { enabled: false } } });
    const text = hostsText();
    expect(text).toContain('Guard mixed');
    expect(text).toMatch(/mixed = the Action guard\s+posture row fails/);
  });

  it('a disabled plugin entry shows off, which the legend defines as entry disabled', () => {
    signed({ enabled: false });
    openclawEntry({ enabled: false });
    expect(readHostGatePlanes(home).openclaw).toBe('off');
    expect(hostsText()).toMatch(/off = entry disabled/);
  });
});

describe('#651 item 4 — duplicate install dirs name observed paths, never a removal command', () => {
  const caseHome = '/home/case';
  const projects = '/home/case/.openclaw/npm/projects';
  const live = 'drakon-systems-shieldcortex-realtime-6e7e2e7717';
  const extra = `${live}__openclaw-generation__1752230000-4.47.2-abc`;
  const base: ReconcileInput = {
    pluginId: 'shieldcortex-realtime',
    expectedVersion: '4.47.2',
    config: { enabled: true, inAllow: true },
    installsJson: {
      version: '4.47.2',
      installPath: `${projects}/${live}/node_modules/@drakon-systems/shieldcortex-realtime`,
    },
    index: {
      installRecords: {
        'shieldcortex-realtime': {
          source: 'npm',
          version: '4.47.2',
          resolvedVersion: '4.47.2',
          installPath: `${projects}/${live}/node_modules/@drakon-systems/shieldcortex-realtime`,
        },
      },
      plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true, origin: 'npm' }],
      warning: null,
      generatedAtMs: 1752230565000,
    },
    onDiskVersion: '4.47.2',
    projectDirs: [live, extra],
  } as ReconcileInput;

  function render(input: ReconcileInput) {
    const verdict = reconcilePluginState(input);
    expect(verdict.state).toBe('duplicate-install');
    return withDuplicateInstallEvidence(renderPluginLoadVerdict(verdict), caseHome, input);
  }

  // #651 r2: the caution lives in the MESSAGE, which the human renderer always
  // prints in full; the fix (whose `shieldcortex repair` the honesty renderer
  // filters, discarding the whole note) is the verdict's own, unchanged.
  function noRemovalCommand(row: { message: string; fix?: string }): void {
    for (const text of [row.message, row.fix ?? '']) {
      expect(text).not.toMatch(/\brm\b|rmdir|unlink|--force|trash|action-guard-enable/);
    }
    expect(row.fix ?? '').toContain('`shieldcortex repair`');
    expect(row.message).toMatch(/inspect each .* before removing anything by hand/);
    expect(row.message).toMatch(/does not say which of these, if any, is stale or safe to delete/);
  }

  it('names every observed dir and the one the install index records', () => {
    const row = render(base);
    expect(row.status).toBe('warn');
    expect(row.message).toContain(`${projects}/${live}`);
    expect(row.message).toContain(`${projects}/${extra}`);
    expect(row.message).toContain(`install index names ${projects}/${live} as the install`);
    expect(row.message).toContain(`it does not name ${projects}/${extra}`);
    // Install state, not a load proof, and never "stale".
    expect(row.message).toMatch(/not what the running gateway loaded/);
    noRemovalCommand(row);
  });

  it('says it cannot tell when the index cannot be read', () => {
    const row = withDuplicateInstallEvidence(
      renderPluginLoadVerdict(reconcilePluginState(base)),
      caseHome,
      { ...base, index: null },
    );
    expect(row.status).toBe('warn');
    expect(row.message).toMatch(/install index could not be read/);
    expect(row.message).not.toMatch(/names .* as the install/);
    noRemovalCommand(row);
  });

  it('says it cannot tell when the index names no dir', () => {
    const row = render({
      ...base,
      index: { ...base.index!, installRecords: {}, plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true, origin: 'npm' }] },
      installsJson: null,
    });
    expect(row.message).toMatch(/names no install dir/);
    noRemovalCommand(row);
  });

  it('says so when the index names a dir that is not on disk', () => {
    const elsewhere = 'drakon-systems-shieldcortex-realtime-gone';
    const record = { ...base.index!.installRecords!['shieldcortex-realtime'], installPath: `${projects}/${elsewhere}/node_modules/x` };
    const input = { ...base, index: { ...base.index!, installRecords: { 'shieldcortex-realtime': record } } };
    const row = withDuplicateInstallEvidence(renderPluginLoadVerdict(reconcilePluginState(base)), caseHome, input);
    expect(row.message).toContain(`names ${projects}/${elsewhere}, which is not among them`);
    noRemovalCommand(row);
  });

  it.each([
    [40, false], [40, true], [100, false], [100, true],
  ])('the caution survives the human renderer (width %i, verbose %s) and no removal/enable `$` appears', (width, verbose) => {
    const row = render(base);
    const lines = formatDoctorReport([row], { width, verbose, color: false });
    const flat = lines.join(' ').replace(/\s+/g, ' ');
    expect(flat).toMatch(/does not say which of these, if any, is stale or safe to delete/);
    expect(flat).toMatch(/inspect each .* before removing anything by hand/);
    // Long paths are hard-split at narrow widths; compare with whitespace gone.
    expect(lines.join('').replace(/\s+/g, '')).toContain(`${projects}/${extra}`);
    const dollars = lines.filter((l) => l.trim().startsWith('$'));
    for (const l of dollars) expect(l).not.toMatch(/\brm\b|rmdir|unlink|repair|enable/);
    expect(flat).not.toMatch(/\brm -|rmdir|unlink/);
  });
});
