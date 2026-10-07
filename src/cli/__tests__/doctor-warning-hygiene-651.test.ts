import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  checkHermesPluginFreshness,
  checkHermesPluginShadowing,
  doctorExitCode,
  hermesConfirmedAbsent,
  renderPluginLoadVerdict,
  withDuplicateInstallEvidence,
} from '../doctor.js';
import { reconcilePluginState, type ReconcileInput } from '../../integrations/openclaw-plugin-index.js';
import { scanHermesPluginCopies } from '../../setup/hermes-plugins.js';

/**
 * #651 — doctor warning hygiene.
 *
 * Every Hermes case forces the interpreter seam (`null` = none found, a
 * nonexistent path = found but cannot run), so no case asks this box's real
 * Hermes, and every home is a fresh fixture under `os.tmpdir()`.
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

  function noRemovalCommand(fix: string | undefined): void {
    expect(fix ?? '').not.toMatch(/\brm\b|rmdir|unlink|--force|trash/);
    expect(fix ?? '').toContain('`shieldcortex repair`');
    expect(fix ?? '').toMatch(/inspect the ones listed/);
    expect(fix ?? '').toMatch(/does not say which is safe to delete/);
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
    noRemovalCommand(row.fix);
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
    noRemovalCommand(row.fix);
  });

  it('says it cannot tell when the index names no dir', () => {
    const row = render({
      ...base,
      index: { ...base.index!, installRecords: {}, plugins: [{ pluginId: 'shieldcortex-realtime', enabled: true, origin: 'npm' }] },
      installsJson: null,
    });
    expect(row.message).toMatch(/names no install dir/);
    noRemovalCommand(row.fix);
  });

  it('says so when the index names a dir that is not on disk', () => {
    const elsewhere = 'drakon-systems-shieldcortex-realtime-gone';
    const record = { ...base.index!.installRecords!['shieldcortex-realtime'], installPath: `${projects}/${elsewhere}/node_modules/x` };
    const input = { ...base, index: { ...base.index!, installRecords: { 'shieldcortex-realtime': record } } };
    const row = withDuplicateInstallEvidence(renderPluginLoadVerdict(reconcilePluginState(base)), caseHome, input);
    expect(row.message).toContain(`names ${projects}/${elsewhere}, which is not among them`);
    noRemovalCommand(row.fix);
  });
});
