import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkHermesPluginShadowing, fixHermesPluginShadowing } from '../doctor.js';

/**
 * #569 — Hermes loads plugins by manifest `name:`, in sorted directory order,
 * and lets the LAST one win silently. A backup left beside the live plugin
 * (`plugins/shieldcortex.bak-pre510-<ts>/`) sorts after `plugins/shieldcortex/`
 * and is therefore what runs: the upgrade lands on disk and the gateway keeps
 * executing the old code, with nothing said about it anywhere.
 *
 * Every case below builds a fake home in a temp dir. The real `~/.hermes` is
 * never read and never written — `HERMES_HOME` is scrubbed per test so a
 * developer box that has it set cannot redirect the scan onto a live host.
 */
let home: string;
let hermes: string;
let plugins: string;
const savedHermesHome = process.env.HERMES_HOME;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-shadow-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  delete process.env.HERMES_HOME;
});

afterEach(() => {
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
});

/**
 * Doctor prints paths tildified. The temp dir a CI box hands out can itself
 * live under $HOME, so the tests apply the same rule rather than assuming the
 * fixture paths come out verbatim.
 */
function shown(target: string): string {
  const real = os.homedir();
  return target.startsWith(real) ? target.replace(real, '~') : target;
}

/** A plugin directory declaring `name: <manifestName>` (null = no manifest). */
function makePlugin(
  root: string,
  dirName: string,
  manifestName: string | null = 'shieldcortex',
  opts: { file?: string; body?: string } = {},
): string {
  const dir = path.join(root, dirName);
  fs.mkdirSync(dir, { recursive: true });
  if (opts.body !== undefined) {
    fs.writeFileSync(path.join(dir, opts.file ?? 'plugin.yaml'), opts.body);
  } else if (manifestName !== null) {
    fs.writeFileSync(
      path.join(dir, opts.file ?? 'plugin.yaml'),
      `# a manifest\nname: ${manifestName}\nkind: standalone\nversion: 0.1.0\n`,
    );
  }
  return dir;
}

describe('checkHermesPluginShadowing (#569)', () => {
  it('skips with info when there is no Hermes home', async () => {
    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('info');
    expect(result.message).toMatch(/Hermes not detected/);
  });

  it('passes on a single canonical copy', async () => {
    makePlugin(plugins, 'shieldcortex');
    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/one canonical/);
  });

  it('warns and names the backup as the copy Hermes loads', async () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');

    const result = await checkHermesPluginShadowing(home);

    expect(result.status).toBe('warn');
    // Every path is named…
    expect(result.message).toContain(shown(canonical));
    expect(result.message).toContain(shown(backup));
    // …and the loser/winner question is answered, not left to the reader.
    expect(result.message).toMatch(
      new RegExp(`Hermes loads ${shown(backup).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`),
    );
    expect(result.fix).toMatch(/--fix-hermes-plugin-copies/);
    expect(result.fix).toMatch(/restart the Hermes gateway/i);
  });

  it('ignores a sibling whose manifest declares a different name', async () => {
    makePlugin(plugins, 'shieldcortex');
    // Sorts after `shieldcortex`, so it would win if the key were the folder
    // name — it is not, and `ekho` cannot collide with `shieldcortex`.
    makePlugin(plugins, 'zz-other', 'ekho');

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('pass');
  });

  it('ignores a category directory', async () => {
    makePlugin(plugins, 'shieldcortex');
    // A child with no manifest is a CATEGORY: its own children are keyed
    // `zz-category/shieldcortex`, which can never collide with the flat key.
    const category = makePlugin(plugins, 'zz-category', null);
    makePlugin(category, 'shieldcortex');

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('pass');
  });

  it('ignores a dunder directory', async () => {
    makePlugin(plugins, 'shieldcortex');
    makePlugin(plugins, '__pycache__');
    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('pass');
  });

  it('skips a malformed manifest instead of throwing', async () => {
    makePlugin(plugins, 'shieldcortex');
    makePlugin(plugins, 'zz-broken', null, { body: ':\n  not: [a manifest\n' });

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('pass');
  });

  it('reads the plugin.yml spelling too', async () => {
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.old', 'shieldcortex', { file: 'plugin.yml' });

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('warn');
    expect(result.message).toContain(shown(backup));
  });

  it('scans a profile plugin root', async () => {
    makePlugin(plugins, 'shieldcortex');
    const profile = path.join(hermes, 'profiles', 'research', 'plugins');
    makePlugin(profile, 'shieldcortex');
    const profileBackup = makePlugin(profile, 'shieldcortex.bak-x');

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('warn');
    expect(result.message).toContain(shown(profileBackup));
  });

  it('honours HERMES_HOME over <home>/.hermes', async () => {
    // The default location is clean; the override is not. A check that read
    // `<home>/.hermes` would pass and miss the whole host.
    makePlugin(plugins, 'shieldcortex');
    const elsewhere = path.join(home, 'agent-home');
    const overrideBackup = makePlugin(path.join(elsewhere, 'plugins'), 'shieldcortex.bak-x');
    makePlugin(path.join(elsewhere, 'plugins'), 'shieldcortex');
    process.env.HERMES_HOME = elsewhere;

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('warn');
    expect(result.message).toContain(shown(overrideBackup));
  });
});

describe('fixHermesPluginShadowing (#569)', () => {
  it('moves the backup out of plugins/, preserving its contents', async () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-pre510-1');
    fs.mkdirSync(path.join(backup, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(backup, 'nested', 'sc_client.py'), 'old code\n');

    const fix = fixHermesPluginShadowing(home);

    expect(fix.changed).toBe(true);
    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fix.message).toMatch(/restart the Hermes gateway/);

    // Source gone from the search path, contents intact at the destination.
    expect(fs.existsSync(backup)).toBe(false);
    expect(fs.existsSync(canonical)).toBe(true);
    const dest = fix.moved[0].to;
    expect(path.dirname(dest)).toBe(path.join(hermes, 'backups'));
    expect(path.basename(dest)).toMatch(/^shieldcortex-shadow-shieldcortex\.bak-pre510-1-/);
    expect(fs.readFileSync(path.join(dest, 'nested', 'sc_client.py'), 'utf8')).toBe('old code\n');

    // And the row the operator reads is green afterwards.
    const after = await checkHermesPluginShadowing(home);
    expect(after.status).toBe('pass');
  });

  it('moves nothing when there is no canonical copy to keep', async () => {
    const onlyCopy = makePlugin(plugins, 'shieldcortex.bak-x');

    const before = await checkHermesPluginShadowing(home);
    expect(before.status).toBe('warn');
    expect(before.fix).toMatch(/human/i);

    const fix = fixHermesPluginShadowing(home);

    expect(fix.changed).toBe(false);
    expect(fix.moved).toEqual([]);
    expect(fix.refused).toHaveLength(1);
    expect(fix.refused[0].dir).toBe(onlyCopy);
    expect(fix.refused[0].reason).toMatch(/human must choose/);
    // Untouched: the only copy of the plugin stays where the host can load it.
    expect(fs.existsSync(path.join(onlyCopy, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses to overwrite an existing destination', () => {
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    // Pin the clock so the destination name is knowable, then occupy it.
    const now = new Date('2026-09-24T12:34:56.789Z');
    const dest = path.join(
      hermes,
      'backups',
      `shieldcortex-shadow-shieldcortex.bak-x-${now.toISOString().replace(/[:.]/g, '-')}`,
    );
    fs.mkdirSync(dest, { recursive: true });
    fs.writeFileSync(path.join(dest, 'someone-elses-data'), 'keep me\n');

    const fix = fixHermesPluginShadowing(home, now);

    expect(fix.changed).toBe(false);
    expect(fix.moved).toEqual([]);
    expect(fix.refused[0].reason).toMatch(/already exists/);
    // Neither side was disturbed.
    expect(fs.readFileSync(path.join(dest, 'someone-elses-data'), 'utf8')).toBe('keep me\n');
    expect(fs.existsSync(path.join(backup, 'plugin.yaml'))).toBe(true);
  });

  it('reports nothing to move when the host is already clean', () => {
    makePlugin(plugins, 'shieldcortex');
    const fix = fixHermesPluginShadowing(home);
    expect(fix.changed).toBe(false);
    expect(fix.message).toMatch(/nothing to move/);
  });

  it('says so when Hermes is not installed at all', () => {
    const fix = fixHermesPluginShadowing(home);
    expect(fix.changed).toBe(false);
    expect(fix.message).toMatch(/Hermes not detected/);
  });
});
