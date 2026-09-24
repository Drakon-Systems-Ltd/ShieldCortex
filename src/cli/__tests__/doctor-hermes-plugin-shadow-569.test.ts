import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
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
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
});

/**
 * Every destination name is derived from a timestamp, so anything that computes
 * one twice — once to stage a collision, once inside the fix — has to freeze the
 * clock or it goes flaky the moment the two calls straddle a second boundary.
 */
const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const STAMP = FROZEN.toISOString().replace(/[:.]/g, '-');

/** The parent directory the fix reserves for one copy, at the frozen clock. */
function reservedFor(dirName: string, suffix = ''): string {
  return path.join(hermes, 'backups', `shieldcortex-shadow-${dirName}-${STAMP}${suffix}`);
}

/**
 * Force the conservative reader. The default path spawns the Hermes
 * interpreter, which is the right thing on a box that has one; these cases are
 * about what a box WITHOUT one reports, so they say so explicitly rather than
 * depending on the absence of Hermes.
 */
const NO_HERMES = { interpreter: null } as const;

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

  it('sees through an inline # comment on the backup manifest', async () => {
    // Round 1 compared the whole rest of the line, so `shieldcortex # backup`
    // was not `shieldcortex` and this host was reported CLEAN while Hermes was
    // loading the backup. The row's whole value is being right about this.
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x', null, {
      body: 'name: shieldcortex # backup\nkind: standalone\n',
    });

    const result = await checkHermesPluginShadowing(home);

    expect(result.status).toBe('warn');
    expect(result.message).toContain(shown(backup));
  });

  it('counts a canonical manifest with no name: as the canonical copy', async () => {
    // Hermes falls back to the directory name. Round 1 required a `name:` line,
    // so it saw only the backup, and the fix then refused to move anything
    // because it believed there was no canonical copy to keep.
    makePlugin(plugins, 'shieldcortex', null, { body: 'version: 1\n' });
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');

    const result = await checkHermesPluginShadowing(home);

    expect(result.status).toBe('warn');
    expect(result.message).toContain('2 copies');
    expect(result.fix).toMatch(/--fix-hermes-plugin-copies/);

    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect((await checkHermesPluginShadowing(home)).status).toBe('pass');
  });

  it('ignores a plugin.yaml directory that hides a valid plugin.yml', async () => {
    // Hermes selects on `exists()`, hits the directory, fails to parse and
    // takes NOTHING from that child. Falling through to the `.yml` would invent
    // a shadow and send an operator to move a directory that is not loaded.
    makePlugin(plugins, 'shieldcortex');
    const decoy = path.join(plugins, 'shieldcortex.decoy');
    fs.mkdirSync(path.join(decoy, 'plugin.yaml'), { recursive: true });
    fs.writeFileSync(path.join(decoy, 'plugin.yml'), 'name: shieldcortex\n');

    const result = await checkHermesPluginShadowing(home);
    expect(result.status).toBe('pass');
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

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.changed).toBe(true);
    expect(fix.failed).toBe(false);
    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fix.message).toMatch(/restart the Hermes gateway/);

    // Source gone from the search path, contents intact at the destination.
    // The copy lands INSIDE the reserved parent, under its own name, so the
    // reservation and the payload are two different directories.
    expect(fs.existsSync(backup)).toBe(false);
    expect(fs.existsSync(canonical)).toBe(true);
    const dest = fix.moved[0].to;
    expect(dest).toBe(path.join(reservedFor('shieldcortex.bak-pre510-1'), 'shieldcortex.bak-pre510-1'));
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

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.changed).toBe(false);
    expect(fix.moved).toEqual([]);
    expect(fix.refused).toHaveLength(1);
    expect(fix.refused[0].dir).toBe(onlyCopy);
    expect(fix.refused[0].reason).toMatch(/human must choose/);
    // A designed refusal, not a failure: nothing was asked of the operator that
    // an exit code would tell them twice.
    expect(fix.failed).toBe(false);
    // Untouched: the only copy of the plugin stays where the host can load it.
    expect(fs.existsSync(path.join(onlyCopy, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('reports nothing to move when the host is already clean', () => {
    makePlugin(plugins, 'shieldcortex');
    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.changed).toBe(false);
    expect(fix.failed).toBe(false);
    expect(fix.message).toMatch(/nothing to move/);
  });

  it('says so when Hermes is not installed at all', () => {
    const fix = fixHermesPluginShadowing(home, FROZEN);
    expect(fix.changed).toBe(false);
    expect(fix.message).toMatch(/Hermes not detected/);
  });
});

/**
 * Never overwrite (review blocker 3). An existence check before a rename has
 * two holes the review named: a DANGLING symlink is "absent" to `exists()` but
 * very much present to `rename()`, and anything can appear in the window
 * between the check and the move. The destination is therefore RESERVED with an
 * exclusive `mkdir`, and the copy goes inside it.
 */
describe('fixHermesPluginShadowing reserves its destination (#569)', () => {
  it('goes to a fresh name rather than into an occupied one', () => {
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const taken = reservedFor('shieldcortex.bak-x');
    fs.mkdirSync(taken, { recursive: true });
    fs.writeFileSync(path.join(taken, 'someone-elses-data'), 'keep me\n');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.changed).toBe(true);
    expect(fix.moved[0].to).toBe(path.join(reservedFor('shieldcortex.bak-x', '-2'), 'shieldcortex.bak-x'));
    // The occupant is untouched, and so is everything it held.
    expect(fs.readFileSync(path.join(taken, 'someone-elses-data'), 'utf8')).toBe('keep me\n');
    expect(fs.readdirSync(taken)).toEqual(['someone-elses-data']);
    expect(fs.existsSync(backup)).toBe(false);
  });

  it('treats a dangling destination symlink as occupied', () => {
    makePlugin(plugins, 'shieldcortex');
    makePlugin(plugins, 'shieldcortex.bak-x');
    const taken = reservedFor('shieldcortex.bak-x');
    fs.mkdirSync(path.dirname(taken), { recursive: true });
    // Points at nothing: `fs.existsSync(taken)` is FALSE, which is exactly the
    // hole an existence check leaves open.
    fs.symlinkSync(path.join(home, 'no-such-target'), taken);
    expect(fs.existsSync(taken)).toBe(false);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.changed).toBe(true);
    expect(fix.moved[0].to).toBe(path.join(reservedFor('shieldcortex.bak-x', '-2'), 'shieldcortex.bak-x'));
    // The link is still a link, still dangling — nothing was written through it.
    expect(fs.lstatSync(taken).isSymbolicLink()).toBe(true);
    expect(fs.readlinkSync(taken)).toBe(path.join(home, 'no-such-target'));
    expect(fs.existsSync(path.join(home, 'no-such-target'))).toBe(false);
  });

  it('survives a destination that appears between check and move', () => {
    makePlugin(plugins, 'shieldcortex');
    makePlugin(plugins, 'shieldcortex.bak-x');
    const contested = reservedFor('shieldcortex.bak-x');

    // Simulate the race the review described: something else creates the
    // destination at the exact moment we reach for it. With an exclusive
    // `mkdir` there is no window to lose — the create IS the check — so the
    // squatter wins the name and we take the next one.
    const realMkdir = fs.mkdirSync.bind(fs) as typeof fs.mkdirSync;
    let squatted = false;
    jest.spyOn(fs, 'mkdirSync').mockImplementation(((target: fs.PathLike, options?: unknown) => {
      if (!squatted && String(target) === contested) {
        squatted = true;
        realMkdir(target, { recursive: true });
        fs.writeFileSync(path.join(contested, 'raced-in'), 'mine\n');
        const err: NodeJS.ErrnoException = new Error(`EEXIST: file already exists, mkdir '${contested}'`);
        err.code = 'EEXIST';
        throw err;
      }
      return realMkdir(target, options as never);
    }) as typeof fs.mkdirSync);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(squatted).toBe(true);
    expect(fix.changed).toBe(true);
    expect(fix.moved[0].to).toBe(path.join(reservedFor('shieldcortex.bak-x', '-2'), 'shieldcortex.bak-x'));
    expect(fs.readFileSync(path.join(contested, 'raced-in'), 'utf8')).toBe('mine\n');
  });

  it('leaves everything in place on a cross-device move', () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(backup, 'marker'), 'old code\n');

    jest.spyOn(fs, 'renameSync').mockImplementation(() => {
      const err: NodeJS.ErrnoException = new Error('EXDEV: cross-device link not permitted, rename');
      err.code = 'EXDEV';
      throw err;
    });

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    // Non-zero from the CLI: the host is still shadowed and a human has to act.
    expect(fix.failed).toBe(true);
    expect(fix.refused).toHaveLength(1);
    expect(fix.refused[0].dir).toBe(backup);
    expect(fix.refused[0].reason).toMatch(/different filesystem/);
    expect(fix.refused[0].reason).toMatch(/EXDEV/);
    expect(fix.refused[0].reason).toMatch(/by hand/);
    // No copy-then-discard: the source is whole and the backups tree holds
    // nothing at all, not even the reservation that was made for the move.
    expect(fs.readFileSync(path.join(backup, 'marker'), 'utf8')).toBe('old code\n');
    expect(fs.existsSync(canonical)).toBe(true);
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toEqual([]);
  });
});

/**
 * Never break the canonical install (review blocker 4). Each case below is a
 * layout where the repair, done naively, relocates the bytes the live plugin
 * path depends on — and then the re-run check reports PASS because it can no
 * longer find any copies at all.
 */
describe('fixHermesPluginShadowing protects the canonical install (#569)', () => {
  it('refuses when the canonical path is a symlink to the backup', async () => {
    const real = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(real, 'marker'), 'the only bytes\n');
    // `plugins/shieldcortex` is not a directory at all — it is a link to the
    // backup. Moving `shieldcortex.bak-x` would leave it dangling.
    fs.symlinkSync('shieldcortex.bak-x', path.join(plugins, 'shieldcortex'));

    const before = await checkHermesPluginShadowing(home);
    expect(before.status).toBe('warn');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused.map((r) => r.reason).join(' ')).toMatch(/is itself a symlink/);
    // The canonical path still resolves to real bytes.
    expect(fs.readFileSync(path.join(plugins, 'shieldcortex', 'marker'), 'utf8')).toBe(
      'the only bytes\n',
    );
    expect(fs.existsSync(path.join(real, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses a relative symlink backup', () => {
    makePlugin(plugins, 'shieldcortex');
    const elsewhere = makePlugin(path.join(hermes, 'kept-aside'), 'sc-old');
    fs.writeFileSync(path.join(elsewhere, 'marker'), 'old code\n');
    // Relative link text: renaming the link into backups/ would re-resolve it
    // against a different parent and point it at nothing.
    fs.symlinkSync(path.join('..', 'kept-aside', 'sc-old'), path.join(plugins, 'shieldcortex.bak-x'));

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused[0].reason).toMatch(/is a symlink/);
    expect(fs.lstatSync(path.join(plugins, 'shieldcortex.bak-x')).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(path.join(elsewhere, 'marker'), 'utf8')).toBe('old code\n');
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses a backup symlinked to a tree outside plugins/', () => {
    makePlugin(plugins, 'shieldcortex');
    const outside = makePlugin(path.join(home, 'srv'), 'sc-old');
    fs.symlinkSync(outside, path.join(plugins, 'shieldcortex.bak-x'));

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused[0].reason).toMatch(/is a symlink/);
    expect(fs.existsSync(path.join(outside, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('refuses a backup that resolves onto the canonical install itself', () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    fs.writeFileSync(path.join(canonical, 'marker'), 'installed\n');
    // Two names, one directory. The naive repair moves `shieldcortex.bak-x`,
    // which IS `shieldcortex`, and takes the live plugin with it.
    fs.symlinkSync('shieldcortex', path.join(plugins, 'shieldcortex.bak-x'));

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused[0].reason).toMatch(/same tree as/);
    expect(fs.readFileSync(path.join(canonical, 'marker'), 'utf8')).toBe('installed\n');
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('moves a copy visible through two plugin roots exactly once', () => {
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    // A profile whose `plugins/` is the main one: the same physical directory
    // is discovered under two roots, and one rename repairs both.
    const profile = path.join(hermes, 'profiles', 'research');
    fs.mkdirSync(profile, { recursive: true });
    fs.symlinkSync(plugins, path.join(profile, 'plugins'));

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fix.failed).toBe(false);
    expect(fix.refused).toEqual([]);
  });
});

/**
 * Honesty about which half answered. On a host with no Hermes interpreter the
 * conservative reader answers, and every surface says so — a health check that
 * quietly downgrades its own source of truth is how round 1 shipped six wrong
 * answers.
 */
describe('checkHermesPluginShadowing labels an approximate answer (#569)', () => {
  it('marks a shadow found without Hermes as approximate', async () => {
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');

    const result = await checkHermesPluginShadowing(home, NO_HERMES);

    expect(result.status).toBe('warn');
    expect(result.message).toContain('approximate: Hermes discovery not reachable');
    expect(result.message).toMatch(/no Hermes interpreter/);
    expect(result.message).toContain(shown(backup));
  });

  it('marks a clean host found without Hermes as approximate', async () => {
    makePlugin(plugins, 'shieldcortex');
    const result = await checkHermesPluginShadowing(home, NO_HERMES);
    expect(result.status).toBe('pass');
    expect(result.message).toContain('approximate: Hermes discovery not reachable');
  });

  it('does not label an answer that came from Hermes itself', async () => {
    makePlugin(plugins, 'shieldcortex');
    const result = await checkHermesPluginShadowing(home);
    // On a box with no Hermes at all this still holds: the message is then
    // labelled, and this asserts only that the label tracks the source.
    const { scanHermesPluginCopies } = await import('../../setup/hermes-plugins.js');
    const scan = scanHermesPluginCopies(path.join(home, '.hermes'));
    expect(result.message.includes('approximate')).toBe(!scan.fromHermes);
  });

  it('refuses to call a host clean while a manifest is unreadable without Hermes', async () => {
    makePlugin(plugins, 'shieldcortex');
    // A valid `name:` line above YAML the fallback reader does not model. It
    // mentions our key, so it could be a shadow — Hermes would know; this
    // reader will not guess.
    const murky = makePlugin(plugins, 'zz-murky', null, {
      body: 'name: shieldcortex\nkind: [unclosed\n',
    });

    const result = await checkHermesPluginShadowing(home, NO_HERMES);

    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/could not be classified without Hermes/);
    expect(result.message).toContain(shown(murky));
    expect(result.fix).toMatch(/Hermes/);

    // Hermes itself has no such doubt: it rejects the manifest outright.
    const authoritative = await checkHermesPluginShadowing(home);
    const { scanHermesPluginCopies } = await import('../../setup/hermes-plugins.js');
    if (scanHermesPluginCopies(path.join(home, '.hermes')).fromHermes) {
      expect(authoritative.status).toBe('pass');
    }
  });

  it('does not touch a directory it could not classify', () => {
    makePlugin(plugins, 'shieldcortex');
    const murky = makePlugin(plugins, 'zz-murky', null, {
      body: 'name: shieldcortex\nkind: [unclosed\n',
    });

    const fix = fixHermesPluginShadowing(home, FROZEN, NO_HERMES);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused[0].dir).toBe(murky);
    expect(fix.refused[0].reason).toMatch(/could not read without Hermes/);
    expect(fix.message).toMatch(/approximate/);
    expect(fs.existsSync(path.join(murky, 'plugin.yaml'))).toBe(true);
  });
});

/**
 * Round-3 blocker 1+2. The fallback used to guess at manifests it did not
 * model, and the guesses were wrong in both directions — so a root holding one
 * now has NO winner and NO clean bill, and the repair does not touch it.
 */
describe('an undetermined root is neither clean nor shadowed (#569 r3)', () => {
  /** The shape that broke round 2: Hermes reads it, the line reader cannot. */
  const BLOCK_SCALAR_NAME = 'name: >-\n  shieldcortex\n';

  it('names no winner even when two confirmed copies are sitting there', async () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const murky = makePlugin(plugins, 'zz-murky', null, { body: BLOCK_SCALAR_NAME });

    const result = await checkHermesPluginShadowing(home, NO_HERMES);

    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/could not determine which copy Hermes loads/);
    expect(result.message).toContain(shown(murky));
    // Both real copies are still named — those are facts.
    expect(result.message).toContain(shown(canonical));
    expect(result.message).toContain(shown(backup));
    // But no winner is claimed: `zz-murky` sorts last and may well be the one
    // Hermes loads, which is exactly what could not be worked out. (The two
    // "which copy Hermes loads" phrasings say there is no answer, so the thing
    // to look for is `Hermes loads <a path>`.)
    expect(result.message).not.toMatch(/Hermes loads \S*shieldcortex/);
    expect(result.message).not.toMatch(/\d+ copies \(/);
    expect(result.fix).toMatch(/Install the Hermes agent virtualenv/);
  });

  it('moves nothing in that root, not even the obvious backup', () => {
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(backup, 'marker'), 'old code\n');
    const murky = makePlugin(plugins, 'zz-murky', null, { body: BLOCK_SCALAR_NAME });

    const fix = fixHermesPluginShadowing(home, FROZEN, NO_HERMES);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.failed).toBe(true);
    expect(fix.refused.map((r) => r.dir)).toEqual([murky, backup]);
    expect(fix.refused[1].reason).toMatch(/which copy the gateway loads here is unknown/);
    // Every byte where it was, and no backups/ tree invented for a move that
    // never happened.
    expect(fs.readFileSync(path.join(backup, 'marker'), 'utf8')).toBe('old code\n');
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('leaves a determined root alone rather than freezing the whole host', () => {
    // The undetermined root is a profile; the main root is ordinary and gets
    // repaired. Uncertainty is per-root, and so is the refusal.
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const profile = path.join(hermes, 'profiles', 'research', 'plugins');
    makePlugin(profile, 'shieldcortex');
    makePlugin(profile, 'zz-murky', null, { body: BLOCK_SCALAR_NAME });

    const fix = fixHermesPluginShadowing(home, FROZEN, NO_HERMES);

    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fix.refused.map((r) => r.dir)).toEqual([path.join(profile, 'zz-murky')]);
  });
});

/**
 * Round-3 blocker 3: the repair must look across ALL plugin roots before it
 * moves anything.
 *
 * The layout the reviewer found is one a per-root check cannot see. The main
 * root holds two ordinary, unrelated directories, so it passes every local
 * test; the work profile's canonical install is a symlink INTO it. Move the
 * backup and that profile's plugin path dangles — and the profile's own scan
 * had already been skipped as clean, so a re-run reports PASS on a host whose
 * plugin has just been taken away.
 */
describe('fixHermesPluginShadowing preflights every root (#569 r3)', () => {
  /** The reviewer's exact layout; `linkTarget` decides relative vs absolute. */
  function buildEntangledHost(relative: boolean): {
    canonical: string;
    backup: string;
    profileLink: string;
  } {
    const canonical = makePlugin(plugins, 'shieldcortex');
    fs.writeFileSync(path.join(canonical, 'marker'), 'installed\n');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    fs.writeFileSync(path.join(backup, 'marker'), 'the profile runs this\n');

    const profilePlugins = path.join(hermes, 'profiles', 'work', 'plugins');
    fs.mkdirSync(profilePlugins, { recursive: true });
    const profileLink = path.join(profilePlugins, 'shieldcortex');
    fs.symlinkSync(
      relative ? path.join('..', '..', '..', 'plugins', 'shieldcortex.bak-x') : backup,
      profileLink,
    );
    return { canonical, backup, profileLink };
  }

  function expectNothingMoved(
    fix: ReturnType<typeof fixHermesPluginShadowing>,
    layout: { canonical: string; backup: string; profileLink: string },
  ): void {
    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    // Non-zero from the CLI: the host is still shadowed and a human has to act.
    expect(fix.failed).toBe(true);
    // The refusal names the dependent path, not just "something depends on it".
    const reasons = fix.refused.map((r) => r.reason).join(' ');
    expect(reasons).toContain(shown(layout.profileLink));
    expect(reasons).toMatch(/nothing was moved/);

    // Both canonical installations still resolve to their own bytes.
    expect(fs.readFileSync(path.join(layout.canonical, 'marker'), 'utf8')).toBe('installed\n');
    expect(fs.readFileSync(path.join(layout.profileLink, 'marker'), 'utf8')).toBe(
      'the profile runs this\n',
    );
    expect(fs.readFileSync(path.join(layout.backup, 'marker'), 'utf8')).toBe(
      'the profile runs this\n',
    );
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  }

  it('refuses when a profile canonical is a RELATIVE symlink to the backup', () => {
    const layout = buildEntangledHost(true);
    expectNothingMoved(fixHermesPluginShadowing(home, FROZEN), layout);
  });

  it('refuses when a profile canonical is an ABSOLUTE symlink to the backup', () => {
    const layout = buildEntangledHost(false);
    expectNothingMoved(fixHermesPluginShadowing(home, FROZEN), layout);
  });

  it('refuses on the conservative reader too, not only via Hermes', () => {
    const layout = buildEntangledHost(true);
    expectNothingMoved(fixHermesPluginShadowing(home, FROZEN, NO_HERMES), layout);
  });

  it('refuses when a profile install lives INSIDE the directory being moved', () => {
    // Not a link to the copy but a link into it: moving the copy takes the
    // profile's install along with it.
    const canonical = makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const nested = makePlugin(backup, 'inner');
    fs.writeFileSync(path.join(nested, 'marker'), 'nested install\n');
    const profilePlugins = path.join(hermes, 'profiles', 'work', 'plugins');
    fs.mkdirSync(profilePlugins, { recursive: true });
    const profileLink = path.join(profilePlugins, 'shieldcortex');
    fs.symlinkSync(nested, profileLink);

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toEqual([]);
    expect(fix.failed).toBe(true);
    expect(fix.refused.map((r) => r.reason).join(' ')).toContain(shown(profileLink));
    expect(fs.readFileSync(path.join(nested, 'marker'), 'utf8')).toBe('nested install\n');
    expect(fs.existsSync(path.join(canonical, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('still moves an ordinary backup when the other roots are independent', () => {
    // The preflight must not freeze every host that happens to have a profile.
    makePlugin(plugins, 'shieldcortex');
    const backup = makePlugin(plugins, 'shieldcortex.bak-x');
    const profile = path.join(hermes, 'profiles', 'work', 'plugins');
    makePlugin(profile, 'shieldcortex');

    const fix = fixHermesPluginShadowing(home, FROZEN);

    expect(fix.moved).toHaveLength(1);
    expect(fix.moved[0].from).toBe(backup);
    expect(fix.failed).toBe(false);
    expect(fix.refused).toEqual([]);
    expect(fs.existsSync(path.join(profile, 'shieldcortex', 'plugin.yaml'))).toBe(true);
  });
});
