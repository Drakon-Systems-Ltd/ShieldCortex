import fs from 'fs';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { soleConventionalHermesCopy } from '../hermes-plugins.js';
import { hermesPluginSourceDir, refreshHermesPluginCopies } from '../hermes-refresh.js';

/**
 * #974 — the #971 fallback refresh ("Hermes cannot be asked, but there is
 * exactly one conventional copy") selected a directory's manifest with
 * `fs.existsSync`, which answers `false` for EVERY failure. A plugin directory
 * that can be statted but not searched (`chmod 600`, an ACL, a failing mount)
 * therefore looked like a directory with no manifest:
 *
 *   - one level down, under a category directory, it was skipped outright, so
 *     a second copy sitting there was never counted and the refresh went ahead;
 *   - at the root it was descended into as if it were a category, and only the
 *     listing that followed happened to notice.
 *
 * "No manifest here" and "could not find out" are different answers at every
 * depth the scan reaches, and only the first may let a write proceed.
 *
 * Every case builds a throwaway home under /tmp. The lookup failures are
 * injected at the `fs` seam so the suite means the same thing when it runs as
 * root (where a `chmod` denies nothing); one case repeats the category-depth
 * regression with a real `chmod` when the process is not root. Nothing reads
 * or writes the operator's `~/.hermes`, and no Hermes is ever spawned
 * (`interpreter: null`).
 */

const SOURCE = hermesPluginSourceDir();
const FROZEN = new Date('2026-11-14T17:00:00.000Z');

const saved = {
  HERMES_HOME: process.env.HERMES_HOME,
  HERMES_ENABLE_PROJECT_PLUGINS: process.env.HERMES_ENABLE_PROJECT_PLUGINS,
};

let home: string;
let hermes: string;
let plugins: string;
let installed: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join('/tmp', 'sc-hermes-974-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  installed = path.join(plugins, 'shieldcortex');
  fs.mkdirSync(plugins, { recursive: true });
  delete process.env.HERMES_HOME;
  delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/** What `hermes install` puts on disk, then the #576 drift. */
function installStaleCopy(): void {
  fs.cpSync(SOURCE, installed, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
  fs.writeFileSync(path.join(installed, '__init__.py'), '# shieldcortex 5.16.0\n');
}

/** A second copy of our plugin whose manifest never spells the key in bytes. */
function plantCopy(dir: string, base = 'plugin.yaml'): string {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, base), 'name: "shieldcorte\\u0078"\n');
  return dir;
}

function errno(code: string, target: string): NodeJS.ErrnoException {
  const err: NodeJS.ErrnoException = new Error(`${code}: injected, stat '${target}'`);
  err.code = code;
  err.path = target;
  return err;
}

/**
 * Make every lookup of a path matched by `hit` fail with `code`, the way the
 * kernel answers for an entry inside a directory that cannot be searched. The
 * directory itself, and every other path, behaves normally. `existsSync` is
 * given the answer Node really gives for such a path: `false`.
 */
function failLookups(hit: (target: string) => boolean, code = 'EACCES'): void {
  const matches = (target: unknown): target is string => typeof target === 'string' && hit(path.resolve(target));
  for (const method of ['statSync', 'lstatSync', 'accessSync', 'openSync'] as const) {
    const real = (fs[method] as (...args: unknown[]) => unknown).bind(fs);
    (jest.spyOn(fs, method) as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
      if (matches(args[0])) throw errno(code, args[0]);
      return real(...args);
    });
  }
  const realExists = fs.existsSync.bind(fs);
  (jest.spyOn(fs, 'existsSync') as unknown as jest.Mock).mockImplementation((...args: unknown[]) => {
    if (matches(args[0])) return false;
    return realExists(args[0] as fs.PathLike);
  });
}

/** Lookups of anything directly inside `dir` fail; `dir` itself is fine. */
function unsearchable(dir: string, code = 'EACCES'): void {
  const abs = path.resolve(dir);
  failLookups((target) => path.dirname(target) === abs, code);
}

function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (cur: string): void => {
    for (const entry of fs.readdirSync(cur, { withFileTypes: true })) {
      const full = path.join(cur, entry.name);
      const rel = path.relative(dir, full);
      if (entry.isDirectory()) {
        out.push(`${rel}/`);
        walk(full);
      } else {
        out.push(`${rel}=${fs.readFileSync(full, 'utf8')}`);
      }
    }
  };
  walk(dir);
  return out.sort();
}

function declinedReason(): string {
  const answer = soleConventionalHermesCopy(hermes);
  expect(answer).toHaveProperty('declined');
  return (answer as { declined: string }).declined;
}

describe('soleConventionalHermesCopy: a manifest lookup that fails is not an absent manifest (#974)', () => {
  it('category depth: an unsearchable plugin directory under a category declines', () => {
    installStaleCopy();
    const hidden = plantCopy(path.join(plugins, 'tools', 'old-guard'));
    unsearchable(hidden);

    const why = declinedReason();
    expect(why).toContain(hidden);
    expect(why).toContain('EACCES');
  });

  it('category depth, real permissions: chmod 600 on the plugin directory declines', () => {
    if (typeof process.getuid === 'function' && process.getuid() === 0) return; // root is denied nothing
    installStaleCopy();
    const hidden = plantCopy(path.join(plugins, 'tools', 'old-guard'));
    fs.chmodSync(hidden, 0o600);
    try {
      // The premise of #974: the directory stats, its manifest does not.
      expect(fs.statSync(hidden).isDirectory()).toBe(true);
      expect(fs.existsSync(path.join(hidden, 'plugin.yaml'))).toBe(false);

      const why = declinedReason();
      expect(why).toContain(hidden);
      expect(why).toContain('EACCES');
    } finally {
      fs.chmodSync(hidden, 0o755);
    }
  });

  it('root depth: an unsearchable directory declines, naming the manifest it could not look up', () => {
    installStaleCopy();
    const hidden = plantCopy(path.join(plugins, 'old-guard'));
    unsearchable(hidden);

    const why = declinedReason();
    expect(why).toContain(path.join(hidden, 'plugin.yaml'));
    expect(why).toContain('EACCES');
  });

  it('profile roots: an unsearchable plugin directory under a profile category declines', () => {
    installStaleCopy();
    const hidden = plantCopy(path.join(hermes, 'profiles', 'work', 'plugins', 'tools', 'old-guard'));
    unsearchable(hidden);

    const why = declinedReason();
    expect(why).toContain(hidden);
    expect(why).toContain('EACCES');
  });

  it.each(['plugin.yaml', 'plugin.yml', 'plugin.json'])(
    'one candidate (%s) that cannot be looked up declines even when the others are absent',
    (base) => {
      installStaleCopy();
      const dir = path.join(plugins, 'tools', 'old-guard');
      fs.mkdirSync(dir, { recursive: true });
      const candidate = path.join(dir, base);
      failLookups((target) => target === candidate);

      const why = declinedReason();
      expect(why).toContain(candidate);
      expect(why).toContain('EACCES');
    },
  );

  it('any failure other than ENOENT/ENOTDIR is uncertainty (EIO)', () => {
    installStaleCopy();
    const hidden = plantCopy(path.join(plugins, 'tools', 'old-guard'));
    unsearchable(hidden, 'EIO');

    const why = declinedReason();
    expect(why).toContain(hidden);
    expect(why).toContain('EIO');
  });

  it('control: ENOENT and ENOTDIR on every candidate are genuine absence', () => {
    installStaleCopy();
    const empty = path.join(plugins, 'tools', 'not-a-plugin');
    fs.mkdirSync(empty, { recursive: true });
    for (const code of ['ENOENT', 'ENOTDIR']) {
      unsearchable(empty, code);
      expect(soleConventionalHermesCopy(hermes)).toEqual({ dir: installed });
      jest.restoreAllMocks();
    }
  });

  it('control: a readable category tree with no manifests still yields the sole copy', () => {
    installStaleCopy();
    fs.mkdirSync(path.join(plugins, 'tools', 'not-a-plugin'), { recursive: true });
    fs.writeFileSync(path.join(plugins, 'tools', 'not-a-plugin', 'README.md'), 'notes\n');

    expect(soleConventionalHermesCopy(hermes)).toEqual({ dir: installed });
  });

  it('control: a readable second copy at category depth is still counted', () => {
    installStaleCopy();
    const second = plantCopy(path.join(plugins, 'tools', 'old-guard'));

    expect(declinedReason()).toContain(second);
  });

  it.each(['plugin.yml', 'plugin.json'])('control: a readable %s at category depth is still counted', (base) => {
    installStaleCopy();
    const second = plantCopy(path.join(plugins, 'tools', 'old-guard'), base);

    expect(declinedReason()).toContain(second);
  });
});

describe('refreshHermesPluginCopies: discovery cannot be asked (#974)', () => {
  it('an unsearchable plugin directory at category depth: writes nothing', () => {
    installStaleCopy();
    const hidden = plantCopy(path.join(plugins, 'tools', 'old-guard'));
    const before = snapshot(hermes);
    unsearchable(hidden);

    const result = refreshHermesPluginCopies(home, { now: FROZEN, scan: { interpreter: null } });

    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(result.summary).toMatch(/nothing written/);
    jest.restoreAllMocks();
    expect(snapshot(hermes)).toEqual(before);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
  });

  it('control: the same tree without the second copy is refreshed', () => {
    installStaleCopy();
    fs.mkdirSync(path.join(plugins, 'tools', 'not-a-plugin'), { recursive: true });

    const result = refreshHermesPluginCopies(home, { now: FROZEN, scan: { interpreter: null } });

    expect(result.status).toBe('refreshed');
    expect(result.refreshed.map((r) => r.dir)).toEqual([installed]);
  });
});
