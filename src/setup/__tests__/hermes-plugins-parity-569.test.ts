import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import {
  hintDirsInRoot,
  probeHermesDiscovery,
  resolveHermesInterpreter,
  scanHermesPluginCopies,
} from '../hermes-plugins.js';
import { checkHermesPluginShadowing, fixHermesPluginShadowing } from '../../cli/doctor.js';

/**
 * #569 — the detector must never disagree with Hermes about which directory
 * gets the `shieldcortex` key and which one wins it.
 *
 * Round 1 mirrored the discovery rules in a line reader. Round 2 asked Hermes
 * on the primary path but kept a guessing reader for hosts with none. Round 3
 * narrowed that reader to a grammar it was supposed to be certain about.
 * Independent review found a confident wrong answer in EVERY version:
 *
 *   - `name: >-` with an indented name (reported clean while Hermes loaded the
 *     backup);
 *   - `description: backup: before upgrade` (labelled LOADED where Hermes
 *     rejects the manifest);
 *   - `name: "shieldcorte\u0078"` (the escape left undecoded, so the copy that
 *     Hermes loads was missed);
 *   - `description: 2026-99-99` (YAML reads an invalid timestamp and Hermes
 *     drops the manifest, where the grammar happily accepted the line);
 *   - `manifest_version: .inf` (YAML builds infinity and Hermes' `int()`
 *     conversion raises).
 *
 * The last two are ordinary-looking lines: the disagreement lives in YAML's
 * implicit typing and Hermes' own conversion code, not in exotic syntax. So
 * round 4 removed the reader, and the contract these tests pin is:
 *
 *   Hermes' own discovery answers, or NOTHING answers. Without it the check is
 *   WARN, names no winner, and the repair moves nothing.
 *
 * Both halves run over the same trees. Every `hermes` expectation below was
 * recorded by running Hermes' own `scan_directory` + `resolve_manifest_winners`
 * over these exact trees.
 */

const SCHEMA_V1 = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';

interface ParityCase {
  name: string;
  /** Builds one `plugins/` root. */
  build: (root: string) => void;
  /** What Hermes' own discovery reports for this tree. */
  hermes: { copies: string[]; winner: string | null };
  /**
   * A path in this tree that nobody could READ, and the error naming it (#569
   * r8). Absent means the whole tree is readable, which is the normal case:
   * every fixture here is built by this file at ordinary modes. The one that
   * has it holds a `plugin.yaml` that is a DIRECTORY, so Hermes' own read of
   * it raises — the copies and the winner below are still Hermes' answer, but
   * the scan says it did not read that path rather than certifying the root.
   */
  unreadable?: { dir: string; file: string; error: RegExp };
}

function write(target: string, body: string): void {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, body);
}

function manifest(root: string, dirName: string, body: string, file = 'plugin.yaml'): void {
  write(path.join(root, dirName, file), body);
}

const CASES: ParityCase[] = [
  {
    // Hermes parses YAML, so ` # backup` is a comment and the name is
    // `shieldcortex`. A reader that compares the whole rest of the line sees
    // `shieldcortex # backup`, misses the shadow, and calls the host clean.
    name: 'an inline # comment after the name',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.bak-x', 'name: shieldcortex # backup\n');
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.bak-x'], winner: 'shieldcortex.bak-x' },
  },
  {
    // `data.get("name", plugin_dir.name)`: no `name:` key at all means the
    // DIRECTORY name is the key.
    name: 'a manifest with no name: at all',
    build: (root) => {
      manifest(root, 'shieldcortex', 'version: 1\n');
      manifest(root, 'zz-nameless', 'version: 1\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    name: 'quoted names, single and double',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: "shieldcortex"\n');
      manifest(root, 'shieldcortex.q', "name: 'shieldcortex'   # old\n");
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.q'], winner: 'shieldcortex.q' },
  },
  {
    // A portable Agent Plugins v1 package has no plugin.yaml at all, and Hermes
    // accepts it after `agent_plugins._validate_manifest`.
    name: 'a portable plugin.json manifest',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      write(
        path.join(root, 'shieldcortex.portable', 'plugin.json'),
        JSON.stringify({ $schema: SCHEMA_V1, name: 'shieldcortex', version: '1.0.0' }),
      );
      write(
        path.join(root, 'shieldcortex.badjson', 'plugin.json'),
        JSON.stringify({ name: 'shieldcortex' }),
      );
      write(path.join(root, 'shieldcortex.notjson', 'plugin.json'), '{not json');
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.portable'], winner: 'shieldcortex.portable' },
  },
  {
    // Hermes selects the manifest with `Path.exists()`, not `is_file()`. A
    // `plugin.yaml` DIRECTORY is therefore selected, fails to parse, and Hermes
    // takes NOTHING from that child — it never looks at the `plugin.yml`.
    name: 'a plugin.yaml directory beside a valid plugin.yml',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      fs.mkdirSync(path.join(root, 'shieldcortex.dirmanifest', 'plugin.yaml'), { recursive: true });
      manifest(root, 'shieldcortex.dirmanifest', 'name: shieldcortex\n', 'plugin.yml');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
    unreadable: {
      dir: 'shieldcortex.dirmanifest',
      file: 'plugin.yaml',
      error: /IsADirectoryError/,
    },
  },
  {
    // A valid `name:` line above broken YAML: Hermes' safe_load raises and
    // `parse_manifest_file` returns None, so the directory is not a copy.
    name: 'invalid YAML after a valid name: line',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.broken', 'name: shieldcortex\nkind: [unclosed\n');
      manifest(root, 'shieldcortex.broken2', 'name: shieldcortex\n\tkind: standalone\n');
      manifest(root, 'shieldcortex.broken3', 'name: shieldcortex\n:\n  not: [a manifest\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // Dunder children and per-harness manifest dirs are skipped before any
    // manifest is read, a manifest-less child is a category keyed
    // `<cat>/<name>`, a different `name:` cannot collide, `plugin.yml` counts.
    name: 'dunder, foreign-harness, category, other name, plugin.yml',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, '__pycache__', 'name: shieldcortex\n');
      manifest(root, '.claude-plugin', 'name: shieldcortex\n');
      manifest(path.join(root, 'zz-category'), 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'zz-other', 'name: ekho\n');
      manifest(root, 'shieldcortex.yml-spelling', 'name: shieldcortex\n', 'plugin.yml');
    },
    hermes: {
      copies: ['shieldcortex', 'shieldcortex.yml-spelling'],
      winner: 'shieldcortex.yml-spelling',
    },
  },
  {
    // YAML wins the selection outright: a plugin.json beside a plugin.yaml is
    // never read, so a differently-named YAML is not a shadow even when the
    // JSON claims our name.
    name: 'plugin.yaml takes precedence over plugin.json',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.both', 'name: something-else\n');
      write(
        path.join(root, 'shieldcortex.both', 'plugin.json'),
        JSON.stringify({ $schema: SCHEMA_V1, name: 'shieldcortex' }),
      );
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // An empty manifest parses to `{}`, so the name is the directory name.
    name: 'an empty plugin.yaml',
    build: (root) => {
      manifest(root, 'shieldcortex', '');
      manifest(root, 'zz-empty', '');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // A sequence at the top level is not a Mapping, and Hermes rejects it.
    name: 'a top-level sequence document',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.list', '- name: shieldcortex\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    name: 'no copy at all',
    build: (root) => {
      manifest(root, 'kanban', 'name: kanban\n');
    },
    hermes: { copies: [], winner: null },
  },

  // ── The round-3 differential fixtures ──────────────────────────────────
  {
    // THE round-2 blocker. Hermes reads the folded scalar, gets `shieldcortex`
    // and LOADS the backup. Round 2 saw a shape it did not model, decided the
    // name was absent, keyed the directory on its own name, and reported a
    // clean canonical install.
    name: 'a block-scalar name Hermes reads and loads',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.bak-x', 'name: >-\n  shieldcortex\n');
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.bak-x'], winner: 'shieldcortex.bak-x' },
  },
  {
    // The same blocker in the other direction. `description: backup: before
    // upgrade` is not YAML — Hermes raises and drops the manifest.
    name: 'invalid YAML from a colon in a later value',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(
        root,
        'shieldcortex.bak-y',
        'name: shieldcortex\ndescription: backup: before upgrade\n',
      );
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // `agent_plugins._validate_manifest` requires plugin.json to resolve INSIDE
    // the plugin root, so Hermes rejects this one.
    name: 'a plugin.json symlinked outside the plugin root',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      const outside = path.join(path.dirname(root), 'outside');
      write(
        path.join(outside, 'plugin.json'),
        JSON.stringify({ $schema: SCHEMA_V1, name: 'shieldcortex', version: '1.0.0' }),
      );
      const linked = path.join(root, 'shieldcortex.linked');
      fs.mkdirSync(linked, { recursive: true });
      fs.symlinkSync(path.join(outside, 'plugin.json'), path.join(linked, 'plugin.json'));
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // `author` may hold only name/email/url. An unknown field raises, so Hermes
    // takes nothing from this directory.
    name: 'a plugin.json with an unknown author field',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      write(
        path.join(root, 'shieldcortex.authored', 'plugin.json'),
        JSON.stringify({
          $schema: SCHEMA_V1,
          name: 'shieldcortex',
          version: '1.0.0',
          author: { name: 'a', twitter: 'b' },
        }),
      );
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },

  // ── The round-4 fixtures: ordinary lines, typed by YAML ────────────────
  {
    // Recorded live: Hermes keys the backup `shieldcortex` and LOADS it. The
    // literal bytes `shieldcortex` never appear in that manifest's name value —
    // the escape spells the final `x` — so even the raw-substring hint would
    // only find it through the folder name.
    name: 'a unicode escape in a double-quoted name',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.bak-esc', 'name: "shieldcorte\\u0078"\n');
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.bak-esc'], winner: 'shieldcortex.bak-esc' },
  },
  {
    // Round-4 blocker, half one. `2026-99-99` is a plain scalar the grammar
    // accepted without a second look; YAML's implicit typing reads it as a
    // TIMESTAMP, month 99 fails construction, and Hermes rejects the whole
    // manifest. Recorded live: the backup is not a copy at all.
    name: 'a date-shaped value YAML cannot construct',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.bak-date', 'name: shieldcortex\ndescription: 2026-99-99\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // Round-4 blocker, half two. `.inf` constructs as a float infinity, and
    // Hermes' manifest conversion calls `int()` on it, which raises
    // OverflowError outside the narrow handler. Recorded live: rejected.
    name: 'an infinite manifest_version Hermes cannot convert',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.bak-inf', 'name: shieldcortex\nmanifest_version: .inf\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
];

let fixtures: string;
/** Case name → the fake Hermes HOME (`<case>`), whose `.hermes/plugins` is the root. */
const homes = new Map<string, string>();
/** Case name → the `plugins/` root itself. */
const roots = new Map<string, string>();
const savedHermesHome = process.env.HERMES_HOME;

/** Frozen so a destination name computed twice cannot straddle a second. */
const FROZEN = new Date('2026-09-24T12:34:56.789Z');

beforeAll(() => {
  delete process.env.HERMES_HOME;
  fixtures = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-parity-'));
  CASES.forEach((testCase, index) => {
    // One Hermes home per case: a collision is per-root, so mixing cases into
    // one root would make the winner meaningless.
    const home = path.join(fixtures, `case-${index}`);
    const root = path.join(home, '.hermes', 'plugins');
    fs.mkdirSync(root, { recursive: true });
    testCase.build(root);
    homes.set(testCase.name, home);
    roots.set(testCase.name, root);
  });
});

afterAll(() => {
  fs.rmSync(fixtures, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
});

/** The Hermes interpreter this box can offer, resolved once. */
const interpreter = resolveHermesInterpreter(path.join(os.homedir(), '.hermes'));

/**
 * Force the "no Hermes to ask" path. A box WITH a working Hermes would never
 * otherwise reach it, and that path is the whole subject of round 4.
 */
const NO_HERMES = { interpreter: null } as const;

/** Every directory under a tree, so "nothing moved" can be asserted exactly. */
function snapshot(dir: string): string[] {
  const out: string[] = [];
  const walk = (current: string): void => {
    for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) =>
      a.name < b.name ? -1 : 1,
    )) {
      const full = path.join(current, entry.name);
      out.push(path.relative(dir, full));
      if (entry.isDirectory() && !entry.isSymbolicLink()) walk(full);
    }
  };
  walk(dir);
  return out;
}

describe('without Hermes there is no verdict at all (#569 r4)', () => {
  it.each(CASES)('reports unknown rather than an answer on: $name', async (testCase) => {
    const home = homes.get(testCase.name)!;

    const scan = scanHermesPluginCopies({ home, hermesHome: null }, NO_HERMES);
    expect(scan.fromHermes).toBe(false);
    expect(scan.undeterminedReason).toMatch(/no Hermes interpreter/i);
    // No copies, no winner, no shadow verdict — the three things every earlier
    // round produced from a reader of its own, and got wrong.
    expect(scan.roots).toEqual([]);
    expect(scan.copies).toEqual([]);
    expect(scan.shadowed).toBe(false);

    const row = await checkHermesPluginShadowing(home, NO_HERMES);
    expect(row.status).toBe('warn');
    expect(row.message).toContain('could not determine which copy Hermes loads');
    expect(row.message).toContain('Install Hermes, or point the doctor at its python.');
    // Never a winner: the one claim that made a shadowed host look healthy.
    // "which copy Hermes loads" is the question; "Hermes loads <path>" is the
    // answer, and this row is not entitled to give one.
    expect(row.message).not.toMatch(/Hermes loads [~/]/);
    expect(row.message).not.toMatch(/last in sorted order wins/);
    expect(row.message).not.toMatch(/\bclean\b/);
  });

  it.each(CASES)('moves nothing and exits non-zero on: $name', (testCase) => {
    const home = homes.get(testCase.name)!;
    const before = snapshot(home);

    const fix = fixHermesPluginShadowing(home, FROZEN, NO_HERMES);

    expect(fix.moved).toEqual([]);
    expect(fix.changed).toBe(false);
    expect(fix.failed).toBe(true);
    expect(fix.fromHermes).toBe(false);
    expect(fix.message).toContain('nothing was moved');
    expect(fix.message).toContain('could not determine which copy Hermes loads');
    expect(snapshot(home)).toEqual(before);
    expect(fs.existsSync(path.join(home, '.hermes', 'backups'))).toBe(false);
  });

  it('offers hints, and never lets them read as a verdict', async () => {
    // The hint is a folder-name prefix or a raw substring — no parsing. Both
    // halves are wrong in both directions, which is exactly why they are
    // labelled unverified and never counted as copies.
    const home = homes.get('a block-scalar name Hermes reads and loads')!;
    const row = await checkHermesPluginShadowing(home, NO_HERMES);
    expect(row.message).toContain('Possible copies (unverified');
    expect(row.message).toContain(path.join('.hermes', 'plugins', 'shieldcortex.bak-x'));
    expect(row.status).toBe('warn');
  });

  it('lists a hint by folder name and by raw manifest substring, and nothing else', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-hint-'));
    try {
      manifest(tmp, 'shieldcortex.bak-x', 'name: >-\n  anything\n'); // folder name
      manifest(tmp, 'zz-mentions', 'name: other\ndescription: replaces shieldcortex\n'); // text
      manifest(tmp, 'zz-unrelated', 'name: kanban\n');
      manifest(tmp, '__pycache__', 'name: shieldcortex\n'); // Hermes skips dunder
      manifest(tmp, '.claude-plugin', 'name: shieldcortex\n'); // and harness dirs
      fs.mkdirSync(path.join(tmp, 'zz-category'), { recursive: true }); // no manifest
      expect(hintDirsInRoot(tmp).map((d) => path.basename(d))).toEqual([
        'shieldcortex.bak-x',
        'zz-mentions',
      ]);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });
});

// The primary path needs a Hermes to ask. Skipped cleanly, not faked, where
// there is none — a green run that never spawned anything would be a lie.
const describePrimary = interpreter === null ? describe.skip : describe;

describePrimary(`primary path via Hermes itself (${interpreter ?? 'no interpreter'})`, () => {
  it.each(CASES)('Hermes reports the recorded copies and winner: $name', (testCase) => {
    const root = roots.get(testCase.name)!;
    const probe = probeHermesDiscovery(
      { home: homes.get(testCase.name)!, hermesHome: null },
      { interpreter },
    );
    expect('roots' in probe ? null : probe.error).toBeNull();
    if (!('roots' in probe)) return;
    // Hermes' own root set for a home with no profiles: exactly `plugins/`.
    expect(probe.roots.map((r) => r.root)).toEqual([root]);
    expect(probe.roots[0].copies.map((c) => path.basename(c))).toEqual(testCase.hermes.copies);
    expect(probe.roots[0].loaded === null ? null : path.basename(probe.roots[0].loaded)).toBe(
      testCase.hermes.winner,
    );
  });

  it('answers every fixture — Hermes never reports an unknown', () => {
    // The contract that replaced the differential one: where Hermes answers,
    // the answer is complete. There is no third state to reconcile.
    for (const testCase of CASES) {
      const scan = scanHermesPluginCopies(
        { home: homes.get(testCase.name)!, hermesHome: null },
        { interpreter },
      );
      if (testCase.unreadable !== undefined) {
        // A tree with a path nobody read is not a tree with a verdict (#569
        // r8): the scan names that path and withdraws, which is a complete
        // answer to a different question and still not a third state.
        const root = roots.get(testCase.name)!;
        const { dir, file, error } = testCase.unreadable;
        expect(scan.fromHermes).toBe(false);
        expect(scan.undetermined).toEqual([
          { path: path.join(root, dir, file), error: expect.stringMatching(error) },
        ]);
        continue;
      }
      expect(scan.fromHermes).toBe(true);
      expect(scan.undeterminedReason).toBeNull();
      expect(scan.undetermined).toEqual([]);
      expect(scan.hintRoots).toEqual([]);
      expect(scan.copies.map((c) => c.dirName)).toEqual(testCase.hermes.copies);
      expect(scan.roots[0].loaded?.dirName ?? null).toBe(testCase.hermes.winner);
    }
  });

  it('flags the canonical copy as canonical and the backup as not', () => {
    const scan = scanHermesPluginCopies(
      { home: homes.get('an inline # comment after the name')!, hermesHome: null },
      { interpreter },
    );
    expect(scan.roots[0].copies.map((c) => c.canonical)).toEqual([true, false]);
    expect(scan.roots[0].hasCanonical).toBe(true);
    expect(scan.roots[0].shadowed).toBe(true);
  });
});

describe('interpreter resolution (#569)', () => {
  it('prefers the agent virtualenv inside the Hermes home', () => {
    const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-interp-'));
    try {
      const bin = path.join(fake, 'hermes-agent', '.venv', 'bin');
      fs.mkdirSync(bin, { recursive: true });
      const python = path.join(bin, 'python3');
      fs.writeFileSync(python, '#!/bin/sh\n');
      expect(resolveHermesInterpreter(fake)).toBe(python);
    } finally {
      fs.rmSync(fake, { recursive: true, force: true });
    }
  });

  it('falls back to the shebang of a hermes launcher on PATH', () => {
    const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-interp-'));
    const savedPath = process.env.PATH;
    try {
      const python = path.join(fake, 'python3.12');
      fs.writeFileSync(python, '# a stand-in interpreter\n');
      const binDir = path.join(fake, 'bin');
      fs.mkdirSync(binDir);
      fs.writeFileSync(path.join(binDir, 'hermes'), `#!${python}\nimport sys\n`);
      process.env.PATH = binDir;
      // No venv under this home, so the launcher is the only candidate left.
      expect(resolveHermesInterpreter(path.join(fake, 'nonexistent-home'))).toBe(python);
    } finally {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
      fs.rmSync(fake, { recursive: true, force: true });
    }
  });

  it('refuses a shebang it cannot spawn with confidence', () => {
    const fake = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-interp-'));
    const savedPath = process.env.PATH;
    try {
      const binDir = path.join(fake, 'bin');
      fs.mkdirSync(binDir, { recursive: true });
      // `#!/usr/bin/env python3` names no interpreter path we can resolve, and
      // a shell wrapper names one that cannot import hermes_cli.
      fs.writeFileSync(path.join(binDir, 'hermes'), '#!/usr/bin/env python3\n');
      process.env.PATH = binDir;
      expect(resolveHermesInterpreter(path.join(fake, 'nonexistent-home'))).toBeNull();
      fs.writeFileSync(path.join(binDir, 'hermes'), '#!/bin/sh\nexec hermes-real "$@"\n');
      expect(resolveHermesInterpreter(path.join(fake, 'nonexistent-home'))).toBeNull();
    } finally {
      if (savedPath === undefined) delete process.env.PATH;
      else process.env.PATH = savedPath;
      fs.rmSync(fake, { recursive: true, force: true });
    }
  });

  it('reports why, rather than "no copies", when there is no interpreter', () => {
    const probe = probeHermesDiscovery(
      { home: homes.get('an inline # comment after the name')!, hermesHome: null },
      { interpreter: null },
    );
    expect('error' in probe).toBe(true);
    if ('error' in probe) expect(probe.error).toMatch(/no Hermes interpreter/i);
  });

  it('reports why when the interpreter cannot import Hermes discovery', () => {
    // A real Python with no hermes_cli on its path: the probe must come back as
    // an error the caller can print, not as an empty scan.
    const probe = probeHermesDiscovery(
      { home: homes.get('an inline # comment after the name')!, hermesHome: null },
      { interpreter: process.execPath },
    );
    expect('error' in probe).toBe(true);
  });

  it('reports why when the interpreter path does not exist at all', () => {
    // The "bogus interpreter" seam: the reason has to survive to the caller so
    // doctor can print it, rather than being flattened to "no copies".
    const probe = probeHermesDiscovery(
      { home: homes.get('an inline # comment after the name')!, hermesHome: null },
      { interpreter: path.join(os.tmpdir(), 'sc-no-such-python-569') },
    );
    expect('error' in probe).toBe(true);
    if ('error' in probe) expect(probe.error).toMatch(/failed to run|ENOENT/i);
  });
});
