import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import {
  probeHermesDiscovery,
  resolveHermesInterpreter,
  scanHermesPluginRootFallback,
} from '../hermes-plugins.js';
import { classifyPluginDir, couldBeOurs, readYamlManifestName } from '../hermes-manifest-parse.js';

/**
 * #569 — the detector must never disagree with Hermes about which directory
 * gets the `shieldcortex` key and which one wins it.
 *
 * Round 1 mirrored the discovery rules in a line reader. Round 2 asked Hermes
 * on the primary path but kept a guessing reader for the fallback, and
 * independent review of the sibling Ekho change found the guesses wrong in
 * BOTH directions: a block-scalar `name:` made it report a clean install while
 * Hermes was loading the backup, and an invalid `description: backup: x` under
 * a valid `name:` line made it label a backup LOADED that Hermes rejects.
 *
 * Round 3 narrowed the fallback to "understood, or unknown", so the contract
 * these tests pin is a differential one:
 *
 *   for every fixture tree, the fallback gives the SAME answer as Hermes, or
 *   it says unknown. Never a confident disagreement.
 *
 * Two halves run over the same trees:
 *
 *   - the FALLBACK reader (`scanHermesPluginRootFallback`), always;
 *   - the PRIMARY path (`probeHermesDiscovery`, which spawns the Hermes
 *     interpreter and asks `hermes_cli.plugins_discovery`), when this box has a
 *     Hermes to ask. That is the differential half.
 *
 * Every `hermes` expectation below was recorded by running Hermes' own
 * `scan_directory` + `resolve_manifest_winners` over these exact trees, so the
 * fallback-only half is still pinned to Hermes' behaviour on a box with none.
 */

const SCHEMA_V1 = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';

interface ParityCase {
  name: string;
  /** Builds one `plugins/` root. */
  build: (root: string) => void;
  /** What Hermes' own discovery reports for this tree. */
  hermes: { copies: string[]; winner: string | null };
  /** What the conservative reader reports: copies, winner, and unknowns. */
  fallback: { copies: string[]; winner: string | null; unknown?: string[] };
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
    fallback: { copies: ['shieldcortex', 'shieldcortex.bak-x'], winner: 'shieldcortex.bak-x' },
  },
  {
    // `data.get("name", plugin_dir.name)`: no `name:` key at all means the
    // DIRECTORY name is the key. Round 1 excluded such a manifest entirely,
    // which loses the canonical copy and can turn a shadowed root into
    // "there is no canonical copy — a human must choose".
    name: 'a manifest with no name: at all',
    build: (root) => {
      manifest(root, 'shieldcortex', 'version: 1\n');
      manifest(root, 'zz-nameless', 'version: 1\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
    fallback: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    name: 'quoted names, single and double',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: "shieldcortex"\n');
      manifest(root, 'shieldcortex.q', "name: 'shieldcortex'   # old\n");
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.q'], winner: 'shieldcortex.q' },
    fallback: { copies: ['shieldcortex', 'shieldcortex.q'], winner: 'shieldcortex.q' },
  },
  {
    // A portable Agent Plugins v1 package has no plugin.yaml at all, and Hermes
    // accepts it after `agent_plugins._validate_manifest`. The fallback does
    // not mirror that validation and no longer judges plugin.json at all, so
    // the copy Hermes loads here comes back UNKNOWN and the root has no winner.
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
    fallback: {
      copies: ['shieldcortex'],
      winner: null,
      unknown: ['shieldcortex.badjson', 'shieldcortex.portable'],
    },
  },
  {
    // Hermes selects the manifest with `Path.exists()`, not `is_file()`. A
    // `plugin.yaml` DIRECTORY is therefore selected, fails to parse, and Hermes
    // takes NOTHING from that child — it never looks at the `plugin.yml`.
    // Falling through to the `.yml` invents a shadow that does not exist.
    name: 'a plugin.yaml directory beside a valid plugin.yml',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      fs.mkdirSync(path.join(root, 'shieldcortex.dirmanifest', 'plugin.yaml'), { recursive: true });
      manifest(root, 'shieldcortex.dirmanifest', 'name: shieldcortex\n', 'plugin.yml');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
    fallback: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // A valid `name:` line above broken YAML: Hermes' safe_load raises and
    // `parse_manifest_file` returns None, so the directory is not a copy. A
    // line reader that stops at the first `name:` claims it is.
    name: 'invalid YAML after a valid name: line',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.broken', 'name: shieldcortex\nkind: [unclosed\n');
      manifest(root, 'shieldcortex.broken2', 'name: shieldcortex\n\tkind: standalone\n');
      manifest(root, 'shieldcortex.broken3', 'name: shieldcortex\n:\n  not: [a manifest\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
    fallback: {
      copies: ['shieldcortex'],
      winner: null,
      unknown: ['shieldcortex.broken', 'shieldcortex.broken2', 'shieldcortex.broken3'],
    },
  },
  {
    // The rules round 1 got right, kept as regression cover: dunder children
    // and per-harness manifest dirs are skipped before any manifest is read, a
    // manifest-less child is a category keyed `<cat>/<name>`, a different
    // `name:` cannot collide, and `plugin.yml` counts.
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
    fallback: {
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
    fallback: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // An empty manifest parses to `{}`, so the name is the directory name.
    name: 'an empty plugin.yaml',
    build: (root) => {
      manifest(root, 'shieldcortex', '');
      manifest(root, 'zz-empty', '');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
    fallback: { copies: ['shieldcortex'], winner: 'shieldcortex' },
  },
  {
    // A sequence at the top level is not a Mapping, and Hermes rejects it.
    name: 'a top-level sequence document',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.list', '- name: shieldcortex\n');
    },
    hermes: { copies: ['shieldcortex'], winner: 'shieldcortex' },
    fallback: { copies: ['shieldcortex'], winner: null, unknown: ['shieldcortex.list'] },
  },
  {
    name: 'no copy at all',
    build: (root) => {
      manifest(root, 'kanban', 'name: kanban\n');
    },
    hermes: { copies: [], winner: null },
    fallback: { copies: [], winner: null },
  },

  // ── The four round-3 differential fixtures ─────────────────────────────
  {
    // THE round-2 blocker. Hermes reads the folded scalar, gets `shieldcortex`
    // and LOADS the backup. Round 2 saw a shape it did not model, decided the
    // name was absent, keyed the directory on its own name, and reported a
    // clean canonical install — certifying the exact state it exists to catch.
    name: 'a block-scalar name Hermes reads and loads',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.bak-x', 'name: >-\n  shieldcortex\n');
    },
    hermes: { copies: ['shieldcortex', 'shieldcortex.bak-x'], winner: 'shieldcortex.bak-x' },
    fallback: { copies: ['shieldcortex'], winner: null, unknown: ['shieldcortex.bak-x'] },
  },
  {
    // The same blocker in the other direction. `description: backup: before
    // upgrade` is not YAML — Hermes raises and drops the manifest. Round 2 only
    // ever inspected the `name:` line, so it labelled this backup LOADED.
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
    fallback: { copies: ['shieldcortex'], winner: null, unknown: ['shieldcortex.bak-y'] },
  },
  {
    // `agent_plugins._validate_manifest` requires plugin.json to resolve INSIDE
    // the plugin root, so Hermes rejects this one. Round 2 followed the link
    // and called the directory the winner.
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
    fallback: { copies: ['shieldcortex'], winner: null, unknown: ['shieldcortex.linked'] },
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
    fallback: { copies: ['shieldcortex'], winner: null, unknown: ['shieldcortex.authored'] },
  },
];

let fixtures: string;
let roots: Map<string, string>;
const savedHermesHome = process.env.HERMES_HOME;

beforeAll(() => {
  delete process.env.HERMES_HOME;
  fixtures = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-parity-'));
  roots = new Map();
  CASES.forEach((testCase, index) => {
    // One `plugins/` root per case: a collision is per-root, so mixing cases
    // into one root would make the winner meaningless.
    const root = path.join(fixtures, `case-${index}`, 'plugins');
    fs.mkdirSync(root, { recursive: true });
    testCase.build(root);
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

describe('fallback reader (#569)', () => {
  it.each(CASES)('reports the recorded answer on: $name', (testCase) => {
    const root = roots.get(testCase.name)!;
    const scan = scanHermesPluginRootFallback(root);
    expect(scan.copies.map((c) => c.dirName)).toEqual(testCase.fallback.copies);
    expect(scan.loaded?.dirName ?? null).toBe(testCase.fallback.winner);
    expect(scan.unknownDirs.map((d) => path.basename(d))).toEqual(testCase.fallback.unknown ?? []);
    expect(scan.undetermined).toBe((testCase.fallback.unknown ?? []).length > 0);
  });

  it('flags the canonical copy as canonical and the backup as not', () => {
    const root = roots.get('an inline # comment after the name')!;
    const scan = scanHermesPluginRootFallback(root);
    expect(scan.copies.map((c) => c.canonical)).toEqual([true, false]);
    expect(scan.hasCanonical).toBe(true);
    expect(scan.shadowed).toBe(true);
  });

  it('gives an undetermined root no winner and no shadow verdict', () => {
    // The point of the rule: the directory we would not read may well be a
    // copy, and it may sort after every copy we did read. Naming a winner
    // anyway is the guess that made round 2 certify a shadowed host.
    for (const name of [
      'a block-scalar name Hermes reads and loads',
      'invalid YAML from a colon in a later value',
      'a plugin.json symlinked outside the plugin root',
      'a plugin.json with an unknown author field',
    ]) {
      const scan = scanHermesPluginRootFallback(roots.get(name)!);
      expect(scan.undetermined).toBe(true);
      expect(scan.loaded).toBeNull();
      expect(scan.shadowed).toBe(false);
      expect(scan.copies.map((c) => c.dirName)).toEqual(['shieldcortex']);
    }
  });
});

describe('the understood-manifest rule (#569 r3)', () => {
  it.each([
    'name: shieldcortex\n',
    'name: shieldcortex # backup\n',
    'name: "shieldcortex"\n',
    'version: 1\nname: shieldcortex\nkind: standalone\n',
    '# only a comment\n',
    '',
    'meta:\n  inner: value\n  - item\nname: shieldcortex\n',
  ])('understands the ordinary shape: %j', (body) => {
    expect(readYamlManifestName(body).understood).toBe(true);
  });

  it.each([
    'name: >-\n  shieldcortex\n', // folded block scalar
    'name: |\n  shieldcortex\n', // literal block scalar
    'name:\n  first: x\n', // a null name with a block under it
    'name: [shieldcortex]\n', // flow collection
    'name: &anchor shieldcortex\n',
    'name: *alias\n',
    'name: !!str shieldcortex\n',
    '---\nname: shieldcortex\n', // document marker
    'name: shieldcortex\n...\n',
    'name: shieldcortex\n\tkind: x\n', // tab
    'name: shieldcortex\ndescription: backup: x\n', // unquoted `: `
    '- name: shieldcortex\n', // sequence document
    "name: 'unterminated\n",
    '  name: shieldcortex\n', // nothing at column 0
    'name: shieldcortex\ndeps: [a, b]\n', // a flow collection anywhere
  ])('refuses to read: %j', (body) => {
    expect(readYamlManifestName(body).understood).toBe(false);
  });

  it('reserves unknown for manifests that could take our key', () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-unknown-'));
    try {
      // A neighbour's block scalar must not put a permanent "cannot determine"
      // on a host where nothing is wrong.
      manifest(tmp, 'zz-other', 'name: kanban\ndescription: >-\n  a plugin\n');
      expect(classifyPluginDir(path.join(tmp, 'zz-other'), 'zz-other')).toBe('other');
      // …but the same shape in a directory that could take our key is unknown.
      manifest(tmp, 'zz-maybe', 'name: shieldcortex\nkind: [unclosed\n');
      expect(classifyPluginDir(path.join(tmp, 'zz-maybe'), 'zz-maybe')).toBe('unknown');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('covers the three ways our key can reach a manifest', () => {
    expect(couldBeOurs('shieldcortex', 'name: anything\n')).toBe(true);
    expect(couldBeOurs('other', 'name: shieldcortex\n')).toBe(true);
    // A double-quoted escape is the only way to spell the name without the
    // literal bytes, and a backslash is the only way to write one.
    expect(couldBeOurs('other', 'name: "shieldcorte\\x78"\n')).toBe(true);
    expect(couldBeOurs('other', 'name: kanban\n')).toBe(false);
  });
});

// The primary path needs a Hermes to ask. Skipped cleanly, not faked, where
// there is none — a green run that never spawned anything would be a lie.
const describePrimary = interpreter === null ? describe.skip : describe;

describePrimary(`primary path via Hermes itself (${interpreter ?? 'no interpreter'})`, () => {
  it.each(CASES)('Hermes reports the recorded copies and winner: $name', (testCase) => {
    const root = roots.get(testCase.name)!;
    const probe = probeHermesDiscovery(path.dirname(root), [root], { interpreter });
    expect('roots' in probe ? null : probe.error).toBeNull();
    if (!('roots' in probe)) return;
    expect(probe.roots).toHaveLength(1);
    expect(probe.roots[0].copies.map((c) => path.basename(c))).toEqual(testCase.hermes.copies);
    expect(probe.roots[0].loaded === null ? null : path.basename(probe.roots[0].loaded)).toBe(
      testCase.hermes.winner,
    );
  });

  it('never disagrees confidently with Hermes on any fixture tree', () => {
    // The round-3 contract: the same answer, or unknown. Never a third thing.
    const disagreements: string[] = [];
    for (const testCase of CASES) {
      const root = roots.get(testCase.name)!;
      const probe = probeHermesDiscovery(path.dirname(root), [root], { interpreter });
      if (!('roots' in probe)) {
        disagreements.push(`${testCase.name}: probe failed — ${probe.error}`);
        continue;
      }
      const fallback = scanHermesPluginRootFallback(root);
      const theirs = probe.roots[0].copies.map((c) => path.basename(c));
      const mine = fallback.copies.map((c) => c.dirName);
      const unknown = fallback.unknownDirs.map((d) => path.basename(d));

      // Every copy the fallback NAMES is one Hermes names too: a confident
      // positive is never invented.
      for (const name of mine) {
        if (!theirs.includes(name)) {
          disagreements.push(`${testCase.name}: fallback invented the copy ${name}`);
        }
      }
      // Every copy it MISSES it has flagged unknown: a confident negative is
      // never a real shadow swept under the carpet.
      for (const name of theirs) {
        if (!mine.includes(name) && !unknown.includes(name)) {
          disagreements.push(`${testCase.name}: fallback silently dropped ${name}`);
        }
      }
      const mineWinner = fallback.loaded?.dirName ?? null;
      const theirWinner =
        probe.roots[0].loaded === null ? null : path.basename(probe.roots[0].loaded);
      if (mineWinner !== null && mineWinner !== theirWinner) {
        disagreements.push(
          `${testCase.name}: fallback named ${mineWinner}, Hermes loads ${theirWinner}`,
        );
      }
      if (mineWinner === null && theirWinner !== null && unknown.length === 0) {
        disagreements.push(
          `${testCase.name}: fallback named no winner and no unknowns, Hermes loads ${theirWinner}`,
        );
      }
    }
    expect(disagreements).toEqual([]);
  });

  it('never reports an unknown directory — Hermes always has an answer', () => {
    const root = roots.get('invalid YAML after a valid name: line')!;
    const probe = probeHermesDiscovery(path.dirname(root), [root], { interpreter });
    expect('roots' in probe).toBe(true);
    if (!('roots' in probe)) return;
    // The three broken manifests the fallback calls `unknown` are, to Hermes,
    // simply not copies.
    expect(probe.roots[0].copies).toHaveLength(1);
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
    const root = roots.get('an inline # comment after the name')!;
    const probe = probeHermesDiscovery(path.dirname(root), [root], { interpreter: null });
    expect('error' in probe).toBe(true);
    if ('error' in probe) expect(probe.error).toMatch(/no Hermes interpreter/i);
  });

  it('reports why when the interpreter cannot import Hermes discovery', () => {
    const root = roots.get('an inline # comment after the name')!;
    // A real Python with no hermes_cli on its path: the probe must come back as
    // an error the caller can print, not as an empty scan.
    const probe = probeHermesDiscovery(path.join(os.tmpdir(), 'sc-no-hermes-here'), [root], {
      interpreter: process.execPath,
    });
    expect('error' in probe).toBe(true);
  });

  it('reports why when the interpreter path does not exist at all', () => {
    // The "bogus interpreter" seam: the reason has to survive to the caller so
    // doctor can print it, rather than being flattened to "no copies".
    const root = roots.get('an inline # comment after the name')!;
    const probe = probeHermesDiscovery(path.dirname(root), [root], {
      interpreter: path.join(os.tmpdir(), 'sc-no-such-python-569'),
    });
    expect('error' in probe).toBe(true);
    if ('error' in probe) expect(probe.error).toMatch(/failed to run|ENOENT/i);
  });
});
