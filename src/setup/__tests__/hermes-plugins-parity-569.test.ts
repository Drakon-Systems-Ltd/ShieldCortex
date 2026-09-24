import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import {
  probeHermesDiscovery,
  resolveHermesInterpreter,
  scanHermesPluginRootFallback,
} from '../hermes-plugins.js';

/**
 * #569 round 2 — the detector must agree with Hermes about which directory gets
 * the `shieldcortex` key and which one wins it.
 *
 * Round 1 mirrored the discovery rules in a line reader. An independent review
 * of the sibling Ekho fix found six shapes where a line reader and Hermes give
 * DIFFERENT answers, and every one of them is a health check confidently
 * reporting the wrong thing. Those six shapes are the fixtures below.
 *
 * Two halves run over the same trees:
 *
 *   - the FALLBACK reader (`scanHermesPluginRootFallback`), always;
 *   - the PRIMARY path (`probeHermesDiscovery`, which spawns the Hermes
 *     interpreter and asks `hermes_cli.plugins_discovery`), when this box has a
 *     Hermes to ask. Where both run, they must produce the same copies and the
 *     same winner — that is the differential half.
 *
 * `expected` is not the fallback's opinion of itself: each value was recorded by
 * running Hermes' own `scan_directory` + `resolve_manifest_winners` over these
 * exact trees, so the fallback-only half is still pinned to Hermes' behaviour
 * on a box with no interpreter.
 */

const SCHEMA_V1 = 'https://agent-plugins.org/schemas/1.0.0/plugin.schema.json';

interface ParityCase {
  name: string;
  /** Builds one `plugins/` root; returns nothing. */
  build: (root: string) => void;
  /** Directory basenames Hermes keys `shieldcortex`, in discovery order. */
  copies: string[];
  /** The basename Hermes loads, or null. */
  winner: string | null;
  /** Basenames the fallback reader refuses to classify (primary never does). */
  unknown?: string[];
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
    copies: ['shieldcortex', 'shieldcortex.bak-x'],
    winner: 'shieldcortex.bak-x',
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
    copies: ['shieldcortex'],
    winner: 'shieldcortex',
  },
  {
    name: 'quoted names, single and double',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: "shieldcortex"\n');
      manifest(root, 'shieldcortex.q', "name: 'shieldcortex'   # old\n");
    },
    copies: ['shieldcortex', 'shieldcortex.q'],
    winner: 'shieldcortex.q',
  },
  {
    // A portable Agent Plugins v1 package has no plugin.yaml at all, and Hermes
    // accepts it. It also applies the v1 gate, so a plugin.json without the
    // schema id or with an unparseable body yields nothing.
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
    copies: ['shieldcortex', 'shieldcortex.portable'],
    winner: 'shieldcortex.portable',
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
    copies: ['shieldcortex'],
    winner: 'shieldcortex',
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
    copies: ['shieldcortex'],
    winner: 'shieldcortex',
    // The fallback cannot decide these without a YAML parser, and says so
    // rather than claiming three shadows that do not exist.
    unknown: ['shieldcortex.broken', 'shieldcortex.broken2', 'shieldcortex.broken3'],
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
    copies: ['shieldcortex', 'shieldcortex.yml-spelling'],
    winner: 'shieldcortex.yml-spelling',
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
    copies: ['shieldcortex'],
    winner: 'shieldcortex',
  },
  {
    // An empty manifest parses to `{}`, so the name is the directory name.
    name: 'an empty plugin.yaml',
    build: (root) => {
      manifest(root, 'shieldcortex', '');
      manifest(root, 'zz-empty', '');
    },
    copies: ['shieldcortex'],
    winner: 'shieldcortex',
  },
  {
    // A sequence at the top level is not a Mapping, and Hermes rejects it.
    name: 'a top-level sequence document',
    build: (root) => {
      manifest(root, 'shieldcortex', 'name: shieldcortex\n');
      manifest(root, 'shieldcortex.list', '- name: shieldcortex\n');
    },
    copies: ['shieldcortex'],
    winner: 'shieldcortex',
    unknown: ['shieldcortex.list'],
  },
  {
    name: 'no copy at all',
    build: (root) => {
      manifest(root, 'kanban', 'name: kanban\n');
    },
    copies: [],
    winner: null,
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
  it.each(CASES)('matches Hermes on: $name', (testCase) => {
    const root = roots.get(testCase.name)!;
    const scan = scanHermesPluginRootFallback(root);
    expect(scan.copies.map((c) => c.dirName)).toEqual(testCase.copies);
    expect(scan.loaded?.dirName ?? null).toBe(testCase.winner);
    expect(scan.unknownDirs.map((d) => path.basename(d))).toEqual(testCase.unknown ?? []);
  });

  it('flags the canonical copy as canonical and the backup as not', () => {
    const root = roots.get('an inline # comment after the name')!;
    const scan = scanHermesPluginRootFallback(root);
    expect(scan.copies.map((c) => c.canonical)).toEqual([true, false]);
    expect(scan.hasCanonical).toBe(true);
    expect(scan.shadowed).toBe(true);
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
    expect(probe.roots[0].copies.map((c) => path.basename(c))).toEqual(testCase.copies);
    expect(probe.roots[0].loaded === null ? null : path.basename(probe.roots[0].loaded)).toBe(
      testCase.winner,
    );
  });

  it('agrees with the fallback reader on every fixture tree', () => {
    const disagreements: string[] = [];
    for (const testCase of CASES) {
      const root = roots.get(testCase.name)!;
      const probe = probeHermesDiscovery(path.dirname(root), [root], { interpreter });
      if (!('roots' in probe)) {
        disagreements.push(`${testCase.name}: probe failed — ${probe.error}`);
        continue;
      }
      const fallback = scanHermesPluginRootFallback(root);
      const fromHermes = {
        copies: probe.roots[0].copies.map((c) => path.basename(c)),
        winner: probe.roots[0].loaded === null ? null : path.basename(probe.roots[0].loaded),
      };
      const fromFallback = {
        copies: fallback.copies.map((c) => c.dirName),
        winner: fallback.loaded?.dirName ?? null,
      };
      if (JSON.stringify(fromHermes) !== JSON.stringify(fromFallback)) {
        disagreements.push(
          `${testCase.name}: hermes=${JSON.stringify(fromHermes)} fallback=${JSON.stringify(fromFallback)}`,
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
});
