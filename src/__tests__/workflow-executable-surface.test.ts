/**
 * #466 — the YAML-subset reader behind the scanner-claim rule.
 *
 * The rule that "a scanner result may appear in SKILL.md only if a workflow
 * actually runs it" is only as good as this: if the reader misses a `run:`, a
 * true claim is refused (annoying, but the safe direction); if it invents one,
 * a false claim is permitted (the defect review found, via a workflow file
 * containing nothing but `# snyk is not installed or run`).
 *
 * So both directions are pinned here, against hand-written fixtures AND
 * against the repo's real workflow files — a subset reader that cannot read
 * the actual `.github/workflows` would make the rule vacuous in exactly the
 * way a substring check was.
 */

import { describe, expect, it } from '@jest/globals';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  executableSurface,
  isDisabledCondition,
  parseWorkflow,
  stripComment,
  workflowExecutableText,
} from './support/workflow-executable-surface.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOWS = join(HERE, '..', '..', '.github', 'workflows');

const surface = (yaml: string): string[] => executableSurface(parseWorkflow(yaml));

describe('#466 — comments are not code', () => {
  it('drops a whole-line comment', () => {
    expect(stripComment('# snyk is not installed or run')).toBe('');
  });

  it('drops a trailing comment, leaving the separator whitespace for the caller to trim', () => {
    expect(stripComment('  - run: npm test  # not snyk')).toBe('  - run: npm test  ');
    expect(surface('steps:\n  - run: npm test  # not snyk')).toEqual(['npm test']);
  });

  it('keeps a `#` that belongs to the value', () => {
    expect(stripComment('  - uses: acme/scan@abc#def')).toBe('  - uses: acme/scan@abc#def');
    expect(stripComment("  - run: echo 'a # b'")).toBe("  - run: echo 'a # b'");
    expect(stripComment('  - run: echo "#1"')).toBe('  - run: echo "#1"');
  });
});

describe('#466 — the executable surface is run: and uses:, nothing else', () => {
  it('collects a shell step and an action step', () => {
    expect(
      surface(
        ['jobs:', '  ci:', '    steps:', '      - uses: actions/checkout@v4', '      - run: npm test'].join('\n'),
      ),
    ).toEqual(['actions/checkout@v4', 'npm test']);
  });

  it('collects every line of a block scalar', () => {
    expect(surface(['steps:', '  - run: |', '      npm ci', '      npx snyk test'].join('\n'))).toEqual([
      'npm ci\nnpx snyk test',
    ]);
  });

  it('collects a folded block scalar too', () => {
    expect(surface(['steps:', '  - run: >-', '      npm ci', '      && npm test'].join('\n'))).toEqual([
      'npm ci\n&& npm test',
    ]);
  });

  it('ignores name:, env: and with: values', () => {
    expect(
      surface(
        [
          'jobs:',
          '  ci:',
          '    env:',
          '      SCANNER: snyk',
          '    steps:',
          '      - name: run snyk here one day',
          '        with:',
          '          args: snyk test',
          '        run: npm test',
        ].join('\n'),
      ),
    ).toEqual(['npm test']);
  });

  it('collects a job-level reusable-workflow call', () => {
    expect(surface(['jobs:', '  sec:', '    uses: acme/.github/.workflows/scan.yml@v1'].join('\n'))).toEqual([
      'acme/.github/.workflows/scan.yml@v1',
    ]);
  });

  it('keeps a quoted value without its quotes', () => {
    expect(surface(['steps:', "  - run: 'npm test'"].join('\n'))).toEqual(['npm test']);
  });

  it('is empty for a file with nothing executable in it', () => {
    expect(surface('# snyk is not installed or run\n')).toEqual([]);
    expect(surface('')).toEqual([]);
    expect(surface('name: CI\non:\n  push:\n    branches: [main]\n')).toEqual([]);
  });
});

describe('#466 — a switched-off step is not an executable step', () => {
  it.each(['false', 'False', 'FALSE', "'false'", '${{ false }}', 'off', 'no'])(
    'prunes a step guarded by if: %s',
    (condition) => {
      expect(isDisabledCondition(condition)).toBe(true);
      expect(surface(['steps:', `  - if: ${condition}`, '    run: snyk test'].join('\n'))).toEqual([]);
    },
  );

  it.each(["github.ref == 'refs/heads/main'", 'success()', '${{ github.event_name == \'push\' }}', 'true'])(
    'keeps a step guarded by the real condition if: %s',
    (condition) => {
      expect(isDisabledCondition(condition)).toBe(false);
      expect(surface(['steps:', `  - if: ${condition}`, '    run: snyk test'].join('\n'))).toEqual(['snyk test']);
    },
  );

  it('prunes every step of a job that is switched off', () => {
    expect(
      surface(
        ['jobs:', '  sec:', '    if: false', '    steps:', '      - run: snyk test', '      - run: npm test'].join(
          '\n',
        ),
      ),
    ).toEqual([]);
  });

  it('prunes only the step that is switched off', () => {
    expect(
      surface(
        [
          'jobs:',
          '  sec:',
          '    steps:',
          '      - if: false',
          '        run: snyk test',
          '      - run: npm test',
        ].join('\n'),
      ),
    ).toEqual(['npm test']);
  });
});

describe('#466 — the reader can read this repository’s real workflows', () => {
  const files = readdirSync(WORKFLOWS).map((name) => ({
    name,
    text: readFileSync(join(WORKFLOWS, name), 'utf8'),
  }));

  it('finds workflow files to read', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it.each(files.map((f) => f.name))('extracts real steps from %s', (name) => {
    const file = files.find((f) => f.name === name);
    if (!file) throw new Error(`missing fixture ${name}`);
    const values = executableSurface(parseWorkflow(file.text));
    // Every real workflow here checks out and installs; if the reader returns
    // nothing for a 3-to-14 KB file, the rule built on it is vacuous.
    expect(values.length).toBeGreaterThan(3);
    expect(values.join('\n')).toContain('actions/checkout@v4');
    expect(values.join('\n')).toContain('npm ci');
  });

  it('extracts the same commands a reader would see, not the prose around them', () => {
    const ci = files.find((f) => f.name === 'ci.yml');
    if (!ci) throw new Error('ci.yml missing');
    const text = workflowExecutableText(ci.text);
    expect(text).toContain('npm run build:ts');
    expect(text).toContain('npm run test:dist');
    // ci.yml's comments are long and full of prose; none of it is executable.
    expect(ci.text).toContain('macOS runners bill at a');
    expect(text).not.toContain('macos runners bill at a');
  });
});
