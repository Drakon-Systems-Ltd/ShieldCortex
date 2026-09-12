/**
 * #466 — the YAML-subset reader behind the scanner-claim rule.
 *
 * The rule that "a scanner result may appear in SKILL.md only if a workflow
 * actually runs it" is only as good as this: if the reader misses a `run:`, a
 * true claim is refused (annoying, but the safe direction); if it invents one,
 * a false claim is permitted. Review found three ways to invent one, and each
 * time `snyk: no-known-vulnerabilities` went back into SKILL.md:
 *
 *     # snyk is not installed or run      a comment is not a step
 *     env: { run: snyk }                  a value under a key spelled `run`
 *     run: echo "snyk is not installed"   a step that names it and runs echo
 *
 * So there are two independent questions and both are pinned below. WHERE a
 * value came from — `executableSurface` reads only `jobs.<id>.steps[].run`,
 * `jobs.<id>.steps[].uses` and `jobs.<id>.uses`, from jobs and steps that are
 * not switched off. And WHETHER it invokes the scanner — `invokesScanner` wants
 * the scanner to be the command a statement starts, or the owner/repository of
 * an action.
 *
 * Both directions are pinned, against hand-written fixtures AND against the
 * repo's real workflow files — a subset reader that cannot read the actual
 * `.github/workflows` would make the rule vacuous in exactly the way a
 * substring check was.
 */

import { describe, expect, it } from '@jest/globals';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  executableSurface,
  invokesScanner,
  isDisabledCondition,
  parseWorkflow,
  stripComment,
  workflowExecutableSteps,
  workflowExecutableText,
} from './support/workflow-executable-surface.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKFLOWS = join(HERE, '..', '..', '.github', 'workflows');

/** The values a workflow will execute, in order. */
const surface = (yaml: string): string[] => executableSurface(parseWorkflow(yaml)).map((step) => step.value);

/** A one-job workflow whose job body is the lines given, at job indentation. */
const job = (...lines: string[]): string => ['jobs:', '  ci:', ...lines.map((line) => `    ${line}`)].join('\n');

/** A one-job workflow whose `steps:` are the lines given. */
const steps = (...lines: string[]): string => job('steps:', ...lines.map((line) => `  ${line}`));

describe('#466 — comments are not code', () => {
  it('drops a whole-line comment', () => {
    expect(stripComment('# snyk is not installed or run')).toBe('');
  });

  it('drops a trailing comment, leaving the separator whitespace for the caller to trim', () => {
    expect(stripComment('  - run: npm test  # not snyk')).toBe('  - run: npm test  ');
    expect(surface(steps('- run: npm test  # not snyk'))).toEqual(['npm test']);
  });

  it('keeps a `#` that belongs to the value', () => {
    expect(stripComment('  - uses: acme/scan@abc#def')).toBe('  - uses: acme/scan@abc#def');
    expect(stripComment("  - run: echo 'a # b'")).toBe("  - run: echo 'a # b'");
    expect(stripComment('  - run: echo "#1"')).toBe('  - run: echo "#1"');
  });
});

describe('#466 — the executable surface is a step’s run: and uses:, nothing else', () => {
  it('collects a shell step and an action step', () => {
    expect(surface(steps('- uses: actions/checkout@v4', '- run: npm test'))).toEqual([
      'actions/checkout@v4',
      'npm test',
    ]);
  });

  it('records which key each value came from', () => {
    expect(executableSurface(parseWorkflow(steps('- uses: actions/checkout@v4', '- run: npm test')))).toEqual([
      { kind: 'uses', value: 'actions/checkout@v4' },
      { kind: 'run', value: 'npm test' },
    ]);
  });

  it('collects every line of a block scalar', () => {
    expect(surface(steps('- run: |', '    npm ci', '    npx snyk test'))).toEqual(['npm ci\nnpx snyk test']);
  });

  it('collects a folded block scalar too', () => {
    expect(surface(steps('- run: >-', '    npm ci', '    && npm test'))).toEqual(['npm ci\n&& npm test']);
  });

  it('collects a job-level reusable-workflow call', () => {
    expect(surface(job('uses: acme/.github/.workflows/scan.yml@v1'))).toEqual([
      'acme/.github/.workflows/scan.yml@v1',
    ]);
  });

  it('keeps a quoted value without its quotes', () => {
    expect(surface(steps("- run: 'npm test'"))).toEqual(['npm test']);
  });

  it('is empty for a file with nothing executable in it', () => {
    expect(surface('# snyk is not installed or run\n')).toEqual([]);
    expect(surface('')).toEqual([]);
    expect(surface('name: CI\non:\n  push:\n    branches: [main]\n')).toEqual([]);
  });

  // ── Only the three positions Actions executes ────────────────────────────
  //
  // An earlier version walked the whole document and collected any nested key
  // spelled `run` or `uses`. Review's decisive fixture was a job-level
  // `env: { run: snyk }` alongside one real step that printed "skipped": no
  // scanner ran, and the claim was permitted anyway.

  it('ignores a value under a key merely SPELLED run, in a job environment', () => {
    expect(surface(job('env:', '  run: snyk', 'steps:', '  - run: printf "skipped"'))).toEqual([
      'printf "skipped"',
    ]);
  });

  it('ignores name:, env: and with: on a step', () => {
    expect(
      surface(
        steps(
          '- name: run snyk here one day',
          '  env:',
          '    run: snyk test',
          '  with:',
          '    args: snyk test',
          '    run: snyk test',
          '  run: npm test',
        ),
      ),
    ).toEqual(['npm test']);
  });

  it('ignores a run: outside any job', () => {
    expect(surface('run: snyk test\nuses: snyk/actions/node@v1\n')).toEqual([]);
    expect(surface('steps:\n  - run: snyk test\n')).toEqual([]);
  });

  it('ignores a run: parked under a matrix or an outputs block', () => {
    expect(
      surface(
        job(
          'strategy:',
          '  matrix:',
          '    run: snyk',
          'outputs:',
          '  run: snyk',
          'steps:',
          '  - run: npm test',
        ),
      ),
    ).toEqual(['npm test']);
  });

  it('ignores a job whose steps are not a sequence', () => {
    expect(surface(job('steps: snyk test'))).toEqual([]);
  });
});

describe('#466 — a switched-off step is not an executable step', () => {
  it.each(['false', 'False', 'FALSE', "'false'", '${{ false }}', 'off', 'no'])(
    'prunes a step guarded by if: %s',
    (condition) => {
      expect(isDisabledCondition(condition)).toBe(true);
      expect(surface(steps(`- if: ${condition}`, '  run: snyk test'))).toEqual([]);
    },
  );

  it.each(["github.ref == 'refs/heads/main'", 'success()', '${{ github.event_name == \'push\' }}', 'true'])(
    'keeps a step guarded by the real condition if: %s',
    (condition) => {
      expect(isDisabledCondition(condition)).toBe(false);
      expect(surface(steps(`- if: ${condition}`, '  run: snyk test'))).toEqual(['snyk test']);
    },
  );

  /**
   * A conjunction is false whenever any conjunct is, and review found a step
   * hidden behind `${{ false && true }}` — constantly false, but not the bare
   * word `false`. Only trivially-constant conjuncts are evaluated: nothing here
   * knows what `github.event_name` is.
   */
  it.each([
    '${{ false && true }}',
    '${{ false && github.event_name == \'push\' }}',
    '${{ github.event_name == \'push\' && false }}',
    'false && success()',
    '${{ 0 && success() }}',
  ])('prunes a step guarded by the constantly-false expression if: %s', (condition) => {
    expect(isDisabledCondition(condition)).toBe(true);
    expect(surface(steps(`- if: ${condition}`, '  run: snyk test'))).toEqual([]);
  });

  /**
   * An `||` means a false operand decides nothing, so the condition reads as
   * unknown — and unknown means the step runs somewhere, which is the one
   * direction this module deliberately errs towards permitting.
   */
  it.each(['${{ false || true }}', '${{ false || github.event_name == \'push\' }}', '!false'])(
    'keeps a step whose condition it cannot evaluate: if: %s',
    (condition) => {
      expect(isDisabledCondition(condition)).toBe(false);
      expect(surface(steps(`- if: ${condition}`, '  run: snyk test'))).toEqual(['snyk test']);
    },
  );

  it('prunes every step of a job that is switched off', () => {
    expect(surface(job('if: false', 'steps:', '  - run: snyk test', '  - run: npm test'))).toEqual([]);
  });

  it('prunes a job switched off by a constantly-false expression too', () => {
    expect(surface(job('if: ${{ false && true }}', 'steps:', '  - run: snyk test'))).toEqual([]);
  });

  it('prunes only the step that is switched off', () => {
    expect(surface(steps('- if: false', '  run: snyk test', '- run: npm test'))).toEqual(['npm test']);
  });
});

describe('#466 — a step invokes a scanner, or it only names one', () => {
  const invokes = (scanner: string, ...lines: string[]): boolean =>
    invokesScanner(workflowExecutableSteps(steps(...lines)), scanner);

  it.each([
    '- run: snyk test',
    '- run: snyk test --all-projects',
    '- run: npx snyk test',
    '- run: npx --yes snyk test',
    '- run: pnpm dlx snyk test',
    '- run: pnpm exec snyk test',
    '- run: yarn dlx snyk test',
    '- run: bunx snyk test',
    '- run: SNYK_TOKEN=${{ secrets.SNYK_TOKEN }} snyk test',
    '- run: npm ci && snyk test',
    '- run: npm ci; snyk test',
    '- run: cat package.json | snyk test',
    '- run: /usr/local/bin/snyk test',
    '- run: ./node_modules/.bin/snyk test',
  ])('counts %s as an invocation', (step) => {
    expect(invokes('snyk', step)).toBe(true);
  });

  it('counts the scanner on a later line of a block scalar', () => {
    expect(invokes('snyk', '- run: |', '    npm ci', '    npx snyk test')).toBe(true);
  });

  it.each([
    '- run: echo "snyk is not installed"',
    '- run: echo snyk is disabled',
    "- run: printf 'snyk: skipped\\n'",
    '- run: grep -r snyk .',
    '- run: npm test --reporter=snyk',
    '- run: docker run aquasec/snyk',
    '- run: echo "npx snyk test"',
  ])('does not count %s, which names it without running it', (step) => {
    expect(invokes('snyk', step)).toBe(false);
  });

  it.each([
    ['- uses: snyk/actions/node@v1', 'snyk'],
    ['- uses: snyk/actions/node@master', 'snyk'],
    ['- uses: aquasecurity/trivy-action@0.24.0', 'trivy'],
    ['- uses: anchore/scan-action@v3', 'anchore'],
  ])('counts the action %s for %s', (step, scanner) => {
    expect(invokes(scanner, step)).toBe(true);
  });

  it.each([
    ['- uses: acme/snykish-linter@v1', 'snyk'],
    ['- uses: actions/checkout@v4', 'snyk'],
    ['- uses: acme/build@v1', 'trivy'],
    // A local composite action is refused on purpose: the directory name is a
    // label on steps this function is not looking at — "named, not run", one
    // level deeper.
    ['- uses: ./.github/actions/snyk', 'snyk'],
  ])('does not count the action %s for %s', (step, scanner) => {
    expect(invokes(scanner, step)).toBe(false);
  });

  it('counts a reusable workflow the scanner publishes', () => {
    expect(invokesScanner(workflowExecutableSteps(job('uses: snyk/.github/.workflows/scan.yml@v1')), 'snyk')).toBe(
      true,
    );
  });

  it('reads nothing out of an empty surface', () => {
    expect(invokesScanner([], 'snyk')).toBe(false);
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
    const values = executableSurface(parseWorkflow(file.text)).map((step) => step.value);
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

  it('finds no scanner invocation in them, which is why SKILL.md may claim none', () => {
    const all = files.flatMap((f) => workflowExecutableSteps(f.text));
    for (const scanner of ['snyk', 'trivy', 'grype', 'dependabot']) {
      expect({ scanner, invoked: invokesScanner(all, scanner) }).toEqual({ scanner, invoked: false });
    }
    // The rule is not vacuous on these files: what they DO run, it sees.
    expect(invokesScanner(all, 'npm')).toBe(true);
  });
});
