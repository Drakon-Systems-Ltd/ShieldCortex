import { describe, it, expect } from '@jest/globals';
import {
  parseInstallCommands,
  parseMcpServerEntry,
  INSTALL_OPTION_TABLES,
} from '../package-vetting.js';
import { NPM_OPTION_WORDS } from '../npm-cli-args.js';
import {
  parseInstallCommands as mainParseInstallCommands,
  parseMcpServerEntry as mainParseMcpServerEntry,
} from './fixtures/package-vetting-parser-main-482f30a9.js';

/**
 * #1054 Part B — lookup parity with `main`.
 *
 * The rule this file enforces: for a fixed list of install commands, every
 * package `main` looks up must also be looked up by the current parser.
 * "Looked up" means the parser returns a ref for the package that is on the
 * public path (`customIndex` not set): that ref is sent to OSV's
 * malicious-package batch. A ref with a version option is still looked up
 * (by name); a custom-index ref is not.
 *
 * `main` is not transcribed here. It is the parser exactly as it stood on
 * main at 482f30a9 (`fixtures/package-vetting-parser-main-482f30a9.ts`, a
 * frozen copy), run on the same command. So a new row needs no expected
 * value for main: the oracle answers.
 *
 * Each row also names the packages the installer really fetches (`must`).
 * That is the stronger half: several rows are commands where main itself
 * looks nothing up.
 *
 * `mainOnly` is the complete, per-row list of names main looks up and the
 * current parser deliberately does not, each with the reason. There are two
 * reasons only: main read a word that is an option's value or an argument of
 * the program being run as a package; or the command names an index other
 * than the public one. A row without `mainOnly` is a strict superset check.
 * Every `mainOnly` name is asserted to be looked up by main, so the list
 * cannot go stale.
 *
 * No command here is run and nothing is installed: commands are assembled
 * from parts and only parsed. Package names are invented.
 */

const j = (...parts: string[]) => parts.join(' ');

interface RefLike { ecosystem: string; name: string; customIndex?: boolean }
/** The names on the public lookup path, sorted, once each. */
const publicNames = (refs: readonly RefLike[]): string[] => [...new Set(refs.filter((r) => !r.customIndex).map((r) => r.name))].sort();
const publicKeys = (refs: readonly RefLike[]): string[] => [...new Set(refs.filter((r) => !r.customIndex).map((r) => `${r.ecosystem}:${r.name}`))].sort();

const P = 'synth-pkg';
const T = 'synth-tool';
const PRIVATE = 'https://private.example/simple/';
const NPM_PUBLIC = 'https://registry.npmjs.org';

/** Reasons a name main looks up is not looked up now. */
const VALUE = 'main read an option value as a package';
const ARG = 'main read an argument of the program being run as a package';
const REMOTE = 'the spec installs from a URL or repository, not from the registry';

interface Row {
  /** The review round or source the input comes from. */
  from: string;
  cmd: string;
  /** Packages the installer fetches from the public registry: each must be on the public lookup path. */
  must: string[];
  /** Names main looks up that the current parser deliberately does not, with the reason. */
  mainOnly?: Record<string, string>;
}

const rows: Row[] = [];
const row = (from: string, cmd: string, must: string[], mainOnly?: Record<string, string>) => { rows.push({ from, cmd, must, ...(mainOnly ? { mainOnly } : {}) }); };

// ── Baseline: every installer form main recognises ──────────────────────────
{
  const from = 'baseline: installer forms on main';
  row(from, j('npm', 'install', P), [P]);
  row(from, j('npm', 'i', '-D', `${P}@1.2.3`, 'synth-other'), [P, 'synth-other']);
  row(from, j('npm', 'add', P), [P]);
  row(from, j('pnpm', 'add', P), [P]);
  row(from, j('pnpm', 'install', P), [P]);
  row(from, j('yarn', 'add', P), [P]);
  row(from, j('yarn', 'global', 'add', P), [P]);
  row(from, j('bun', 'add', P), [P]);
  row(from, j('bun', 'install', P), [P]);
  row(from, j('npx', '-y', T), [T]);
  row(from, j('npx', '--package', P, 'cmd'), [P]);
  row(from, j('npx', '-p', P, '-p', 'synth-other', 'cmd'), [P, 'synth-other']);
  row(from, j('bunx', T), [T]);
  row(from, j('pnpm', 'dlx', T), [T]);
  row(from, j('yarn', 'dlx', T), [T]);
  row(from, j('npm', 'exec', '--', T), [T]);
  row(from, j('npm', 'x', '--package', P, '--', 'cmd'), [P]);
  row(from, j('pip', 'install', P), [P]);
  row(from, j('pip3', 'install', '-U', `${P}==1.0`, 'synth-other>=2,<3'), [P, 'synth-other']);
  row(from, j('python3', '-m', 'pip', 'install', P), [P]);
  row(from, j('uv', 'add', P), [P]);
  row(from, j('uv', 'pip', 'install', P), [P]);
  row(from, j('uv', 'tool', 'install', T), [T]);
  row(from, j('uv', 'tool', 'run', T), [T]);
  row(from, j('uvx', T), [T]);
  row(from, j('uvx', '--from', P, 'cmd'), [P]);
  row(from, j('pipx', 'install', T), [T]);
  row(from, j('pipx', 'run', T), [T]);
  row(from, j('pipx', 'run', '--spec', P, 'cmd'), [P]);
  row(from, j('sudo', 'npm', 'install', '-g', P), [P]);
  row(from, j('sh', '-c', `'npm install ${P}'`), [P]);
  row(from, j('cd', '/tmp', '&&', 'npm', 'install', P, '&&', 'pip', 'install', 'synth-other'), [P, 'synth-other']);
}

// ── v5.20.0 release review B1: version-selection options; runner forms stop at the command ──
{
  const from = 'release review B1 (9f05895a)';
  row(from, j('npm', 'install', '--tag', 'beta', P), [P]);
  row(from, j('npm', 'install', P, '--before', '2020-06-01'), [P]);
  row(from, j('pnpm', 'add', '--resolution-mode', 'lowest-direct', P), [P], { 'lowest-direct': VALUE });
  row(from, j('pip', 'install', '--pre', P), [P]);
  row(from, j('pip', 'install', '--only-binary', ':all:', P), [P]);
  row(from, j('uv', 'pip', 'install', '--prerelease', 'allow', P), [P], { allow: VALUE });
  row(from, j('uv', 'add', '--exclude-newer', '2020-01-01', P), [P], { '2020-01-01': VALUE });
  row(from, j('NPM_CONFIG_TAG=beta', 'npm', 'install', P), [P]);
  row(from, j('npx', T, '--tag', 'beta'), [T]);
  row(from, j('npx', T, '-p', 'synth-arg'), [T], { 'synth-arg': ARG });
  row(from, j('bunx', T, '--package', 'synth-arg'), [T], { 'synth-arg': ARG });
  row(from, j('uvx', T, '--from', 'synth-arg'), [T], { 'synth-arg': ARG });
  row(from, j('pipx', 'run', T, '--spec', 'synth-arg'), [T], { 'synth-arg': ARG });
}

// ── Release review round 2 B1: npm's own option spellings; unknown options ──
{
  const from = 'release review round 2 B1 (15fff5c2)';
  row(from, j('npm', 'install', '--bef', '2020-06-01', P), [P], { '2020-06-01': VALUE });
  row(from, j('npm', 'install', '--enjoy-by', '2020-06-01', P), [P], { '2020-06-01': VALUE });
  row(from, j('npm', 'install', '--befor=2020-06-01', P), [P]);
  row(from, j('npm', 'install', '-w', 'synth-ws', P), [P]);
  row(from, j('npm', 'install', '--no-save', P), [P]);
  row(from, j('npm', 'install', '--future-option', P), [P]);
  row(from, j('npm', '--future-option', 'install', P), [P]);
  row(from, j('npm', 'insta', P), [P]);
  row(from, j('npm', 'isntall', P), [P]);
  row(from, j('npm', 'install-test', P), [P]);
  row(from, j('npm', 'it', P), [P]);
  row(from, j('npm', '--loglevel', 'silent', 'install', P), [P]);
  row(from, j('npm', '-g', 'install', P), [P]);
  row(from, j('pip', 'install', '--future-option', P), [P]);
  row(from, j('pipx', 'install', '--pip-args', "'--pre'", T), [T]);
}

// ── Release review nits: named remote specs ─────────────────────────────────
{
  const from = 'release review nits (898196d1)';
  row(from, j('npm', 'install', `${P}@https://example.com/x.tgz`), []);
  row(from, j('npm', 'install', `${P}@github:someone/repo`), []);
  row(from, j('npm', 'install', `${P}@git+ssh://git@example.com/x/y.git`), [], { [P]: REMOTE });
  row(from, j('npm', 'install', `${P}@git+https://example.com/x.git`, 'synth-other'), ['synth-other'], { [P]: REMOTE });
  row(from, j('npm', 'install', `${P}@latest`, `synth-other@^1.2.3`), [P, 'synth-other']);
}

// ── Source panel, Sol 2: registry state from earlier statements is never trusted ──
{
  const from = 'source panel Sol 2 (20991ce6), ruled 12 Nov (cfd5793f)';
  row(from, j('export', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'npm', 'install', P), [P]);
  row(from, j(`NPM_CONFIG_REGISTRY=${PRIVATE};`, 'npm', 'install', P), [P]);
  row(from, j('unset', 'NPM_CONFIG_REGISTRY;', 'npm', 'install', P), [P]);
  row(from, j('export', `PIP_INDEX_URL=${PRIVATE}`, '&&', 'pip', 'install', P), [P]);
  row(from, j('export', `UV_INDEX_URL=${PRIVATE};`, 'uv', 'pip', 'install', P), [P]);
  row(from, j('declare', '-x', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'npx', T), [T]);
  row(from, j('export', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'unset', 'NPM_CONFIG_REGISTRY;', 'npm', 'install', P), [P]);
}

// ── Source panel, Daybreak 3 and Grok 2: unknown runner options; value options before the verb ──
{
  const from = 'source panel Daybreak 3 / Grok 2 (63b18f4c)';
  row(from, j('npx', '--new-option', 'synth-word', P), ['synth-word', P]);
  row(from, j('bunx', '--future-option', 'synth-word', P), ['synth-word', P]);
  row(from, j('uvx', '--future-option', 'synth-word', P), ['synth-word', P]);
  row(from, j('pipx', 'run', '--future-option', 'synth-word', P), ['synth-word', P]);
  row(from, j('pnpm', 'dlx', '--future-option', 'synth-word', P), ['synth-word', P]);
  row(from, j('bunx', '--future-option', P, 'arg'), [P]);
  row(from, j('npm', '--globalconfig', './npmrc', 'install', P), [P]);
  row(from, j('pnpm', '--globalconfig', './npmrc', 'add', P), [P]);
  row(from, j('pnpm', '--globalconfig', './npmrc', 'dlx', T), [T]);
  row(from, j('yarn', '--globalconfig', './npmrc', 'add', P), [P]);
  row(from, j('pip', '--python-version', '3.9', 'install', P), [P]);
  row(from, j('uv', '--python-preference', 'managed', 'pip', 'install', P), [P]);
  row(from, j('uv', '--future-option', 'synth-word', 'pip', 'install', P), [P]);
}

// ── PR #1061 round 1: an index variable applies to its own family; runner candidates kept ──
{
  const from = 'PR #1061 round 1, Sol 1 and 2 (b6c73c82)';
  row(from, j(`PIP_INDEX_URL=${PRIVATE}`, 'npm', 'install', P), [P]);
  row(from, j(`UV_INDEX_URL=${PRIVATE}`, 'pip', 'install', P), [P]);
  row(from, j(`npm_config_registry=${PRIVATE}`, 'uvx', T), [T]);
  row(from, j(`PIP_INDEX_URL=${PRIVATE}`, 'uv', 'pip', 'install', P), [P]);
  row(from, j('export', `PIP_INDEX_URL=${PRIVATE};`, 'npm', 'install', P), [P]);
  row(from, j(`PIP_INDEX_URL=${PRIVATE}`, 'sh', '-c', `'npm install ${P}'`), [P]);
  row(from, j('pnpm', 'dlx', '--u1', 'synth-a', '--u2', 'synth-b', '--package', P, 'cmd'), ['synth-a', 'synth-b', P]);
  row(from, j('bunx', '--u1', 'synth-a', '--u2', 'synth-b', '-p', P, 'cmd'), ['synth-a', 'synth-b', P]);
}

// ── PR #1061 round 2: an index variable set to nothing; python -m pip ───────
{
  const from = 'PR #1061 round 2, Sol 1 / Daybreak 2 (8b93aa3c)';
  row(from, j('export', 'NPM_CONFIG_REGISTRY=;', 'npm', 'install', P), [P]);
  row(from, j('NPM_CONFIG_REGISTRY=', 'npm', 'install', P), [P]);
  row(from, j('PIP_INDEX_URL=', 'pip', 'install', P), [P]);
  row(from, j('UV_DEFAULT_INDEX=', 'uvx', T), [T]);
  row(from, j('sh', '-c', `'NPM_CONFIG_REGISTRY= npm install ${P}'`), [P]);
  row(from, j(`NPM_CONFIG_REGISTRY=${PRIVATE}`, 'sh', '-c', `'NPM_CONFIG_REGISTRY= npm install ${P}'`), [P]);
  row(from, j('python', '-m', 'pip', 'install', P), [P]);
  row(from, j('python3.12', '-m', 'pip', 'install', '--upgrade', P), [P]);
}

// ── PR #1061 round 3: subshell clears, expansions, nested shells ────────────
{
  const from = 'PR #1061 round 3, Sol / Grok / Daybreak (cfd5793f)';
  row(from, j('export', 'NPM_CONFIG_REGISTRY=$UNSET_VARIABLE;', 'npm', 'install', P), [P]);
  row(from, j('export', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'NPM_CONFIG_REGISTRY=', 'true', '|', 'cat;', 'npm', 'install', P), [P]);
  row(from, j('export', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'NPM_CONFIG_REGISTRY=', 'true', '&', 'npm', 'install', P), [P]);
  row(from, j('export', 'NPM_CONFIG_REGISTRY=;', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'npm', 'install', P), [P]);
  row(from, j('export', `NPM_CONFIG_REGISTRY=${PRIVATE};`, 'sh', '-c', `'npm install ${P}'`), [P]);
  row(from, j('export', '-n', 'NPM_CONFIG_REGISTRY;', 'npm', 'install', P), [P]);
  row(from, j('export', `PIP_INDEX_URL=${PRIVATE};`, 'pip', 'install', P, '&&', 'pipx', 'install', T), [P, T]);
}

// ── TARSDrakon source review at b2478780 (F1 to F3 of the 13 Nov ruling) ────
{
  const from = 'TARSDrakon review at b2478780, F1 (e31b0c7c)';
  row(from, j('uv', 'tool', 'install', '--with-executables-from', P, T), [P, T]);
  row(from, j('uv', 'tool', 'install', '-w', P, T), [P, T]);
  row(from, j('uv', 'tool', 'install', '--with', P, T), [P, T]);
  row(from, j('uv', 'tool', 'install', T, '--with', P), [P, T]);
  row(from, j('uvx', '-w', P, T), [P, T]);
  row(from, j('uvx', '--with', P, T), [P, T]);
  row(from, j('uvx', `--with=${P}`, T), [P, T]);
  row(from, j('uvx', `-w${P}`, T), [P, T]);
  row(from, j('uvx', '--with-executables-from', P, T), [P, T]);
  row(from, j('uv', 'tool', 'run', '--with', P, T), [P, T]);
  row(from, j('uv', 'tool', 'run', '-w', P, T), [P, T]);
  row(from, j('uvx', '--with', 'synth-a,synth-b', T), ['synth-a', 'synth-b', T]);
  row(from, j('uvx', '--with', "'synth-a>=1,<2'", T), ['synth-a', T]);
  row(from, j('uvx', '--with', 'synth-a', '--with', 'synth-b', T), ['synth-a', 'synth-b', T]);
  row(from, j('pipx', 'install', '--preinstall', P, T), [P, T]);
  row(from, j('pipx', 'install', `--preinstall=${P}`, T), [P, T]);
  row(from, j('pipx', 'install', '--pre', P, T), [P, T]);
  row(from, j('pipx', 'run', '--preinstall', P, T), [P, T]);
}
{
  const from = 'TARSDrakon review at b2478780, F2 (e31b0c7c)';
  for (const opt of ['--allow-build', '--global-dir', '--workspace-concurrency', '--save-catalog-name', '--mode', '--backend', '--config', '-c', '--linker', '--concurrent-scripts', '--cache-dir']) {
    row(from, j('pnpm', 'dlx', opt, 'synth-value', '--package', P, 'cmd'), [P]);
    row(from, j('bunx', opt, 'synth-value', '-p', P, 'cmd'), [P]);
  }
  row(from, j('yarn', 'dlx', '--allow-build', 'synth-value', '--package', P, 'cmd'), [P]);
  row(from, j('pnpm', '--allow-build', 'synth-value', 'add', P), [P]);
  row(from, j('pnpm', 'dlx', '--allow-build', 'synth-value', T), [T]);
  row(from, j('uvx', '-qp', '3.12', T), [T]);
}
{
  const from = 'TARSDrakon review at b2478780, F3 (e31b0c7c)';
  for (const spelling of ['--reg', '--regi', '--registr', '--registry']) {
    row(from, j('npm', 'install', P, spelling, NPM_PUBLIC), [P]);
    row(from, j('npm', 'install', P, spelling, `${NPM_PUBLIC}/`), [P]);
    row(from, j('npm', 'install', P, spelling), [P]);
  }
  row(from, j('npm', 'install', `--registry=${NPM_PUBLIC}/`, P), [P]);
  row(from, j('npx', '--registry', `${NPM_PUBLIC}/`, T), [T]);
  row(from, j('npm', 'exec', `--reg=${NPM_PUBLIC}`, '--', T), [T]);
  row(from, j('npm', 'install', P, '--registry', PRIVATE, '--registry', NPM_PUBLIC), [P]);
}

// ── The three findings open at e31b0c7c (TARSDrakon 6858531477, CASE-Drakon review 5894862630) ──
{
  const from = 'open at e31b0c7c, blocker 1: uv extra-package value with bracketed extras and a comma';
  row(from, j('uvx', '--with', "'requests[security,socks]'", 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '--with', 'requests[security,socks]', 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '--with=requests[security,socks]', 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '-w', 'requests[security,socks]', 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '--with', "'requests[security,socks]==2.0'", 'ruff'), ['requests', 'ruff']);
  row(from, j('uv', 'tool', 'install', '--with', "'requests[security,socks]'", 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '--with-executables-from', "'ruff[extra,other]'", 'cmd'), ['ruff', 'cmd']);
  row(from, j('uv', 'tool', 'run', '-w', 'requests[security,socks]', 'ruff'), ['requests', 'ruff']);
  row(from, j('uv', 'tool', 'install', '-w', 'requests[security,socks]', 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '--with', "'synth-a[x,y],synth-b[z],synth-c>=1,<2'", 'ruff'), ['synth-a', 'synth-b', 'synth-c', 'ruff']);
  row(from, j('uvx', '--with', "'requests[security, socks] >= 2.0, < 3'", 'ruff'), ['requests', 'ruff']);
  row(from, j('uvx', '--with', 'requests[socks]', 'ruff'), ['requests', 'ruff']);
}
{
  const from = 'open at e31b0c7c, blocker 2: an npm registry value that still resolves to the public registry';
  row(from, j('npm', 'install', 'lodash', '--reg', 'not-a-url'), ['lodash'], { 'not-a-url': VALUE });
  row(from, j('npm', 'install', 'lodash', '--registry', "' '"), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--registry', 'https://user@registry.npmjs.org/'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--registry', 'https://registry.npmjs.org:443'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--registry', 'https://registry.npmjs.org./'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--registry', 'https://registry.npmjs.org//'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--registry', 'http://registry.npmjs.org'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--reg', 'https://user@registry.npmjs.org/'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--reg', 'https://registry.npmjs.org:443'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--regi', 'https://registry.npmjs.org./'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--registr', 'http://registry.npmjs.org'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--reg', 'HTTPS://REGISTRY.NPMJS.ORG/'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--reg', 'registry.npmjs.org'), ['lodash']);
  row(from, j('npm', 'install', 'lodash', '--reg', 'synth-word'), ['lodash'], { 'synth-word': VALUE });
  row(from, j('npx', '--reg', 'https://registry.npmjs.org:443/', T), [T]);
  row(from, j('npm', 'exec', '--reg', 'http://registry.npmjs.org', '--', T), [T]);
}
{
  const from = 'open at e31b0c7c, blocker 3: both-ways options before a package option use up the candidate limit';
  const four = ['--allow-build', 'synth-a', '--mode', 'synth-b', '--backend', 'synth-c', '--cache-dir', 'synth-d'];
  const unknown = ['--u1', 'synth-a', '--u2', 'synth-b', '--u3', 'synth-c', '--u4', 'synth-d'];
  for (const runner of [['pnpm', 'dlx'], ['yarn', 'dlx'], ['bunx']]) {
    row(from, j(...runner, ...four, '--package', P), [P]);
    row(from, j(...runner, ...four, '--package', P, 'cmd'), [P]);
    row(from, j(...runner, ...four, '-p', P, 'cmd'), [P]);
    row(from, j(...runner, ...four, `--package=${P}`, 'cmd'), [P]);
    row(from, j(...runner, ...unknown, '--package', P), [P]);
    row(from, j(...runner, ...four, ...unknown.slice(0, 4), '--package', P, 'cmd'), [P]);
    // With no package option, the word after the last such option may be the command: it is a package in that reading.
    row(from, j(...runner, ...unknown, 'synth-fifth'), ['synth-fifth']);
    row(from, j(...runner, ...four, '--u5', 'synth-fifth', 'arg'), ['synth-fifth']);
  }
  row(from, j('uvx', ...unknown, '--from', P, 'cmd'), [P]);
  row(from, j('uvx', ...unknown, '--with', P, T), [P, T]);
  row(from, j('pipx', 'run', ...unknown, '--spec', P, 'cmd'), [P]);
  row(from, j('npx', ...unknown, '--package', P, 'cmd'), [P]);
  row(from, j('npx', ...unknown, 'synth-fifth'), ['synth-fifth']);
}

describe('#1054 Part B — lookup parity with main: the fixed list', () => {
  it('has a row for every source it claims', () => {
    expect(rows.length).toBeGreaterThan(200);
    expect(new Set(rows.map((r) => r.cmd)).size).toBe(rows.length);
  });

  it.each(rows.map((r) => [r.from, r.cmd, r] as const))('%s: %s', (_from, cmd, r) => {
    const main = publicNames(mainParseInstallCommands(cmd));
    const now = publicNames(parseInstallCommands(cmd));
    const mainOnly = Object.keys(r.mainOnly ?? {});
    // The exclusions are live: main really looks each one up.
    expect({ cmd, mainOnlyNotLookedUpByMain: mainOnly.filter((n) => !main.includes(n)) }).toEqual({ cmd, mainOnlyNotLookedUpByMain: [] });
    // Every package main looks up is looked up now.
    expect({ cmd, droppedAgainstMain: main.filter((n) => !mainOnly.includes(n) && !now.includes(n)) }).toEqual({ cmd, droppedAgainstMain: [] });
    // Every package the installer fetches from the public registry is looked up.
    expect({ cmd, notLookedUp: r.must.filter((n) => !now.includes(n)) }).toEqual({ cmd, notLookedUp: [] });
    // And an excluded name really is excluded (so the list says what the parser does).
    expect({ cmd, mainOnlyLookedUpNow: mainOnly.filter((n) => now.includes(n) && !r.must.includes(n)) }).toEqual({ cmd, mainOnlyLookedUpNow: [] });
  });
});

// ── MCP server entries (the watch path) ─────────────────────────────────────

interface McpRow { from: string; entry: { command: string; args: string[]; env?: Record<string, string> }; must: string[]; mainOnly?: Record<string, string> }
const CUSTOM = 'the entry replaces the public index with another host';
const mcpRows: McpRow[] = [
  { from: 'baseline', entry: { command: 'npx', args: ['-y', P] }, must: [P] },
  { from: 'baseline', entry: { command: 'uvx', args: [T] }, must: [T] },
  { from: 'baseline', entry: { command: 'pipx', args: ['run', T] }, must: [T] },
  { from: 'nits (898196d1): a version variable in env', entry: { command: 'npx', args: ['-y', P], env: { NPM_CONFIG_TAG: 'beta' } }, must: [P] },
  { from: 'parity: the public registry named in env', entry: { command: 'npx', args: ['-y', P], env: { npm_config_registry: `${NPM_PUBLIC}/` } }, must: [P] },
  { from: 'parity: the public registry named in env', entry: { command: 'npx', args: ['-y', P], env: { NPM_CONFIG_REGISTRY: 'https://registry.npmjs.org:443' } }, must: [P] },
  { from: 'parity: a registry value npm rejects', entry: { command: 'npx', args: ['-y', P], env: { npm_config_registry: 'not-a-url' } }, must: [P] },
  { from: 'parity: the public index named in env', entry: { command: 'pipx', args: ['run', T], env: { PIP_INDEX_URL: 'https://pypi.org/simple' } }, must: [T] },
  { from: 'parity: the public index named in env', entry: { command: 'uvx', args: [T], env: { UV_DEFAULT_INDEX: 'https://pypi.org/simple/' } }, must: [T] },
  { from: 'parity: the public index named in env', entry: { command: 'uvx', args: [T], env: { UV_INDEX_URL: 'https://PyPI.org/simple' } }, must: [T] },
  { from: 'parity: an empty index variable in env', entry: { command: 'npx', args: ['-y', P], env: { npm_config_registry: '' } }, must: [P] },
  { from: 'parity: an extra index keeps the public one in use', entry: { command: 'uvx', args: [T], env: { UV_EXTRA_INDEX_URL: PRIVATE } }, must: [T] },
  { from: 'parity: an extra index keeps the public one in use', entry: { command: 'pipx', args: ['run', T], env: { PIP_EXTRA_INDEX_URL: PRIVATE } }, must: [T] },
  { from: 'parity: an extra index keeps the public one in use', entry: { command: 'pipx', args: ['run', T], env: { PIP_FIND_LINKS: PRIVATE } }, must: [T] },
  { from: 'parity: a scoped registry leaves other packages public', entry: { command: 'npx', args: ['-y', P], env: { 'npm_config_@synth:registry': PRIVATE } }, must: [P] },
  { from: 'parity: another family\'s variable', entry: { command: 'npx', args: ['-y', P], env: { PIP_INDEX_URL: PRIVATE } }, must: [P] },
  { from: 'nits (898196d1): a private registry in env', entry: { command: 'npx', args: ['-y', P], env: { npm_config_registry: PRIVATE } }, must: [], mainOnly: { [P]: CUSTOM } },
  { from: 'nits (898196d1): a private index in env', entry: { command: 'uvx', args: [T], env: { UV_DEFAULT_INDEX: PRIVATE } }, must: [], mainOnly: { [T]: CUSTOM } },
  { from: 'nits (898196d1): a private index in env', entry: { command: 'pipx', args: ['run', T], env: { PIP_INDEX_URL: PRIVATE } }, must: [], mainOnly: { [T]: CUSTOM } },
];

describe('#1054 Part B — lookup parity with main: MCP server entries', () => {
  it.each(mcpRows.map((r) => [r.from, JSON.stringify(r.entry), r] as const))('%s: %s', (_from, _text, r) => {
    const main = publicNames(mainParseMcpServerEntry(r.entry));
    const now = publicNames(parseMcpServerEntry(r.entry));
    const mainOnly = Object.keys(r.mainOnly ?? {});
    expect({ mainOnlyNotLookedUpByMain: mainOnly.filter((n) => !main.includes(n)) }).toEqual({ mainOnlyNotLookedUpByMain: [] });
    expect({ droppedAgainstMain: main.filter((n) => !mainOnly.includes(n) && !now.includes(n)) }).toEqual({ droppedAgainstMain: [] });
    expect({ notLookedUp: r.must.filter((n) => !now.includes(n)) }).toEqual({ notLookedUp: [] });
    expect({ mainOnlyLookedUpNow: mainOnly.filter((n) => now.includes(n)) }).toEqual({ mainOnlyLookedUpNow: [] });
  });
});

// ── The sweep: every option in the parser's tables, around a package ────────
//
// The fixed list holds the inputs reviewers found. The sweep is the class: for
// every option the parser knows (and two it does not), in each position and
// spelling, on every installer form, the same rule against the same oracle.
// The option's value here is `./v`, a path, which neither parser can read as a
// package: so main looks up exactly the packages the command names, and there
// are no `mainOnly` exclusions anywhere in the sweep.

const V = './v';
const UNKNOWN = ['--zz-not-an-option', '-Z'];
const t = INSTALL_OPTION_TABLES;
const union = (...sets: Array<Iterable<string>>): string[] => [...new Set(sets.flatMap((s) => [...s]))].sort();

const NPM_OWN = union(NPM_OPTION_WORDS, UNKNOWN);
const NPM_FAMILY = union(t.npmFamilyValue, t.npmFamilyKnown, t.npmFamilyMaybeValue, t.npmVersion, ['--registry', '--package'], UNKNOWN);
const PYTHON = union(t.pythonValue, t.pythonKnown, t.pythonVersion, t.uvExtraPackage, UNKNOWN);
const PIPX = union(t.pipxValue, t.pythonKnown, t.pipxExtraPackage, UNKNOWN);

/** Options that name the package themselves: with one of these, the swept package is not the thing fetched. */
const NAMES_A_PACKAGE = new Set(['-p', '--package', '--from', '--spec', '--call', '-c', ...t.uvExtraPackage, ...t.pipxExtraPackage]);

interface Form { words: string[]; options: string[]; /** The option that names the runner's package. */ packageOption?: string }
const INSTALL_FORMS: Form[] = [
  { words: ['npm', 'install'], options: NPM_OWN },
  { words: ['pnpm', 'add'], options: NPM_FAMILY },
  { words: ['yarn', 'add'], options: NPM_FAMILY },
  { words: ['bun', 'add'], options: NPM_FAMILY },
  { words: ['pip', 'install'], options: PYTHON },
  { words: ['uv', 'add'], options: PYTHON },
  { words: ['uv', 'pip', 'install'], options: PYTHON },
  { words: ['uv', 'tool', 'install'], options: PYTHON },
  { words: ['pipx', 'install'], options: PIPX },
];
const RUNNER_FORMS: Form[] = [
  { words: ['npx'], options: NPM_OWN, packageOption: '--package' },
  { words: ['npm', 'exec'], options: NPM_OWN, packageOption: '--package' },
  { words: ['bunx'], options: NPM_FAMILY, packageOption: '--package' },
  { words: ['pnpm', 'dlx'], options: NPM_FAMILY, packageOption: '--package' },
  { words: ['yarn', 'dlx'], options: NPM_FAMILY, packageOption: '--package' },
  { words: ['uvx'], options: PYTHON, packageOption: '--from' },
  { words: ['uv', 'tool', 'run'], options: PYTHON, packageOption: '--from' },
  { words: ['pipx', 'run'], options: PIPX, packageOption: '--spec' },
];

interface Failure { where: string; cmd: string; problem: string }
/** Parity for one command; and, when `present` is set, that the swept package yields a ref at all. */
function check(failures: Failure[], where: string, cmd: string, present: boolean): void {
  const main = publicKeys(mainParseInstallCommands(cmd));
  const refs = parseInstallCommands(cmd);
  const now = publicKeys(refs);
  const dropped = main.filter((k) => !now.includes(k));
  if (dropped.length) failures.push({ where, cmd, problem: `main looks up ${dropped.join(', ')}` });
  if (present && !refs.some((r) => r.name === P)) failures.push({ where, cmd, problem: `${P} yields no ref` });
}
/** Failures by form and shape, with the first two commands of each: what a red run prints. */
function summary(failures: Failure[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const f of failures) {
    const k = `${f.where} :: ${f.problem.replace(/npm:|PyPI:/g, '')}`;
    out[k] ??= [];
    if (out[k].length < 2) out[k].push(f.cmd);
    else if (out[k].length === 2) out[k].push('…');
  }
  return out;
}

describe('#1054 Part B — lookup parity with main: every option in the tables', () => {
  it('the tables are the parser\'s own and are not empty', () => {
    for (const [name, set] of Object.entries(t)) expect({ name, size: set.size > 0 }).toEqual({ name, size: true });
    expect(NPM_OPTION_WORDS.length).toBeGreaterThan(150);
  });

  it('install forms: an option before or after the package never hides it', () => {
    const failures: Failure[] = [];
    let n = 0;
    for (const f of INSTALL_FORMS) {
      const form = j(...f.words);
      const npmOwn = f.options === NPM_OWN;
      // npm reads `--switch=word` as the switch and a positional `word`, so only `=true` is a value every npm option takes.
      const eq = npmOwn ? 'true' : V;
      const c = (shape: string, cmd: string, present: boolean) => { check(failures, `${form} | ${shape}`, cmd, present); n++; };
      for (const o of f.options) {
        const named = NAMES_A_PACKAGE.has(o);
        c('F O ./v P', j(form, o, V, P), false);
        c('F O=v P', j(form, `${o}=${eq}`, P), !named);
        c('F P O ./v', j(form, P, o, V), !named);
        c('F P O', j(form, P, o), true);
        c('F P O=v', j(form, P, `${o}=${eq}`), true);
        // Before the verb.
        c('B O=v VERB P', j(f.words[0], `${o}=${eq}`, ...f.words.slice(1), P), false);
        c('B O ./v VERB P', j(f.words[0], o, V, ...f.words.slice(1), P), false);
        // npm gives a value option the verb itself as its value; the other tools are read with the verb in mind.
        if (!npmOwn) c('B O VERB P', j(f.words[0], o, ...f.words.slice(1), P), false);
      }
    }
    expect(n).toBeGreaterThan(8000);
    expect(summary(failures)).toEqual({});
  });

  it('runner forms: an option before the command never hides the command or a package option', () => {
    const failures: Failure[] = [];
    let n = 0;
    for (const f of RUNNER_FORMS) {
      const form = j(...f.words);
      const pkgOpt = f.packageOption!;
      const eq = f.options === NPM_OWN ? 'true' : V;
      const c = (shape: string, cmd: string, present: boolean) => { check(failures, `${form} | ${shape}`, cmd, present); n++; };
      for (const o of f.options) {
        const named = NAMES_A_PACKAGE.has(o);
        c('R O ./v P', j(form, o, V, P), false);
        c('R O=v P', j(form, `${o}=${eq}`, P), !named);
        c('R O=v P arg --flag', j(form, `${o}=${eq}`, P, 'arg', '--flag'), !named);
        // A package option straight after it, in both spellings.
        c('R O=v --pkg P ./cmd', j(form, `${o}=${eq}`, pkgOpt, P, './cmd'), !named);
        c('R O=v --pkg=P ./cmd', j(form, `${o}=${eq}`, `${pkgOpt}=${P}`, './cmd'), !named);
        c('R --pkg P O ./v ./cmd', j(form, pkgOpt, P, o, V, './cmd'), false);
        c('R --pkg P O=v ./cmd', j(form, pkgOpt, P, `${o}=${eq}`, './cmd'), true);
      }
    }
    expect(n).toBeGreaterThan(6000);
    expect(summary(failures)).toEqual({});
  });

  it('runner forms: any number of both-ways or unrecognised options before a package option', () => {
    const failures: Failure[] = [];
    const bothWays = [...t.npmFamilyMaybeValue].sort();
    let n = 0;
    for (const f of RUNNER_FORMS) {
      const form = j(...f.words);
      const pkgOpt = f.packageOption!;
      const pool = f.options === NPM_FAMILY ? [...bothWays, ...UNKNOWN] : UNKNOWN;
      const c = (shape: string, cmd: string) => { check(failures, `${form} | ${shape}`, cmd, true); n++; };
      for (let count = 1; count <= 12; count++) {
        for (let start = 0; start < pool.length; start++) {
          const chain: string[] = [];
          for (let k = 0; k < count; k++) chain.push(pool[(start + k) % pool.length], `synth-value-${k}`);
          c('R (O w)* --pkg P ./cmd', j(form, ...chain, pkgOpt, P, './cmd'));
          c('R (O w)* --pkg=P ./cmd', j(form, ...chain, `${pkgOpt}=${P}`, './cmd'));
          c('R (O w)* --pkg P', j(form, ...chain, pkgOpt, P));
          // No package option: the last word may be the command.
          c('R (O w)* P', j(form, ...chain, P));
        }
      }
    }
    expect(n).toBeGreaterThan(1500);
    expect(summary(failures)).toEqual({});
  });
});
