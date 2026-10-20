/**
 * #838: occurrence selection is a parser property, not "skip after every flag".
 * Private, pure readers are compiled straight from their source below: no copy
 * of indexOf/readFlag/parseFlag in the oracle and no production exports for tests.
 * Inline readers use their actual index initializer and value expression.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import { describe, expect, it, jest } from '@jest/globals';
import { COMMAND_HELP_SPECS, argvWantsHelp, commandWantsHelp, type CommandHelpSpec, type GatedCommand } from '../wants-help.js';
import { dispatchHelp, isDispatchGated } from '../dispatch-help.js';
import { parseProtectArgs } from '../protect.js';
import { parseEmbedBackfillLimit, parseEmbedBackfillProject } from '../embed-backfill.js';
import { parseScanArgs } from '../scan-command.js';
import { parseNativeImportArgs } from '../import-native.js';
import { handleMemoriesCommand } from '../migrate-legacy.js';
import { runAllowlistScan } from '../allowlist-scan.js';
import { requireFreshBuiltArtefacts } from '../../__tests__/built-artefact-freshness.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const sources = new Map<string, ts.SourceFile>();
function source(file: string): ts.SourceFile {
  if (!sources.has(file)) sources.set(file, ts.createSourceFile(file, fs.readFileSync(path.join(root, file), 'utf8'), ts.ScriptTarget.Latest, true));
  return sources.get(file)!;
}
function nodeMatching<T extends ts.Node>(file: string, match: (n: ts.Node) => n is T): T {
  let found: T | undefined;
  function visit(n: ts.Node): void {
    if (!found && match(n)) found = n;
    if (!found) ts.forEachChild(n, visit);
  }
  visit(source(file));
  if (!found) throw new Error(`No parser node matched in ${file}`);
  return found;
}
function compile<T>(code: string, bindings: Record<string, unknown> = {}): T {
  const js = ts.transpileModule(code, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  return new Function(...Object.keys(bindings), js)(...Object.values(bindings)) as T;
}
function privateReader<T>(file: string, name: string, bindings: Record<string, unknown> = {}): T {
  const fn = nodeMatching(file, (n): n is ts.FunctionDeclaration => ts.isFunctionDeclaration(n) && n.name?.text === name);
  return compile<T>(`${fn.getText(source(file))}\nreturn ${name};`, bindings);
}
type Reader = (args: string[], flag: string) => string | undefined;
const firstFlag = privateReader<Reader>('src/cli/migrate-legacy.ts', 'flagValue');
const sessionFlag = privateReader<Reader>('src/cli/sessions.ts', 'flagValue');
const rememberFlag = privateReader<Reader>('src/cli/remember.ts', 'parseFlag');
const memoryFlag = privateReader<Reader>('src/cli/memory.ts', 'parseFlag');
const inspectFlag = privateReader<Reader>('src/cli/inspect.ts', 'parseFlag');

/** Execute the real inline index expression and its following-token read. */
function inlineReader(file: string, indexName: string): Reader {
  const index = nodeMatching(file, (n): n is ts.VariableDeclaration => ts.isVariableDeclaration(n) && n.name.getText(source(file)) === indexName);
  const read = nodeMatching(file, (n): n is ts.ElementAccessExpression => ts.isElementAccessExpression(n)
    && n.argumentExpression.getText(source(file)) === `${indexName} + 1`);
  return (args) => compile<string | undefined>(`const ${index.getText(source(file))}; return ${read.getText(source(file))};`, { args, argv: args, extraArgs: args });
}

interface Probe { command: GatedCommand; prefix: string[]; flags: string[]; read: Reader }
const FIRST: Probe[] = [
  { command: 'sessions', prefix: ['prune'], flags: ['--days'], read: sessionFlag },
  { command: 'memories', prefix: ['migrate-legacy'], flags: ['--source'], read: inlineReader('src/cli/migrate-legacy.ts', 'sourceIdx') },
  ...[
    ['prune', ['--salience-lte', '--older-than', '--project']],
    ['dedupe', ['--project', '--limit']],
    ['repair-project-keys', ['--scan-paths', '--project', '--db']],
    ['purge', ['--backup-dir']],
    ['recalc', ['--backup-dir', '--db']],
  ].map(([verb, flags]) => ({ command: 'memories' as const, prefix: [verb as string], flags: flags as string[], read: firstFlag })),
  { command: 'guard', prefix: ['readiness'], flags: ['--surface'], read: inlineReader('src/cli/guard.ts', 'surfaceAt') },
  { command: 'protect', prefix: [], flags: ['--config'], read: (a) => parseProtectArgs(a).sourceConfig },
  { command: 'protect', prefix: [], flags: ['--agent-uid'], read: (a) => parseProtectArgs(a).agentUid },
  { command: 'remember', prefix: ['title'], flags: ['--content', '--category', '--importance', '--tags', '--project'], read: rememberFlag },
  { command: 'memory', prefix: ['list'], flags: ['--purpose', '--category', '--limit'], read: memoryFlag },
  { command: 'memory', prefix: ['downvote', '1'], flags: ['--reason'], read: memoryFlag },
  { command: 'inspect', prefix: ['last-recall'], flags: ['--history'], read: inspectFlag },
  ...[['--id', 'idIdx'], ['--limit', 'limitIdx']].map(([flag, idx]) => ({ command: 'review-copilot' as const, prefix: ['annotate'], flags: [flag], read: inlineReader('src/cli/review-copilot.ts', idx) })),
  ...[['--profile', 'profileIdx', 'activate'], ['--text', 'textIdx', 'scan'], ['--file', 'fileIdx', 'scan'], ['--search', 'searchIdx', 'audit']].map(([flag, idx, verb]) => ({ command: 'iron-dome' as const, prefix: [verb], flags: [flag], read: inlineReader('src/cli/iron-dome.ts', idx) })),
  { command: 'approve', prefix: [], flags: ['--ttl'], read: inlineReader('src/cli/approve.ts', 'ttlIndex') },
  { command: 'approve', prefix: [], flags: ['--attempt'], read: inlineReader('src/cli/approve.ts', 'attemptIndex') },
  { command: 'deny', prefix: [], flags: ['--attempt'], read: inlineReader('src/cli/deny.ts', 'attemptIndex') },
  ...[
    ['--mode', 'modeIdx'], ['--cloud-api-key', 'keyIdx'], ['--cloud-url', 'urlIdx'],
    ['--verify-mode', 'verifyModeIdx'], ['--verify-timeout', 'verifyTimeoutIdx'],
    ['--openclaw-auto-memory', 'openclawAutoMemoryIdx'], ['--ranker', 'rankerIdx'],
    ['--proactive-recall', 'proactiveRecallIdx'], ['--self-heal', 'selfHealIdx'],
    ['--action-guard-notify-webhook', 'agNotifyWebhookIdx'], ['--memory-inject-contract', 'memInjectContractIdx'],
    ['--memory-plane', 'memPlaneIdx'], ['--memory-host-posture', 'hostPostureIdx'],
    ['--memory-host-runtime', 'hostRuntimeIdx'], ['--auto-memory-sampling', 'autoMemSamplingIdx'],
  ].map(([flag, idx]) => ({ command: 'config' as const, prefix: [], flags: [flag], read: inlineReader('src/cloud/cli.ts', idx) })),
  { command: 'scan-skills', prefix: [], flags: ['--dir'], read: (args) => {
    const declaration = nodeMatching('src/index.ts', (n): n is ts.VariableDeclaration => ts.isVariableDeclaration(n) && n.name.getText(source('src/index.ts')) === 'customDir');
    return compile<string | undefined>(`return ${declaration.initializer!.getText(source('src/index.ts'))};`, { process: { argv: ['node', 'cli', 'scan-skills', ...args] } });
  } },
];
const firstCases = FIRST.flatMap((p) => p.flags.map((flag) => ({ ...p, flag, label: [p.command, ...p.prefix, flag].join(' ') })));
function expectHelp(command: GatedCommand, args: string[], expected: boolean): void {
  expect({ command, args, help: commandWantsHelp(command, args) }).toEqual({ command, args, help: expected });
  expect(argvWantsHelp([command, ...args])).toBe(expected);
  if (isDispatchGated(command)) expect(dispatchHelp([command, ...args], () => {})).toBe(expected);
}

describe('#838 first-occurrence readers (real parser source)', () => {
  it('covers every first reader that accepts -h, with embed-backfill exercised separately', () => {
    const declared: string[] = [];
    function collect(label: string, row: CommandHelpSpec): void {
      for (const [flag, rule] of Object.entries(row.values)) {
        if (rule.occurrence === 'first' && rule.value !== 'unless-dash' && !rule.equalsPrecedence) declared.push(`${label} ${flag}`);
      }
      for (const [verb, child] of Object.entries(row.verbs ?? {})) collect(`${label} ${verb}`, child);
    }
    for (const [command, row] of Object.entries(COMMAND_HELP_SPECS)) collect(command, row);
    const covered = firstCases.map(({ command, prefix, flag }) => [command, ...(command === 'memories' ? prefix : []), flag].join(' '));
    expect(covered.sort()).toEqual(declared.sort());
  });
  it.each(firstCases)('$label: ignored duplicate leaves a later -h as help', ({ command, prefix, flag, read }) => {
    const args = [flag, '7', flag, '-h'];
    expect(read(args, flag)).toBe('7');
    expectHelp(command, [...prefix, ...args], true);
  });
  it.each(firstCases)('$label: first -h is still the value despite a duplicate', ({ command, prefix, flag, read }) => {
    const args = [flag, '-h', flag, '7'];
    expect(read(args, flag)).toBe('-h');
    expectHelp(command, [...prefix, ...args], false);
  });
  it('migrate-legacy delivers the first literal help value to the real handler', async () => {
    const migrate = jest.fn((_options: { sources?: string[]; dryRun?: boolean } = {}) => ({ target: 'unused.db', dryRun: true, sources: [], totalMemories: 0, totalLinks: 0 }));
    const log = jest.spyOn(console, 'log').mockImplementation(() => {});
    try {
      await handleMemoriesCommand(['migrate-legacy', '--dry-run', '--source', '-h', '--source', 'ignored'], { migrateLegacy: migrate });
      expect(migrate).toHaveBeenCalledWith({ sources: ['-h'], dryRun: true });
    } finally { log.mockRestore(); }
  });
  it('indexOf sees an earlier occurrence even when it was another option\'s value', () => {
    const args = ['--content', '--tags', '--tags', '-h'];
    expect(rememberFlag(args, '--tags')).toBe('--tags');
    expectHelp('remember', ['title', ...args], true);
  });
  it('indexOf also reads help after a flag used as another flag\'s value', () => {
    const args = ['--content', '--tags', '-h'];
    expect(rememberFlag(args, '--tags')).toBe('-h');
    expectHelp('remember', ['title', ...args], false);
  });
});

describe('#838 first readers that refuse dash values', () => {
  const cases: Probe[] = [
    { command: 'allowlist', prefix: ['add'], flags: ['--note'], read: inlineReader('src/cli/allowlist.ts', 'noteIndex') },
    { command: 'openclaw', prefix: ['skill', 'install'], flags: ['--agent'], read: inlineReader('src/setup/openclaw.ts', 'agentAt') },
    { command: 'clawdbot', prefix: ['skill', 'update'], flags: ['--agent'], read: inlineReader('src/setup/openclaw.ts', 'agentAt') },
    { command: 'memories', prefix: ['reclassify'], flags: ['--project'], read: inlineReader('src/cli/reclassify.ts', 'projectIdx') },
  ];
  it.each(cases)('$command $prefix: selection stays first; -h is refused, not hidden', ({ command, prefix, flags, read }) => {
    const flag = flags[0];
    for (const args of [[flag, '-h', flag, 'later'], [flag, 'first', flag, '-h']]) {
      expect(read(args, flag)).toBe(args[1]);
      expectHelp(command, [...prefix, ...args], true);
    }
  });
  it('embed-backfill project rejects the first dash value even with a later valid duplicate', () => {
    const args = ['--project', '-h', '--project', 'acme'];
    expect(parseEmbedBackfillProject(args).ok).toBe(false);
    expectHelp('memories', ['embed-backfill', ...args], true);
  });
});

describe('#838 equals precedence uses the real embed-backfill parsers', () => {
  it.each([
    ['--limit=1', '--limit', '--help'],
    ['--limit', '--help', '--limit=1'],
    ['--limit=1', '--limit', '-h', '--limit=2'],
  ])('%j: equals wins, separate help token is unread', (...args) => {
    expect(parseEmbedBackfillLimit(args)).toEqual({ ok: true, limit: 1 });
    expectHelp('memories', ['embed-backfill', ...args], true);
  });
  it('without equals, the first limit consumes -h and the duplicate cannot rescue it', () => {
    const args = ['--limit', '-h', '--limit', '1'];
    expect(parseEmbedBackfillLimit(args)).toEqual({ ok: false, error: expect.stringContaining('positive integer') });
    expectHelp('memories', ['embed-backfill', ...args], false);
  });
  it('a duplicate limit does not consume -h after the first valid limit', () => {
    const args = ['--limit', '1', '--limit', '-h'];
    expect(parseEmbedBackfillLimit(args)).toEqual({ ok: true, limit: 1 });
    expectHelp('memories', ['embed-backfill', ...args], true);
  });
  it('equals project also wins, including over a bare help word', () => {
    const args = ['--project', 'help', '--project=acme'];
    expect(parseEmbedBackfillProject(args)).toEqual({ ok: true, project: 'acme' });
    expectHelp('memories', ['embed-backfill', ...args], false);
    expectHelp('memories', ['embed-backfill', '--project=acme', '--project', '-h'], true);
  });
  it('an empty equals value still takes precedence', () => {
    const args = ['--limit=', '--limit', '--help'];
    expect(parseEmbedBackfillLimit(args).ok).toBe(false);
    expectHelp('memories', ['embed-backfill', ...args], true);
  });
});

describe('#838 streaming controls', () => {
  it.each(['--glob', '--hermes-cron', '--openclaw-cron', '--openclaw-cron-db'])('allowlist scan %s rejects the later dash value before discovery', async (flag) => {
    const args = [flag, 'first', flag, '-h'];
    const errors: string[] = [];
    const code = await runAllowlistScan(args, { log: () => {}, error: (m) => errors.push(m), readEntries: () => { throw new Error('must not discover'); } });
    expect(code).toBe(1);
    expect(errors).toEqual([expect.stringContaining(`${flag} expects a value`)]);
    expectHelp('allowlist', ['scan', ...args], true);
  });
  it('audit consumes a later -h as the deps path', () => {
    const parse = privateReader<(args: string[]) => { depsPath?: string }>('src/cli/audit.ts', 'parseAuditArgs');
    const args = ['--deps-path', 'first', '--deps-path', '-h'];
    expect(parse(args).depsPath).toBe('-h');
    expectHelp('audit', args, false);
  });
  it.each(['--db', '--mode'])('global %s consumes the later occurrence', (flag) => {
    const args = [flag, 'first', flag, '-h'];
    const parse = privateReader<() => { dbPath?: string; mode: string }>('src/index.ts', 'parseArgs', { process: { argv: ['node', 'cli', ...args] } });
    // mode consumes -h but refuses it as an enum; db retains it literally.
    expect(parse()).toEqual(flag === '--db' ? { mode: 'mcp', dbPath: '-h' } : { mode: 'mcp' });
    expect(argvWantsHelp(args)).toBe(false);
    expectHelp('api', args, false);
  });
  it('scan-skills has independent global streaming and directory readers', () => {
    const args = ['--dir', '--db', '-h'];
    const parse = privateReader<() => { dbPath?: string }>('src/index.ts', 'parseArgs', { process: { argv: ['node', 'cli', 'scan-skills', ...args] } });
    expect(parse().dbPath).toBe('-h');
    expect(FIRST.find((p) => p.command === 'scan-skills')!.read(args, '--dir')).toBe('--db');
    expectHelp('scan-skills', args, false);
  });
  it('repair-project-keys reads the later map and rejects its -h value', () => {
    const parse = privateReader<(args: string[]) => Record<string, string>>('src/cli/migrate-legacy.ts', 'parseMapFlags');
    const args = ['--map', 'old=new', '--map', '-h'];
    expect(() => parse(args)).toThrow("got '-h'");
    expectHelp('memories', ['repair-project-keys', ...args], false);
  });
  it('Cortex consumes later arbitrary long flags, including equals-shaped keys', () => {
    const parse = privateReader<(args: string[]) => Record<string, string>>('src/cortex/cli.ts', 'parseArgs');
    for (const key of ['--what', '--what=x']) {
      const args = [key, 'first', key, '-h'];
      expect(parse(args)[key.slice(2)]).toBe('-h');
      expectHelp('cortex', ['capture', ...args], false);
    }
  });
  it.each(['--host-id', '--agent-id', '--project'])('import-native %s rejects repeats and never takes -h as a value', (flag) => {
    const args = ['notes.md', flag, 'first', flag, '-h'];
    expect(() => parseNativeImportArgs(args)).toThrow('ambiguous repeated flag');
    expectHelp('memories', ['import-native', ...args], true);
  });
  it.each(['--source', '--identifier'])('scan %s rejects duplicate dash values', (flag) => {
    const args = ['text', flag, flag === '--source' ? 'document' : 'first', flag, '-h'];
    expect(parseScanArgs(args)).toEqual({ ok: false });
    expectHelp('scan', args, true);
  });
});

describe('#838 built CLI in an empty HOME', () => {
  it.each([
    ['sessions', 'prune', '--days', '7', '--days', '-h'],
    ['memories', 'embed-backfill', '--limit=1', '--limit', '--help'],
  ])('%j prints usage, exits 0, creates no database or other state', (...args) => {
    requireFreshBuiltArtefacts({ repoRoot: root,
      sources: ['src/index.ts', 'src/cli/wants-help.ts'].map((p) => path.join(root, p)),
      artefacts: ['dist/index.js', 'dist/cli/wants-help.js'].map((p) => path.join(root, p)),
    });
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc838-help-'));
    const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, USERPROFILE: home, SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex') };
    delete env.CLAUDE_MEMORY_DB;
    delete env.SHIELDCORTEX_AUDIT_DIR;
    try {
      const result = spawnSync(process.execPath, [path.join(root, 'dist/index.js'), ...args], { cwd: home, env, encoding: 'utf8', input: '', timeout: 20_000 });
      expect({ status: result.status, signal: result.signal, stdout: result.stdout, stderr: result.stderr, entries: fs.readdirSync(home) })
        .toEqual({ status: 0, signal: null, stdout: expect.stringContaining(`Usage: shieldcortex ${args[0]}`), stderr: '', entries: [] });
    } finally { fs.rmSync(home, { recursive: true, force: true }); }
  }, 30_000);
});
