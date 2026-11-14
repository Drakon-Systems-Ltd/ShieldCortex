/**
 * #1038 — `shieldcortex config --action-guard-enabled` must not print the help
 * wall and exit 0. A typo is an unknown option (exit 2, nothing written).
 * Values after `=` are never echoed: they can be credentials.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, jest } from '@jest/globals';
import {
  CONFIG_BOOLEAN_FLAGS,
  CONFIG_KNOWN_OPTIONS,
  CONFIG_VALUE_FLAGS_ALWAYS,
  CONFIG_VALUE_FLAGS_UNLESS_DASH,
  formatUnknownConfigOptions,
  suggestConfigOption,
  unknownConfigOptions,
} from '../../cloud/config-args.js';

const HANDLER_START = 'function handleCloudConfigFlags';
const HANDLER_END = 'export async function handleCloudCommand';

function handlerSource(): string {
  const src = readFileSync(path.join(process.cwd(), 'src/cloud/cli.ts'), 'utf8');
  const start = src.indexOf(HANDLER_START);
  const end = src.indexOf(HANDLER_END);
  if (start === -1 || end === -1 || end <= start) {
    throw new Error('could not slice handleCloudConfigFlags');
  }
  return src.slice(start, end);
}

describe('#1038 config unknown options', () => {
  it('suggests --action-guard-enable for the reported typo, and nothing on a tie', () => {
    expect(suggestConfigOption('--action-guard-enabled')).toBe('--action-guard-enable');
    expect(suggestConfigOption('--not-a-real-option-at-all')).toBeNull();
  });

  it('the reported typo is one stderr line plus a help pointer, and does not dump help', () => {
    expect(formatUnknownConfigOptions(['--action-guard-enabled'])).toEqual([
      'Unknown option "--action-guard-enabled". Did you mean --action-guard-enable?',
      'See `shieldcortex config --help`.',
    ]);
  });

  it('does not treat a value, a help flag, or a bare invocation as unknown', () => {
    expect(unknownConfigOptions([])).toEqual([]);
    expect(unknownConfigOptions(['--help'])).toEqual([]);
    expect(unknownConfigOptions(['-h'])).toEqual([]);
    expect(unknownConfigOptions(['--mode', 'balanced'])).toEqual([]);
    expect(unknownConfigOptions(['--action-guard-enable'])).toEqual([]);
    expect(unknownConfigOptions(['--dashboard-update-check', 'false'])).toEqual([]);
  });

  it('consumes a dash-looking value of an always-flag so the existing invalid-value path still owns it', () => {
    expect(unknownConfigOptions(['--mode', '--nope'])).toEqual([]);
  });

  it('does not consume a -- value of an unless-dash flag, and still names the typo beside a real flag', () => {
    expect(unknownConfigOptions(['--memory-plane', '--bogus'])).toEqual(['--bogus']);
    expect(unknownConfigOptions(['--action-guard-enable', '--action-guard-enabled'])).toEqual([
      '--action-guard-enabled',
    ]);
  });

  it('never echoes an equals value', () => {
    const secret = 's3cret-value-must-not-appear';
    const lines = formatUnknownConfigOptions([`--cloud-api-key=${secret}`]);
    expect(lines?.join('\n')).not.toContain(secret);
    expect(lines?.[0]).toBe(
      'Unknown option "--cloud-api-key=…". Pass the value as a separate word.',
    );
  });

  it('lists several unknown options without guessing', () => {
    expect(formatUnknownConfigOptions(['--aa', '--bb'])).toEqual([
      'Unknown options: --aa, --bb.',
      'See `shieldcortex config --help`.',
    ]);
  });

  it('every flag the handler reads is in the known set, and the sets do not overlap', () => {
    const body = handlerSource();
    const read = [...body.matchAll(/args\.(?:includes|indexOf)\('(--[a-z0-9-]+)'\)/g)].map((m) => m[1]);
    expect(read.length).toBeGreaterThan(20);
    const known = new Set(CONFIG_KNOWN_OPTIONS);
    const missing = [...new Set(read)].filter((f) => !known.has(f));
    expect(missing).toEqual([]);
    const overlap = CONFIG_BOOLEAN_FLAGS.filter((f) =>
      (CONFIG_VALUE_FLAGS_ALWAYS as readonly string[]).includes(f)
      || (CONFIG_VALUE_FLAGS_UNLESS_DASH as readonly string[]).includes(f),
    );
    expect(overlap).toEqual([]);
  });

  it('every flag documented in CONFIG_HELP is known, a resign token, or help', () => {
    const help = readFileSync(path.join(process.cwd(), 'src/cli/dispatch-help.ts'), 'utf8');
    const start = help.indexOf('export const CONFIG_HELP');
    const end = help.indexOf('export const CLOUD_HELP');
    const block = help.slice(start, end);
    const lineFlags = [...block.matchAll(/^\s*(--[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)/gm)].map((m) => m[1]);
    const slashFlags = [...block.matchAll(/ \/ (--[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)/g)].map((m) => m[1]);
    const documented = [...lineFlags, ...slashFlags];
    const known = new Set<string>([...CONFIG_KNOWN_OPTIONS, '--resign', '--confirm', '--help']);
    const missing = [...new Set(documented)].filter((f) => !known.has(f));
    expect(missing).toEqual([]);
  });
});

describe('#1038 config handler refuses before any write', () => {
  const suiteDir = mkdtempSync(path.join(tmpdir(), 'sc1038-'));
  const prev = process.env.SHIELDCORTEX_CONFIG_DIR;

  beforeAll(() => {
    process.env.SHIELDCORTEX_CONFIG_DIR = suiteDir;
  });

  afterAll(() => {
    if (prev === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = prev;
    rmSync(suiteDir, { recursive: true, force: true });
  });

  async function refuse(args: string[]): Promise<{ err: string; log: string }> {
    const err: string[] = [];
    const log: string[] = [];
    jest.spyOn(console, 'error').mockImplementation((m: unknown) => { err.push(String(m)); });
    jest.spyOn(console, 'log').mockImplementation((m: unknown) => { log.push(String(m)); });
    jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as never);
    const { clearCloudConfigCache } = await import('../../cloud/config.js');
    clearCloudConfigCache();
    const { handleCloudConfig } = await import('../../cloud/cli.js');
    expect(() => handleCloudConfig(args)).toThrow('exit 2');
    jest.restoreAllMocks();
    return { err: err.join('\n'), log: log.join('\n') };
  }

  it('the typo exits 2, names the real flag, and writes nothing', async () => {
    const { err, log } = await refuse(['--action-guard-enabled']);
    expect(err).toContain('Unknown option "--action-guard-enabled". Did you mean --action-guard-enable?');
    expect(err).toContain('See `shieldcortex config --help`.');
    expect(log).not.toMatch(/Usage: shieldcortex config/);
    expect(log).not.toMatch(/API Key/);
    expect(existsSync(path.join(suiteDir, 'config.json'))).toBe(false);
  });

  it('a typo beside a real enable does not turn the guard on', async () => {
    const { err } = await refuse(['--action-guard-enable', '--action-guard-enabled']);
    expect(err).toContain('--action-guard-enabled');
    expect(existsSync(path.join(suiteDir, 'config.json'))).toBe(false);
  });
});
