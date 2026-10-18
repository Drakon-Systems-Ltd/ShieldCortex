/**
 * #785 — the standalone `shieldcortex allowlist` subcommands print
 * host-derived text (pinned paths, notes, argv tokens, error messages) through
 * the same terminal display sanitiser #779 applied to the update screen and
 * the scan renderer. A hostile filename, note, argv token or error message must
 * not reach the terminal with escape sequences, C1 controls, line breaks or
 * bidi/zero-width code points intact. Ordinary text prints unchanged.
 */
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAllowlist } from '../allowlist.js';
import { hashScriptSource } from '../../defence/iron-dome/reviewed-scripts.js';

// Hostile middle section: CSI clear-screen, a BEL-terminated OSC 8 hyperlink,
// 8-bit CSI (U+009B), bare CR, CRLF, U+2028, U+2029, U+0085,
// RLO (U+202E), zero-width space (U+200B) and an isolate (U+2066). No '/' so
// it can also be a single filename component.
const HOSTILE =
  'a\u001b[2Jb\u001b]8;;x\u0007c\u009b2Kd\re\r\nf\u2028g\u2029h\u0085i\u202ej\u200bk\u2066l';

// The renderer's own SGR styling (bold, dim, reset, red, green, yellow).
const RENDERER_SGR = /\u001b\[(?:0|1|2|31|32|33)m/g;

function expectClean(text: string): void {
  const withoutStyle = text.replace(RENDERER_SGR, '');
  // Any C0 (except TAB and the renderer's own LF line joins), DEL or C1.
  expect(withoutStyle).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
  expect(withoutStyle).not.toMatch(/[\u2028\u2029\u200b\u202a-\u202e\u2066-\u2069]/);
}

describe('shieldcortex allowlist output sanitising (#785)', () => {
  let dir: string;
  let stored: unknown[];
  let logs: string[];
  let errs: string[];
  const SOURCE = '#!/bin/sh\necho audit\n';
  const SHA = hashScriptSource(SOURCE);

  const deps = (interactive: boolean, extra: Record<string, unknown> = {}) => ({
    interactive,
    log: (m: string) => logs.push(m),
    error: (m: string) => errs.push(m),
    readEntries: () => stored,
    writeEntries: (e: Array<Record<string, unknown>>) => {
      stored = e;
    },
    ...extra,
  });

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'sc-cli-785-')));
    stored = [];
    logs = [];
    errs = [];
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  test('list: pinned path and note are sanitised', () => {
    stored = [{ path: `/opt/x${HOSTILE}/run.sh`, sha256: SHA, note: `note ${HOSTILE} end`, addedAt: 1 }];
    expect(runAllowlist(['list'], deps(false))).toBe(0);
    const out = logs.join('\n');
    expectClean(out);
    expect(out).toContain('/opt/xab');
    expect(out).toContain('/run.sh');
    expect(out).toContain('⏎');
  });

  test('verify: drifted path is sanitised and the exit code is unchanged', () => {
    stored = [{ path: `/opt/x${HOSTILE}/run.sh`, sha256: SHA }];
    expect(runAllowlist(['verify'], deps(false))).toBe(1);
    const out = logs.join('\n');
    expectClean(out);
    expect(out).toContain('MISSING');
  });

  test('add: error naming a hostile path is sanitised', () => {
    expect(runAllowlist(['add', join(dir, `nope${HOSTILE}.sh`)], deps(true))).toBe(1);
    expect(errs.length).toBeGreaterThan(0);
    expectClean(errs.join('\n'));
    expect(stored).toEqual([]);
  });

  test('add then remove: a hostile filename is sanitised in both confirmations', () => {
    const hostileFile = join(dir, `s${HOSTILE}.sh`);
    writeFileSync(hostileFile, SOURCE);
    expect(runAllowlist(['add', hostileFile], deps(true))).toBe(0);
    expect((stored[0] as Record<string, unknown>).path).toBe(realpathSync(hostileFile));
    expect(runAllowlist(['remove', hostileFile], deps(true))).toBe(0);
    expect(stored).toEqual([]);
    const out = logs.join('\n');
    expectClean(out);
    expect(out).toContain('Pinned');
    expect(out).toContain('Removed');
  });

  test('remove: unmatched hostile target is sanitised', () => {
    expect(runAllowlist(['remove', `/opt/${HOSTILE}`], deps(true))).toBe(1);
    expectClean(errs.join('\n'));
    expect(errs.join('\n')).toContain('No allowlist entry matches');
  });

  test('remove: a hostile write error message is sanitised', () => {
    const file = join(dir, 'ok.sh');
    writeFileSync(file, SOURCE);
    stored = [{ path: file, sha256: SHA }];
    const failing = deps(true, {
      writeEntries: () => {
        throw new Error(`disk ${HOSTILE} full`);
      },
    });
    expect(runAllowlist(['remove', file], failing)).toBe(1);
    expectClean(errs.join('\n'));
    expect(errs.join('\n')).toContain('Could not write the allowlist');
  });

  test('unknown subcommand token is sanitised', () => {
    expect(runAllowlist([`bogus${HOSTILE}`], deps(false))).toBe(1);
    expectClean(errs.join('\n'));
    expect(errs.join('\n')).toContain('Unknown subcommand "bogusab');
  });

  test('ordinary paths and notes print unchanged', () => {
    const plain = join(dir, "daily sentry \"v2\" café's.sh");
    writeFileSync(plain, SOURCE);
    expect(runAllowlist(['add', plain, '--note', 'reviewed naïve 日本語'], deps(true))).toBe(0);
    logs = [];
    expect(runAllowlist(['list'], deps(false))).toBe(0);
    const out = logs.join('\n');
    expect(out).toContain(realpathSync(plain));
    expect(out).toContain('reviewed naïve 日本語');
  });
});
