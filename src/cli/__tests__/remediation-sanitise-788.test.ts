/**
 * #788 — native-engine remediation text and the update footer's re-run line
 * are host-derived (install directory, error text, agent id). #783 sanitised
 * them on the update screen's engine panel; these are the remaining terminal
 * sinks: `shieldcortex repair`, the doctor human report, the MCP startup
 * failure message and the update footer. A hostile install dir / agent id must
 * not reach the terminal with escape sequences, C1 controls, stray line breaks
 * or bidi/zero-width code points intact. Ordinary text prints unchanged, and
 * doctor's `--json` keeps the raw values.
 */
import fs from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { formatEngineFailureDetail } from '../repair.js';
import { formatDoctorReport, sanitiseDoctorRowsForDisplay } from '../doctor-report.js';
import { formatMcpSpawnError } from '../../setup/mcp-self-heal.js';
import { nativeBindingRemediation } from '../../setup/native-binding.js';
import { footer } from '../update.js';
import { sanitiseDisplayLines } from '../term-ui.js';

// Hostile middle section: CSI clear-screen, a BEL-terminated OSC 8 hyperlink,
// 8-bit CSI (U+009B), bare CR, U+2028, U+2029, U+0085, RLO (U+202E),
// zero-width space (U+200B) and an isolate (U+2066). No '/' or LF so it can be
// a single path component.
const HOSTILE =
  'a\u001b[2Jb\u001b]8;;x\u0007c\u009b2Kd\re\u2028f\u2029g\u0085h\u202ei\u200bj\u2066k';
const HOSTILE_DIR = path.join('/opt', `inst-${HOSTILE}`, 'shieldcortex');
const ORDINARY_DIR = '/opt/tools/shieldcortex';

// The renderers' own SGR styling.
const RENDERER_SGR = /\u001b\[[0-9;]*m/g;

function expectClean(text: string): void {
  const withoutStyle = text.replace(RENDERER_SGR, '');
  // Any C0 except TAB and the renderer's own LF line joins, DEL or C1.
  // eslint-disable-next-line no-control-regex
  expect(withoutStyle).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
  expect(withoutStyle).not.toMatch(/[\u2028\u2029\u200b\u202a-\u202e\u2066-\u2069]/);
}

const plain = (_code: string, s: string) => s;

describe('#788 shieldcortex repair: engine failure detail', () => {
  it('sanitises the error line, build tail and remediation from a hostile install dir', () => {
    const remediation = nativeBindingRemediation(HOSTILE_DIR, 'NODE_MODULE_VERSION 127 vs 108');
    const out = formatEngineFailureDetail({
      error: `Cannot load ${HOSTILE_DIR}/build/Release/x.node\nstack`,
      rebuildOutput: `gyp info ${HOSTILE}\nmake: *** ${HOSTILE}`,
      remediation,
    }, plain);
    expectClean(out);
    expect(out).toContain('Recommended recovery:');
    expect(out).toContain('npm run build-release');
    // The hostile text is shown (cleaned), not dropped.
    expect(out).toContain('d⏎e⏎f⏎g⏎h');
  });

  it('keeps the coloured renderer output clean too', () => {
    const paint = (code: string, s: string) => `\u001b[${code}m${s}\u001b[0m`;
    const out = formatEngineFailureDetail({
      error: `boom ${HOSTILE}`,
      remediation: nativeBindingRemediation(HOSTILE_DIR, 'NODE_MODULE_VERSION 127 vs 108'),
    }, paint);
    expectClean(out);
  });

  it('prints ordinary text unchanged', () => {
    const remediation = nativeBindingRemediation(ORDINARY_DIR, 'NODE_MODULE_VERSION 127 vs 108');
    const out = formatEngineFailureDetail({
      error: 'Cannot load binding\nsecond line',
      rebuildOutput: 'line one\nline two',
      remediation,
    }, plain);
    const expected =
      '     Cannot load binding\n' +
      '\n  Build output (last lines):\n' +
      '     line one\n     line two\n' +
      '\n  Recommended recovery:\n' +
      remediation.split('\n').map((l) => `     ${l}\n`).join('') +
      '\n';
    expect(out).toBe(expected);
  });
});

describe('#788 doctor human report', () => {
  const hostileRow = {
    label: 'Database',
    status: 'fail' as const,
    message: `cannot load the database engine\nCannot load ${HOSTILE_DIR}`,
    fix: nativeBindingRemediation(HOSTILE_DIR, 'NODE_MODULE_VERSION 127 vs 108'),
    verboseNote: `note ${HOSTILE}`,
  };

  it('renders a hostile remediation fix with no control sequences', () => {
    const rows = sanitiseDoctorRowsForDisplay([hostileRow]);
    const lines = formatDoctorReport(rows, { verbose: true, width: 100, color: false });
    expectClean(lines.join('\n'));
  });

  it('keeps layout line breaks and leaves the input rows (the --json source) raw', () => {
    const rows = sanitiseDoctorRowsForDisplay([hostileRow]);
    expect(rows[0].fix?.split('\n').length).toBe(hostileRow.fix.split('\n').length);
    expect(rows[0].message.split('\n').length).toBe(2);
    expect(hostileRow.fix).toContain('\u001b[2J');
    expect(rows[0].fix).not.toContain('\u001b');
  });

  it('leaves ordinary rows unchanged', () => {
    const row = {
      label: 'Database',
      status: 'fail' as const,
      message: 'cannot open\nsecond line',
      fix: nativeBindingRemediation(ORDINARY_DIR, 'NODE_MODULE_VERSION 127 vs 108'),
    };
    expect(sanitiseDoctorRowsForDisplay([row])).toEqual([row]);
  });

  it('doctor feeds the display copy to the report and NEXT, and the raw rows to --json', () => {
    const src = fs.readFileSync(path.join(process.cwd(), 'src/cli/doctor.ts'), 'utf8');
    expect(src).toContain('const displayRows = sanitiseDoctorRowsForDisplay(visible);');
    expect(src).toContain("const failFix = displayRows.find((r) => r.status === 'fail' && r.fix)");
    expect(src).toContain('const reportLines = formatDoctorReport(displayRows, {');
    expect(src).toContain('results: visible.map((r) => ({');
  });
});

describe('#788 MCP startup failure message', () => {
  it('sanitises the install dir, remediation and underlying error', () => {
    const msg = formatMcpSpawnError(HOSTILE_DIR, `NODE_MODULE_VERSION 127 ${HOSTILE}`);
    expectClean(msg);
    expect(msg).toContain('Recommended recovery:');
    expect(msg).toContain('npm run build-release');
  });

  it('keeps a multi-line underlying error on its own line with ⏎ marks', () => {
    const msg = formatMcpSpawnError(ORDINARY_DIR, 'load failed\n[ok] database engine healthy\r\nrun this command');
    const lines = msg.split('\n');
    expect(lines[lines.length - 1]).toBe('Underlying error: load failed⏎[ok] database engine healthy⏎run this command');
    expect(lines.filter((l) => l.startsWith('[ok]'))).toEqual([]);
    expect(lines.filter((l) => l === 'run this command')).toEqual([]);
  });

  it('is unchanged for an ordinary install dir', () => {
    const underlying = 'NODE_MODULE_VERSION 127 vs 108';
    const remediation = nativeBindingRemediation(ORDINARY_DIR, underlying);
    expect(formatMcpSpawnError(ORDINARY_DIR, underlying)).toBe([
      'ShieldCortex MCP server failed to start: the database engine (better-sqlite3)',
      'could not be loaded and automatic recovery did not produce a loadable binding.',
      '',
      `Install: ${ORDINARY_DIR}`,
      '',
      'Recommended recovery:',
      ...remediation.split('\n').map((line) => `  ${line}`),
      'Then restart the app that launches this MCP server.',
      '',
      `Underlying error: ${underlying}`,
    ].join('\n'));
  });
});

describe('#788 update footer re-run line', () => {
  function runFooter(unresolved: Array<{ label: string; rerun: string }>): string {
    const calls: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (process.stdout as any).write = (chunk: any) => { calls.push(String(chunk)); return true; };
    try {
      footer(1234, true, { version: '0.0.0-test' }, unresolved);
    } finally {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (process.stdout as any).write = original;
    }
    return calls.join('');
  }

  it('sanitises a hostile agent id in the re-run command', () => {
    const out = runFooter([{ label: 'OpenClaw skill', rerun: `openclaw skills install --agent ${HOSTILE}` }]);
    expectClean(out);
    expect(out).toContain('openclaw skills install --agent a');
  });

  it('prints an ordinary re-run command unchanged', () => {
    const rerun = 'openclaw plugins install @drakon-systems/shieldcortex-realtime';
    const out = runFooter([{ label: 'OpenClaw plugin', rerun }]).replace(RENDERER_SGR, '');
    expect(out).toContain(`OpenClaw plugin: re-run ${rerun}`);
  });
});

describe('#788 sanitiseDisplayLines', () => {
  it('cleans each line and keeps LF/CRLF layout breaks as LF', () => {
    expect(sanitiseDisplayLines(`one\r\ntwo\nthree${HOSTILE}`)).toBe(
      'one\ntwo\nthreeabc2Kd⏎e⏎f⏎g⏎hijk',
    );
  });
});
