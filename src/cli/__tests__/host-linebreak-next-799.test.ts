/**
 * #799 — completes #788. A line break inside a host value (the install
 * directory) used to survive into multi-line remediation text, where the
 * display sanitiser kept it as layout: doctor's NEXT then selected the host
 * text as a command (`$ node --version`), and repair / update / the MCP
 * startup message printed it as its own recovery line. Host values are now
 * display-sanitised before they are composed, so their breaks show as ⏎.
 *
 * Also: the MCP startup-failure block printed the breadcrumb path raw after
 * the sanitised message; both stderr writes are now clean.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  formatDoctorReport,
  nextCommandForFailures,
  sanitiseDoctorRowsForDisplay,
} from '../doctor-report.js';
import { formatEngineFailureDetail } from '../repair.js';
import { renderEngineFailure, engineOutcomeFromEnsure } from '../update.js';
import { sanitiseDisplayField } from '../term-ui.js';
import {
  ensureNativeBinding,
  nativeBindingDisplayRemediation,
  nativeBindingRemediation,
  type EnsureResult,
} from '../../setup/native-binding.js';
import {
  formatMcpSpawnError,
  MCP_SPAWN_ERROR_LOG,
  printMcpStartupFailure,
  selfHealMcpNativeBinding,
} from '../../setup/mcp-self-heal.js';

// A non-packaged load error, so the remediation embeds the install dir.
const LOAD_ERROR = 'NODE_MODULE_VERSION 127 vs 108';
const INJECTED = 'node --version';
const BREAKS: Array<[string, string]> = [
  ['LF', '\n'],
  ['CRLF', '\r\n'],
  ['CR', '\r'],
  ['U+2028', '\u2028'],
];
const hostileDir = (br: string) => `/opt/install${br}${INJECTED}${br}rest/shieldcortex`;
const ORDINARY_DIR = '/opt/tools/shieldcortex';

/** Doctor's two native-binding Database rows, as doctor.ts composes them. */
function nativeRow(installDir: string) {
  return {
    label: 'Database',
    status: 'fail' as const,
    message: 'cannot load the database engine (better-sqlite3)',
    fix: nativeBindingRemediation(installDir, LOAD_ERROR),
    displayFix: nativeBindingDisplayRemediation(installDir, LOAD_ERROR),
  };
}

/** True when a rendered line is, or starts with, the injected host text. */
function isInjectedLine(line: string): boolean {
  const t = line.replace(/\u001b\[[0-9;]*m/g, '').trim().replace(/^\$\s*/, '');
  return t === INJECTED || t.startsWith(INJECTED);
}

describe('#799 doctor NEXT: a host line break in the install dir', () => {
  it('doctor.ts composes both native-binding rows with a display-only fix', () => {
    const src = fs.readFileSync(path.join(process.cwd(), 'src/cli/doctor.ts'), 'utf8');
    expect(src.split('displayFix: nativeBindingDisplayRemediation(installDir, ').length - 1).toBe(2);
    expect(src).toContain('nextCommand = nextCommandForFailures(displayRows);');
    // --json emits `fix`, never the display copy.
    expect(src).toContain('label: r.label, status: r.status, message: r.message, fix: r.fix,');
  });

  it.each(BREAKS)('%s: NEXT stays the code-authored command and no fix line is host text', (_name, br) => {
    const row = nativeRow(hostileDir(br));
    const displayRows = sanitiseDoctorRowsForDisplay([row]);
    const nextCommand = nextCommandForFailures(displayRows);

    // The native remediation has no line NEXT can select, so NEXT is doctor's
    // own fallback — never the injected `node --version`.
    expect(nextCommand).toBe('shieldcortex doctor --verbose');

    const lines = formatDoctorReport(displayRows, { verbose: true, width: 200, color: false, nextCommand });
    expect(lines.filter(isInjectedLine)).toEqual([]);
    const nextAt = lines.indexOf('NEXT');
    expect(lines.slice(nextAt, nextAt + 2)).toEqual(['NEXT', '$ shieldcortex doctor --verbose']);

    // The host text is shown, marked, on the code-authored cd line.
    // Only the three code-authored lines.
    expect(displayRows[0].fix?.split('\n')).toHaveLength(3);
    expect(displayRows[0].fix?.split('\n')[0]).toBe(
      `cd "/opt/install⏎${INJECTED}⏎rest/shieldcortex/node_modules/better-sqlite3" && npm run build-release`,
    );
    // The raw row (the --json source) is unchanged.
    expect(row.fix).toContain(`install${br}${INJECTED}${br}rest`);
  });

  it('is byte-identical for an ordinary install dir', () => {
    const row = nativeRow(ORDINARY_DIR);
    expect(row.displayFix).toBe(row.fix);
    const [display] = sanitiseDoctorRowsForDisplay([row]);
    expect(display.fix).toBe(row.fix);
    expect(nextCommandForFailures([display])).toBe('shieldcortex doctor --verbose');
  });

  it('still selects a code-authored command line from a fail fix', () => {
    const rows = sanitiseDoctorRowsForDisplay([
      { label: 'x', status: 'fail' as const, message: 'm', fix: 'Do this:\n  shieldcortex repair\nthen restart' },
    ]);
    expect(nextCommandForFailures(rows)).toBe('shieldcortex repair');
  });
});

describe('#799 repair / update / MCP message: the selected remediation', () => {
  async function failedEnsure(installDir: string): Promise<EnsureResult> {
    return ensureNativeBinding({
      verify: () => ({ ok: false, error: LOAD_ERROR }),
      rebuild: async () => ({ ok: false, output: 'build failed' }),
      installDir: () => installDir,
    });
  }

  it.each(BREAKS)('%s: no sink prints the host text as its own recovery line', async (_name, br) => {
    const dir = hostileDir(br);
    const r = await failedEnsure(dir);
    expect(r.status).toBe('failed');

    const repair = formatEngineFailureDetail(r, (_c, s) => s);
    const update = renderEngineFailure(engineOutcomeFromEnsure(r));
    const mcp = formatMcpSpawnError(dir, LOAD_ERROR, r.remediation);
    for (const out of [repair, update?.body.join('\n') ?? '', mcp]) {
      expect(out.split('\n').filter(isInjectedLine)).toEqual([]);
      expect(out).toContain(`install⏎${INJECTED}⏎rest`);
    }
  });

  it('is byte-identical for an ordinary install dir', async () => {
    const r = await failedEnsure(ORDINARY_DIR);
    expect(r.remediation).toBe(nativeBindingRemediation(ORDINARY_DIR, LOAD_ERROR));
  });
});

describe('#799 MCP startup-failure block: both stderr writes', () => {
  let root: string;
  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-799-')));
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  async function failedHeal(logsDir: string) {
    return selfHealMcpNativeBinding({
      ensure: async () => ({ status: 'failed', error: LOAD_ERROR, remediation: nativeBindingDisplayRemediation('/opt/sc', LOAD_ERROR) }),
      installDir: () => '/opt/sc',
      logsDir: () => logsDir,
      now: () => '2026-10-16T00:00:00.000Z',
    });
  }

  function capture(heal: Parameters<typeof printMcpStartupFailure>[0]): string[] {
    const writes: string[] = [];
    printMcpStartupFailure(heal, (line) => writes.push(line));
    return writes;
  }

  it('cleans a logs path carrying CSI clear-screen and a line break; the file is at the real path', async () => {
    const logsDir = path.join(root, 'logs\u001b[2J\nx\u009b2K\u202ey');
    const heal = await failedHeal(logsDir);
    expect(heal.ok).toBe(false);
    const realCrumb = path.join(logsDir, MCP_SPAWN_ERROR_LOG);
    expect(heal.breadcrumbPath).toBe(realCrumb);
    expect(fs.existsSync(realCrumb)).toBe(true);

    const writes = capture(heal);
    expect(writes).toHaveLength(2);
    const stderr = writes.join('\n');
    // eslint-disable-next-line no-control-regex
    expect(stderr).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/);
    expect(stderr).not.toMatch(/[\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff\u2028\u2029]/);
    expect(writes[0]).toBe(heal.message);
    expect(writes[1]).toBe(`\nDetails written to: ${sanitiseDisplayField(realCrumb)}`);
    expect(writes[1]).toContain('logs⏎x2Ky');
  });

  it('is byte-identical to the previous writes for an ordinary logs path', async () => {
    const logsDir = path.join(root, 'logs');
    const heal = await failedHeal(logsDir);
    expect(capture(heal)).toEqual([heal.message, `\nDetails written to: ${heal.breadcrumbPath}`]);
  });

  it('src/index.ts routes the failure block through printMcpStartupFailure', () => {
    const src = fs.readFileSync(path.join(process.cwd(), 'src/index.ts'), 'utf8');
    expect(src).toContain('printMcpStartupFailure(heal);');
    expect(src).not.toContain('Details written to');
  });
});
