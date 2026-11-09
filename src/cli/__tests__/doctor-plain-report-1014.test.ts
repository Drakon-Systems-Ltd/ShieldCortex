/**
 * #1014 — doctor's default report is plain English and fits on one screen.
 *
 * Snapshot tests on three fixtures captured from a real host (v5.19.0, 91
 * rows): a healthy host with two actionable warnings and four by-design ones,
 * the same host with failures, and the same host with only by-design
 * warnings. The fixtures are the `--json` rows, so the renderer is driven by
 * exactly what doctor computes; the renderer changes none of them.
 */
import { describe, expect, it } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import {
  formatDoctorReport,
  shouldColorDoctor,
  type DoctorReportItem,
} from '../doctor-report.js';
import {
  doctorRowId,
  formatDoctorExplain,
  scrubInternal,
  sessionCounts,
  wrapSoft,
} from '../doctor-plain.js';
import type { HostGatePlanes, HostTable } from '../../setup/host-table.js';

const FIXTURES = path.join(process.cwd(), 'src', '__fixtures__', 'doctor');

function fixture(name: string): DoctorReportItem[] {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, `${name}.json`), 'utf-8')) as DoctorReportItem[];
}

const HOST_TABLE: HostTable = {
  home: '/home/tars',
  rows: [
    { id: 'claude', label: 'Claude Code', kind: 'bound', present: true, wired: true, wireCommand: 'shieldcortex setup', unwireCommand: 'shieldcortex setup uninstall' },
    { id: 'openclaw', label: 'OpenClaw', kind: 'bound', present: false, wired: false, wireCommand: 'shieldcortex openclaw install', unwireCommand: 'shieldcortex openclaw uninstall' },
    { id: 'hermes', label: 'Hermes', kind: 'bound', present: true, wired: true, wireCommand: 'shieldcortex hermes install', unwireCommand: 'shieldcortex hermes uninstall' },
    { id: 'codex', label: 'Codex', kind: 'memory-only', present: true, wired: true, wireCommand: 'shieldcortex codex install', unwireCommand: 'shieldcortex codex uninstall' },
    { id: 'copilot', label: 'Cursor / VS Code', kind: 'memory-only', present: false, wired: false, wireCommand: 'shieldcortex copilot install', unwireCommand: 'shieldcortex copilot uninstall' },
  ],
};

/** Guard off in signed config, Claude Code hook wired, no OpenClaw. */
const PLANES: HostGatePlanes = {
  signedEnforce: false,
  signedEnabled: false,
  claudeWired: true,
  openclaw: 'unknown',
  postureMismatch: false,
  postureNodeReference: 'off',
};

const STYLE = { bold: '\x1b[1m', reset: '\x1b[0m', green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m', cyan: '\x1b[36m', dim: '\x1b[2m' };

function render(rows: DoctorReportItem[], extra: Partial<Parameters<typeof formatDoctorReport>[1]> = {}): string[] {
  return formatDoctorReport(rows, {
    version: '5.19.0',
    target: 'tars',
    width: 120,
    color: false,
    hostTable: HOST_TABLE,
    gatePlanes: PLANES,
    ...extra,
  });
}

// eslint-disable-next-line no-control-regex
const ANSI = /\x1b\[[0-9;]*m/g;

/** Wording that belongs in --verbose / --explain only (#1014 AC2). */
const INTERNAL = [
  /\.ts\b/, /\bWHERE\b/, /#\d+/, /plugins\.entries/, /actionGuard\./, /notify\.enabled/, /…/,
  /Runtime posture/, /NEEDS ATTENTION/, /configured posture, not a live check/, /self-reported by the runtime/,
];

const HEALTHY = fixture('healthy-host');
const FAILURES = fixture('failures-host');
const EXPECTED_ONLY = fixture('expected-only-host');

describe('#1014 fixtures keep the real host shape', () => {
  it('healthy: 0 fail, 6 warn, 39 pass, 46 info', () => {
    const count = (s: string) => HEALTHY.filter((r) => r.status === s).length;
    expect([count('fail'), count('warn'), count('pass'), count('info')]).toEqual([0, 6, 39, 46]);
  });
});

describe('#1014 default report — snapshots', () => {
  it('healthy host', () => {
    expect(render(HEALTHY).join('\n')).toMatchSnapshot();
  });
  it('host with failures', () => {
    expect(render(FAILURES).join('\n')).toMatchSnapshot();
  });
  it('host with only expected warnings', () => {
    expect(render(EXPECTED_ONLY).join('\n')).toMatchSnapshot();
  });
});

describe('#1014 AC7 — one screen', () => {
  it('healthy fixture is at most 30 lines and no line exceeds 100 columns', () => {
    const lines = render(HEALTHY);
    expect(lines.length).toBeLessThanOrEqual(30);
    for (const l of lines) expect(l.length).toBeLessThanOrEqual(100);
  });

  it('a 200-column terminal still wraps at 100', () => {
    for (const rows of [HEALTHY, FAILURES, EXPECTED_ONLY]) {
      for (const l of render(rows, { width: 200 })) expect(l.length).toBeLessThanOrEqual(100);
    }
  });

  it('the coloured TTY render is the same height and visible width', () => {
    const lines = render(HEALTHY, { color: true, style: STYLE });
    expect(lines.length).toBeLessThanOrEqual(30);
    for (const l of lines) expect(l.replace(ANSI, '').length).toBeLessThanOrEqual(100);
  });
});

describe('#1014 AC1 — three tiers', () => {
  const text = render(HEALTHY).join('\n');
  const section = (title: string) => {
    const start = text.indexOf(`\n${title}`);
    expect(start).toBeGreaterThan(-1);
    const rest = text.slice(start + 1);
    const end = rest.indexOf('\n\n');
    return end === -1 ? rest : rest.slice(0, end);
  };

  it('verdict line: healthy, two things to fix, Guard off', () => {
    expect(text).toMatch(/^\[OK\] Healthy \| 2 things to fix \| Guard: off \(your choice\)$/m);
  });

  it('TO FIX holds the two actionable warnings, each with a plain line and a command', () => {
    const fix = section('TO FIX');
    expect(fix).toMatch(/^ 1\. 79 memories can't be found by meaning search \(27%\)/m);
    expect(fix).toMatch(/^    \$ shieldcortex memories embed-backfill --execute$/m);
    expect(fix).toMatch(/^ 2\. Session-end memory capture is switched on but not connected/m);
    expect(fix).toMatch(/^    \$ shieldcortex setup --with-session-end$/m);
    // No by-design warning in TO FIX.
    expect(fix).not.toMatch(/Conversation scanning|Action Guard off|notifications|Policy lock/);
  });

  it('EXPECTED is one line with the four do-not-act warnings and nothing actionable', () => {
    const exp = section('EXPECTED ON THIS HOST (no action)');
    expect(exp.split('\n')).toHaveLength(2);
    expect(exp).toMatch(/Conversation scanning off \| Action Guard off \| Guard notifications not set \| Policy lock not set/);
    expect(exp).not.toMatch(/\$ |embed-backfill|with-session-end/);
  });

  it('with failures, the FAIL rows lead TO FIX and the verdict says so', () => {
    const lines = render(FAILURES);
    const t = lines.join('\n');
    expect(t).toMatch(/^\[FAIL\] 3 failed checks \| 7 things to fix \| Guard: off \(your choice\)$/m);
    expect(t).toMatch(/^ 1\. The memory database refused a test write/m);
    expect(t).toMatch(/^ 2\. Some Claude Code hooks are missing or broken/m);
    expect(t).toMatch(/^ 3\. Action Guard is on, but any process running as you could switch it off/m);
    expect(t).toMatch(/^    \$ sudo shieldcortex protect$/m);
    // An enforcing guard with nobody to tell is actionable, as prose: a warning never prints a guard-changing `$`.
    expect(t).toMatch(/Nobody is told when Action Guard blocks something unattended/);
    expect(t).not.toMatch(/\$ shieldcortex config --action-guard-notify-webhook/);
    expect(t).not.toMatch(/Guard is off or the plugin is off/);
    expect(t.indexOf('TO FIX')).toBeLessThan(t.indexOf('EXPECTED ON THIS HOST'));
  });

  it('with only expected warnings there is no TO FIX section and nothing to fix', () => {
    const t = render(EXPECTED_ONLY).join('\n');
    expect(t).toMatch(/^\[OK\] Healthy \| nothing to fix \| Guard: off \(your choice\)$/m);
    expect(t).not.toMatch(/TO FIX/);
    expect(t).toMatch(/Conversation scanning off \| Action Guard off \| Guard notifications not set \| Policy lock not set/);
  });
});

describe('#1014 AC2 — no internal text in the default report', () => {
  it.each([
    ['healthy', HEALTHY], ['failures', FAILURES], ['expected-only', EXPECTED_ONLY],
  ])('%s fixture', (_name, rows) => {
    const text = render(rows).join('\n');
    for (const re of INTERNAL) expect({ re: String(re), hit: re.test(text) }).toEqual({ re: String(re), hit: false });
  });

  it('scrubInternal drops source refs, SQL, issue numbers and dotted keys, never ellipsizes', () => {
    expect(scrubInternal(
      '213/292 memories embedded — 79 (27%) have no vector (search.ts filters WHERE embedding IS NOT NULL; they are not ranked low)',
    )).toBe('213/292 memories embedded — 79 (27%) have no vector');
    expect(scrubInternal('denials stay local. The #242 cron incidents were this shape.')).toBe('denials stay local.');
    expect(scrubInternal('too many (actionGuard.notify.webhookUrl unset) rows')).toBe('too many rows');
    expect(scrubInternal('healthy (7.6 MB, WAL 680.0 KB)')).toBe('healthy (7.6 MB, WAL 680.0 KB)');
    expect(scrubInternal('')).toBe('');
  });

  it('the detail is still there with --verbose', () => {
    const text = render(HEALTHY, { verbose: true, hostTableLines: ['ShieldCortex  5.19.0    Guard off'] }).join('\n');
    expect(text).toMatch(/NEEDS ATTENTION/);
    expect(text).toMatch(/plugins\.entries\.shieldcortex-realtime\.hooks\.allowConversationAccess/);
    expect(text).toMatch(/#242/);
    expect(text).toMatch(/^HOSTS$/m);
    expect(text).toMatch(/HEALTHY/);
    expect(text.match(/Runtime posture: Claude Code/g)).toHaveLength(16);
  });
});

describe('#1014 AC3 — one line per agent', () => {
  it('collapses 16 Claude Code and 16 Hermes posture rows into counts, and absent agents into one line each', () => {
    const lines = render(HEALTHY);
    const agents = lines.slice(lines.indexOf('AGENTS ON THIS HOST') + 1, lines.indexOf('AGENTS ON THIS HOST') + 6);
    expect(agents).toEqual([
      ' Claude Code       [ok] connected | memory + tool gate | gate off   (16+ sessions)',
      ' OpenClaw          [--] not installed',
      ' Hermes            [ok] connected | memory + tool gate | advisory   (1 live, 15+ ended)',
      ' Codex             [ok] connected | memory only',
      ' Cursor / VS Code  [--] not installed',
    ]);
    expect(lines.filter((l) => /OpenClaw/.test(l))).toHaveLength(1);
    expect(lines.filter((l) => /Hermes/.test(l))).toHaveLength(1);
  });

  it('sessionCounts reads live/ended per agent from the posture rows only', () => {
    const counts = sessionCounts(HEALTHY);
    expect(counts.get('Claude Code')).toEqual({ live: 16, ended: 0, more: true });
    expect(counts.get('Hermes')).toEqual({ live: 1, ended: 15, more: true });
    expect(counts.has('Codex')).toBe(false);
    expect(sessionCounts([{ label: 'Runtime posture (host)', status: 'info', message: 'weakest (current)' }]).size).toBe(0);
  });

  it('a present but unwired host says so with its wire command', () => {
    const table: HostTable = { home: '/h', rows: [{ ...HOST_TABLE.rows[2], wired: false }] };
    const text = render(EXPECTED_ONLY, { hostTable: table }).join('\n');
    expect(text).toMatch(/^ Hermes\s+\[!!\] not connected \| run: shieldcortex hermes install$/m);
  });

  it('a Guard-on host says so in the header and on the Claude Code line', () => {
    const planes: HostGatePlanes = { ...PLANES, signedEnabled: true, signedEnforce: true, postureNodeReference: 'enforce' };
    const text = render(EXPECTED_ONLY, { gatePlanes: planes }).join('\n');
    expect(text).toMatch(/Guard: on$/m);
    expect(text).toMatch(/^ Claude Code\s+\[ok\] connected \| memory \+ tool gate \| enforcing/m);
  });
});

describe('#1014 AC4 — the legend', () => {
  it('is not in the default report', () => {
    for (const rows of [HEALTHY, FAILURES, EXPECTED_ONLY]) {
      expect(render(rows).join('\n')).not.toMatch(/Header Guard on\/off\/mixed\/advisory|Word after a host/);
    }
  });
  it('prints with --explain', () => {
    const idx = formatDoctorExplain(HEALTHY, null, { width: 100, style: { ...STYLE, bold: '', reset: '', green: '', yellow: '', red: '', cyan: '', dim: '' } }).join('\n');
    expect(idx).toMatch(/^LEGEND$/m);
    expect(idx).toMatch(/Header Guard on\/off\/mixed\/advisory/);
  });
});

describe('#1014 AC5 — labels, colour and symbols', () => {
  it('uses full words or a stable id, never a clipped theme code', () => {
    const text = render(HEALTHY).join('\n');
    expect(text).not.toMatch(/\b(SEMANT|RUNTIM|OPENCL|MEMORI|ATTEST)\b/);
    expect(text).toMatch(/\[semantic-coverage\]/);
    expect(text).toMatch(/\[auto-memory-sessionend-hook\]/);
    expect(doctorRowId('Runtime posture: Claude Code (tool-gate, c0001)')).toBe('runtime-posture-claude-code-tool-gate-c0001');
    expect(doctorRowId('Action guard policy lock')).toBe('action-guard-policy-lock');
  });

  it('piped (color off): plain ASCII, no escape codes', () => {
    const text = render(HEALTHY).join('\n');
    expect(text).not.toMatch(ANSI);
    // eslint-disable-next-line no-control-regex
    expect(text.replace(/[—·…]/g, 'X')).not.toMatch(/[^\x00-\x7f]/u);
    // The fixture messages carry an em dash; the layout itself adds no non-ASCII.
    const layoutOnly = render(EXPECTED_ONLY).join('\n');
    // eslint-disable-next-line no-control-regex
    expect(layoutOnly).not.toMatch(/[^\x00-\x7f]/);
  });

  it('TTY (color on): colour and symbols', () => {
    const text = render(HEALTHY, { color: true, style: STYLE }).join('\n');
    expect(text).toMatch(ANSI);
    const visible = text.replace(ANSI, '');
    expect(visible).toMatch(/^✅ Healthy · 2 things to fix · Guard: off \(your choice\)$/m);
    expect(visible).toMatch(/✔ connected/);
    expect(visible).toMatch(/— not installed/);
    expect(visible).toMatch(/^ · Conversation scanning off · Action Guard off/m);
  });

  it('a palette passed with color: false is not applied (NO_COLOR is honoured)', () => {
    expect(render(HEALTHY, { color: false, style: STYLE }).join('\n')).not.toMatch(ANSI);
    expect(render(HEALTHY, { color: false, style: STYLE, verbose: true }).join('\n')).not.toMatch(ANSI);
    expect(shouldColorDoctor({ NO_COLOR: '1' }, true)).toBe(false);
    expect(shouldColorDoctor({}, false)).toBe(false);
    expect(shouldColorDoctor({}, true)).toBe(true);
  });
});

describe('#1014 — --explain <ID>', () => {
  const plain = { ...STYLE, bold: '', reset: '', green: '', yellow: '', red: '', cyan: '', dim: '' };

  it('no id: every check id with its status', () => {
    const lines = formatDoctorExplain(HEALTHY, null, { width: 100, style: plain });
    expect(lines[0]).toBe('CHECK IDS');
    expect(lines).toContain('  WARN  semantic-coverage');
    expect(lines).toContain('  PASS  node-runtime');
    expect(lines.filter((l) => /^  (?:PASS|WARN|FAIL|INFO)  /.test(l))).toHaveLength(HEALTHY.length);
  });

  it('a row id: message, fix and command in full', () => {
    const text = formatDoctorExplain(HEALTHY, 'semantic-coverage', { width: 100, style: plain }).join('\n');
    expect(text).toMatch(/^WARN  Semantic coverage  \[semantic-coverage\]$/m);
    expect(text).toMatch(/search\.ts filters WHERE embedding IS NOT NULL/);
    expect(text).toMatch(/^    Fix:$/m);
    expect(text).toMatch(/that is #458/);
    expect(text).toMatch(/^      \$ shieldcortex memories embed-backfill --execute$/m);
    expect(text).not.toMatch(/LEGEND/);
  });

  it('a guard row brings the legend; a warning never gets a guard-changing $ line', () => {
    const text = formatDoctorExplain(HEALTHY, 'action-guard-notify', { width: 100, style: plain }).join('\n');
    expect(text).toMatch(/#242 cron incidents/);
    expect(text).toMatch(/^LEGEND$/m);
    expect(text).not.toMatch(/^\s*\$ /m);
  });

  it("'expected' prints every no-action warning in full", () => {
    const text = formatDoctorExplain(HEALTHY, 'expected', { width: 100, style: plain }).join('\n');
    for (const label of ['Conversation scanning', 'Action guard posture', 'Action guard notify', 'Action guard policy lock']) {
      expect(text).toContain(`WARN  ${label}  [`);
    }
    expect(text).not.toContain('Semantic coverage');
  });

  it('an unknown id says so', () => {
    expect(formatDoctorExplain(HEALTHY, 'nope', { width: 100, style: plain })).toEqual([
      'No check with id "nope". Run shieldcortex doctor --explain to list the ids.',
    ]);
  });
});

describe('#1014 — wrapSoft keeps long tokens whole', () => {
  it('wraps at spaces with a hanging indent and never splits a path', () => {
    const p = '/very/long/path/'.repeat(8);
    const lines = wrapSoft(`see ${p} now`, 40, 4, 6);
    expect(lines.some((l) => l.includes(p))).toBe(true);
    expect(lines[0].startsWith('    ')).toBe(true);
    expect(wrapSoft('', 40, 2)).toEqual(['  ']);
  });
});
