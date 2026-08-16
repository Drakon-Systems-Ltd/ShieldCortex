/**
 * Mobile/tmux doctor report renderer — pure unit tests.
 */
import { describe, expect, it } from '@jest/globals';
import {
  collapseKey,
  extractFixCommands,
  formatDoctorReport,
  oneLineWhy,
  themeForLabel,
  wrapLine,
  type DoctorReportItem,
} from '../doctor-report.js';

const EDITH: DoctorReportItem[] = [
  { label: 'Database', status: 'pass', message: 'healthy (47.5 MB, WAL 2.0 MB)' },
  { label: 'Schema', status: 'pass', message: 'up to date' },
  { label: 'Hooks', status: 'pass', message: '4/4 installed and resolving' },
  {
    label: 'Project keys',
    status: 'warn',
    message: '1 legacy/canonical collision(s): workspace ↔ edith-vitaetpax-edith-workspace',
    fix: 'Run shieldcortex doctor --fix-project-keys to auto-repair, or shieldcortex memories repair-project-keys --map workspace=edith-vitaetpax-edith-workspace --include-stm (dry-run by default; add --execute to apply)',
  },
  {
    label: 'OpenClaw plugin loaded',
    status: 'warn',
    message:
      'realtime plugin loaded (roster-confirmed, v4.54.2); enforcement not probed here — prove it live with: SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1 shieldcortex openclaw status. NOTE: conversation-hook access is NOT granted, so the gateway refuses this plugin\'s llm_input/llm_output hooks — tool-call gating is live; conversation scanning is NOT live',
    fix: 'Add "hooks": { "allowConversationAccess": true } to plugins.entries["shieldcortex-realtime"] in ~/.openclaw/openclaw.json, then restart the gateway. Conversation content is sensitive — this is your call, and leaving it ungranted is a valid choice.',
  },
  {
    label: 'Conversation scanning',
    status: 'warn',
    message:
      'conversation scanning INACTIVE — OpenClaw drops llm_input/llm_output at registration because plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess is not true; no conversation content is being scanned on this host',
    fix: 'Add "hooks": { "allowConversationAccess": true } to plugins.entries["shieldcortex-realtime"] in ~/.openclaw/openclaw.json, then restart the gateway. Conversation content is sensitive — this is your call, and leaving it ungranted is a valid choice.',
  },
  {
    label: 'Action guard config',
    status: 'warn',
    message:
      'Action Guard runs in warn-mode (`actionGuard.enforce: false`) on both surfaces — dangerous ops log but are not gated (catastrophic still blocks)',
    fix: 'Run `shieldcortex config --action-guard-enforce` to gate dangerous ops — the CLI writes a signed config; hand-editing config.json invalidates its integrity signature.',
  },
  {
    label: 'Attestation coverage',
    status: 'warn',
    message:
      '7666 hook-captured audit rows in the last 28 days and none carries attestation — these writers attest in the current build, so still-running pre-upgrade processes are writing them',
    fix: 'restart long-running ShieldCortex processes (MCP server, OpenClaw gateway, dashboard) so they load the current build',
  },
  { label: 'Defence canary', status: 'pass', message: 'caught (14ms, pattern: defence_canary)' },
  {
    label: 'Dashboard',
    status: 'info',
    message: 'not running (optional on headless/OpenClaw-only setups)',
  },
];

describe('themeForLabel / collapseKey', () => {
  it('maps Edith labels to short themes', () => {
    expect(themeForLabel('Project keys')).toBe('KEY');
    expect(themeForLabel('Conversation scanning')).toBe('SCAN');
    expect(themeForLabel('Action guard config')).toBe('GUARD');
    expect(themeForLabel('Attestation coverage')).toBe('ATTEST');
  });

  it('collapses the two conversation-related warnings', () => {
    const a = EDITH.find((r) => r.label === 'OpenClaw plugin loaded')!;
    const b = EDITH.find((r) => r.label === 'Conversation scanning')!;
    expect(collapseKey(a)).toBe(collapseKey(b));
    expect(collapseKey(a)).toBe('warn:SCAN');
  });
});

describe('extractFixCommands', () => {
  it('pulls backticked shieldcortex commands', () => {
    expect(extractFixCommands(EDITH.find((r) => r.label === 'Action guard config')!.fix)).toEqual([
      'shieldcortex config --action-guard-enforce',
    ]);
  });

  it('surfaces allowConversationAccess guidance', () => {
    const cmds = extractFixCommands(EDITH.find((r) => r.label === 'Conversation scanning')!.fix);
    expect(cmds.some((c) => c.includes('allowConversationAccess'))).toBe(true);
  });
});

describe('wrapLine / oneLineWhy', () => {
  it('never exceeds width', () => {
    const long = 'word '.repeat(40).trim();
    for (const line of wrapLine(long, 40, 4, 6)) {
      expect(line.length).toBeLessThanOrEqual(40);
    }
  });

  it('ellipsizes why to width', () => {
    expect(oneLineWhy('a'.repeat(100), 40).length).toBeLessThanOrEqual(40);
  });
});

describe('formatDoctorReport — Edith case', () => {
  it('default: collapses SCAN x2, hides passes, ranks attention first', () => {
    const lines = formatDoctorReport(EDITH, {
      version: '4.54.2',
      target: 'edith',
      width: 48,
      color: false,
      verbose: false,
    });
    const text = lines.join('\n');

    expect(text).toMatch(/ShieldCortex Doctor\s+v4\.54\.2/);
    expect(text).toMatch(/target\s+edith/);
    // raw tally keeps 5 warn even if themes collapse
    expect(text).toMatch(/5 warn/);
    expect(text).toMatch(/0 fail/);
    expect(text).toMatch(/4 pass/);

    expect(text).toMatch(/NEEDS ATTENTION/);
    // collapsed conversation theme
    expect(text).toMatch(/SCAN/);
    expect(text).toMatch(/x2/);
    expect(text).toMatch(/Conversation scanning|conversation scanning/i);
    expect(text).toMatch(/GUARD/);
    expect(text).toMatch(/ATTEST/);
    expect(text).toMatch(/KEY/);

    // commands on own lines
    expect(text).toMatch(/\$ shieldcortex config --action-guard-enforce/);
    expect(text).toMatch(/\$ shieldcortex doctor --fix-project-keys/);
    expect(text).toMatch(/allowConversationAccess/);
    expect(text).toMatch(/\$ /);

    // passes collapsed
    expect(text).toMatch(/4 pass hidden/);
    expect(text).toMatch(/doctor --verbose/);
    expect(text).not.toMatch(/\[ok\].*Database/);

    // no old bottom wall header
    expect(text).not.toMatch(/Suggested fixes:/);

    // every line fits 48
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(48);
    }
  });

  it('verbose: lists passes and does not hide them', () => {
    const lines = formatDoctorReport(EDITH, {
      version: '4.54.2',
      width: 80,
      color: false,
      verbose: true,
    });
    const text = lines.join('\n');
    expect(text).toMatch(/HEALTHY/);
    expect(text).toMatch(/\[ok\].*Database|DB\s+Database/);
    expect(text).not.toMatch(/pass hidden/);
  });

  it('all-pass host prints All clear', () => {
    const lines = formatDoctorReport(
      [
        { label: 'Database', status: 'pass', message: 'healthy' },
        { label: 'Hooks', status: 'pass', message: 'ok' },
      ],
      { width: 40, color: false },
    );
    expect(lines.join('\n')).toMatch(/All clear/);
  });

  it('failures section precedes warnings', () => {
    const lines = formatDoctorReport(
      [
        { label: 'Hooks', status: 'warn', message: 'missing', fix: '`shieldcortex install`' },
        { label: 'Database', status: 'fail', message: 'corrupt', fix: '`shieldcortex repair`' },
      ],
      { width: 60, color: false },
    );
    const text = lines.join('\n');
    expect(text.indexOf('FAILURES')).toBeGreaterThanOrEqual(0);
    expect(text.indexOf('FAILURES')).toBeLessThan(text.indexOf('NEEDS ATTENTION'));
    expect(text).toMatch(/\$ shieldcortex repair/);
  });
});
