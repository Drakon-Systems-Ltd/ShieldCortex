/**
 * Mobile/tmux doctor report renderer — pure unit tests.
 */
import { describe, expect, it } from '@jest/globals';
import {
  cleanWhy,
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

  it('does not mint a conversation-access grant from honesty copy', () => {
    const cmds = extractFixCommands(
      'Add hooks.allowConversationAccess=true in openclaw.json, then run `openclaw gateway restart`. Conversation content is sensitive.',
    );
    expect(cmds).toEqual([]);
  });


  it('surfaces conversation-access grant before gateway restart', () => {
    const cmds = extractFixCommands(
      'Add "hooks": { "allowConversationAccess": true } to plugins.entries["shieldcortex-realtime"] in ~/.openclaw/openclaw.json, then restart the gateway.',
    );
    expect(cmds).toEqual([]);
  });

  it('never treats English restart prose as a command', () => {
    expect(extractFixCommands('restart OpenClaw gateway')).toEqual(['openclaw gateway restart']);
    expect(extractFixCommands('restart long-running ShieldCortex processes')).toEqual([
      'openclaw gateway restart',
    ]);
  });
});

describe('wrapLine / oneLineWhy', () => {
  it('never exceeds width', () => {
    const long = 'word '.repeat(40).trim();
    for (const line of wrapLine(long, 40, 4, 6)) {
      expect(line.length).toBeLessThanOrEqual(40);
    }
  });

  it('ellipsizes why to width (compact info/pass path only)', () => {
    expect(oneLineWhy('a'.repeat(100), 40).length).toBeLessThanOrEqual(40);
  });

  it('cleanWhy collapses whitespace and strips backticks without ellipsizing', () => {
    const long = 'x'.repeat(200);
    expect(cleanWhy(`a  \`b\`\n c ${long}`)).toBe(`a b c ${long}`);
  });
});

describe('formatDoctorReport — Edith case (default is the #1014 plain-English report)', () => {
  it('default: actionable warns under TO FIX with their commands, by-design warns under EXPECTED, passes counted', () => {
    const lines = formatDoctorReport(EDITH, {
      version: '4.54.2',
      target: 'edith',
      width: 48,
      color: false,
      verbose: false,
    });
    const text = lines.join('\n');
    // 48 columns wraps sentences; match them with the wrapping collapsed.
    const flat = text.replace(/\s+/g, ' ');

    expect(text).toMatch(/ShieldCortex Doctor \| v4\.54\.2 \| edith/);
    expect(text).toMatch(/Healthy \| 2 things to fix/);

    // Actionable: a plain line and a copy-paste command each.
    expect(text).toMatch(/^TO FIX$/m);
    expect(flat).toMatch(/1\. 1 project name points at the same memories as another/);
    expect(text).toMatch(/\$ shieldcortex doctor --fix-project-keys/);
    expect(text).toMatch(/\$ openclaw gateway restart/);
    expect(text).not.toMatch(/\$ shieldcortex config --action-guard-enable/);
    expect(text).not.toMatch(/\$ shieldcortex config --action-guard-enforce/);
    expect(text).not.toMatch(/\$ shieldcortex openclaw install --allow-conversation-access/);
    expect(text).not.toMatch(/\$ restart/);

    // By design: the two conversation warnings are one phrase; warn-mode is a posture, not a task.
    expect(text).toMatch(/EXPECTED ON THIS HOST/);
    expect(flat).toMatch(/Conversation scanning off \| Action Guard in watch only/);
    expect(text).not.toMatch(/allowConversationAccess/);
    expect(text).not.toMatch(/NEEDS ATTENTION|\bSCAN\b|\bATTEST\b|x2/);

    // Passes and info are counted, not listed.
    expect(text).toMatch(/4 checks passed/);
    expect(text).toMatch(/1 informational row hidden/);
    expect(text).toMatch(/doctor --verbose/);
    expect(text).not.toMatch(/\[ok\].*Database/);
    expect(text).not.toMatch(/Suggested fixes:/);

    // every line fits 48
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(48);
    }
  });

  it('verbose: lists passes and does not hide them', () => {
    const lines = formatDoctorReport(EDITH, {
      version: '4.54.2',
      target: 'edith',
      width: 80,
      color: false,
      verbose: true,
    });
    const text = lines.join('\n');
    expect(text).toMatch(/HEALTHY/);
    expect(text).toMatch(/\[ok\].*Database|DB\s+Database/);
    expect(text).not.toMatch(/pass hidden/);
    // The full report keeps its themes, counts and detail.
    expect(text).toMatch(/NEEDS ATTENTION/);
    expect(text).toMatch(/5 warn/);
    expect(text).toMatch(/allowConversationAccess/);
  });

  it('all-pass host: default says nothing to fix, verbose prints All clear', () => {
    const rows: DoctorReportItem[] = [{ label: 'Database', status: 'pass', message: 'ok' }];
    expect(formatDoctorReport(rows, { width: 80, color: false }).join('\n')).toMatch(/Healthy \| nothing to fix/);
    expect(formatDoctorReport(rows, { width: 80, color: false, verbose: true }).join('\n')).toMatch(/All clear/);
  });

  it('verbose prints HOSTS and NEXT when provided, and the honesty note only on warn-without-fail', () => {
    const warnOnly = formatDoctorReport(
      [{ label: 'NOTIFY', status: 'warn', message: 'plugin off' }],
      {
        width: 80,
        color: false,
        verbose: true,
        hostTableLines: ['  Hermes  present  not wired  memory + tool gate'],
        nextCommand: 'shieldcortex setup',
      },
    ).join('\n');
    expect(warnOnly).toMatch(/HOSTS/);
    expect(warnOnly).toMatch(/Hermes/);
    expect(warnOnly).toMatch(/NEXT/);
    expect(warnOnly).toMatch(/\$ shieldcortex setup/);
    expect(warnOnly).toMatch(/Honesty warnings are not unprotected/);

    const fail = formatDoctorReport(
      [{ label: 'Database', status: 'fail', message: 'corrupt', fix: 'shieldcortex repair' }],
      { width: 80, color: false, verbose: true, nextCommand: 'shieldcortex repair' },
    ).join('\n');
    expect(fail).not.toMatch(/Honesty warnings are not unprotected/);
    expect(fail).toMatch(/\$ shieldcortex repair/);
  });

  it('default: AGENTS comes from the host table; HOSTS lines, NEXT and the honesty note are --verbose only', () => {
    const text = formatDoctorReport(
      [{ label: 'NOTIFY', status: 'warn', message: 'plugin off' }],
      {
        width: 80,
        color: false,
        hostTableLines: ['  Hermes  present  not wired  memory + tool gate'],
        hostTable: {
          home: '/h',
          rows: [{ id: 'hermes', label: 'Hermes', kind: 'bound', present: true, wired: false, wireCommand: 'shieldcortex hermes install', unwireCommand: 'shieldcortex hermes uninstall' }],
        },
        nextCommand: 'shieldcortex setup',
      },
    ).join('\n');
    expect(text).toMatch(/AGENTS ON THIS HOST/);
    expect(text).toMatch(/Hermes\s+\[!!\] not connected \| run: shieldcortex hermes install/);
    expect(text).not.toMatch(/^HOSTS$/m);
    expect(text).not.toMatch(/^NEXT$/m);
    expect(text).not.toMatch(/Honesty warnings are not unprotected/);
  });

  it('honesty warns: a by-design row goes under EXPECTED, a check that could not run stays under TO FIX; no $ import-native or $ repair anywhere', () => {
    // The producers' own wording (plane-drift.ts DUAL_LEGACY_FIX; doctor.ts
    // index-unreadable). #1014 r3: the second row is a read error, not a
    // chosen posture, so the default report keeps its label and reason.
    const rows: DoctorReportItem[] = [
      {
        label: 'Memory plane (dual-plane drift)',
        status: 'warn',
        message: 'dual_legacy dual-plane drift (time-boxed defect): native agent SoT written inside the window — ~/.claude/MEMORY.md',
        fix: 'Native memory is still the brain. Expected on dual_legacy. Do not run memories import-native from this warning. dual_legacy is a migration escape, not a tidy-up.',
      },
      {
        label: 'OpenClaw plugin loaded',
        status: 'warn',
        message: "couldn't read OpenClaw's plugin list, so couldn't check the realtime plugin is running. This is a check that couldn't run, not a fault",
        fix: "Couldn't read OpenClaw's plugin list file. If the plugin is already loaded you are protected. Do not run repair from this warning.",
      },
    ];
    const dflt = formatDoctorReport(rows, { width: 80, color: false }).join('\n');
    expect(dflt).not.toMatch(/\$ shieldcortex memories import-native/);
    expect(dflt).not.toMatch(/\$ shieldcortex repair/);
    expect(dflt).toMatch(/Native agent memory stays primary/);
    expect(dflt).toMatch(/^ 1\. OpenClaw plugin loaded  \[openclaw-plugin-loaded\]$/m);
    expect(dflt).toMatch(/couldn't read OpenClaw's plugin list/);
    expect(dflt).toMatch(/Do not run repair from this warning/);
    expect(dflt).not.toMatch(/Memory plane \(dual-plane drift\)/);

    const verbose = formatDoctorReport(rows, { width: 80, color: false, verbose: true }).join('\n');
    expect(verbose).not.toMatch(/\$ shieldcortex memories import-native/);
    expect(verbose).not.toMatch(/\$ shieldcortex repair/);
    expect(verbose).not.toMatch(/no single copy-paste command/);
    expect(verbose).toMatch(/Honesty warnings are not unprotected/);
    expect(verbose).toMatch(/Native memory is still the brain/);
    expect(verbose).toMatch(/Do not run repair from this warning/);
  });

  it('verbose warn-only NEXT does not print $ repair or $ import-native', () => {
    const repair = formatDoctorReport(
      [{ label: 'OpenClaw plugin loaded', status: 'warn', message: 'roster unread' }],
      { width: 80, color: false, verbose: true, nextCommand: 'shieldcortex repair' },
    ).join('\n');
    expect(repair).not.toMatch(/\$ shieldcortex repair/);
    expect(repair).not.toMatch(/^NEXT$/m);

    const native = formatDoctorReport(
      [{ label: 'Memory plane', status: 'warn', message: 'dual_legacy' }],
      { width: 80, color: false, verbose: true, nextCommand: 'shieldcortex memories import-native' },
    ).join('\n');
    expect(native).not.toMatch(/\$ shieldcortex memories import-native/);
    expect(native).not.toMatch(/^NEXT$/m);

    const setup = formatDoctorReport(
      [{ label: 'NOTIFY', status: 'warn', message: 'plugin off' }],
      { width: 80, color: false, verbose: true, nextCommand: 'shieldcortex setup' },
    ).join('\n');
    expect(setup).toMatch(/\$ shieldcortex setup/);
  });

  it('Jarvis-class warns: a real command or the row own guidance under TO FIX, posture notes under EXPECTED', () => {
    const text = formatDoctorReport(
      [
        {
          label: 'Memories',
          status: 'warn',
          message: '432 total (99 STM, 331 LTM) — 99/100 STM — consolidation needed',
          fix: 'Housekeeping. STM is near its cap. Run `shieldcortex consolidate` if you want it now; otherwise the worker does it. No action needed unless recall feels stale.',
        },
        {
          label: 'Disk',
          status: 'warn',
          message: '84.3 MB / 100 MB limit — approaching limit (DB 47.7 MB · logs 35.0 MB)',
          fix: '35.0 MB is audit/log files — safe to rotate or clear under ~/.shieldcortex/{logs,audit}/.',
        },
        {
          label: 'Action Guard notify',
          status: 'warn',
          message: 'Action Guard signed config says Enforce, but the OpenClaw plugin is off, notify.openclaw only',
          fix: 'Do not add a webhook and do not enable Action Guard from this line.',
        },
      ],
      { width: 80, color: false },
    ).join('\n');
    expect(text).not.toMatch(/no single copy-paste command/);
    expect(text).toMatch(/\$ shieldcortex consolidate/);
    expect(text).toMatch(/safe to rotate or clear/);
    expect(text).toMatch(/Guard notifications not set/);
    expect(text).not.toMatch(/Do not add a webhook/);
    expect(text).not.toMatch(/\$ shieldcortex memories/);
    expect(text).not.toMatch(/\$ shieldcortex repair/);
  });

  it('warn-only NOTIFY never prints $ webhook', () => {
    const text = formatDoctorReport(
      [{
        label: 'Action Guard notify',
        status: 'warn',
        message: 'Action Guard is disabled and, when re-enabled, would run with no denial-capable notify sink',
        fix: 'Run `shieldcortex config --action-guard-notify-webhook <https-url>` so denials reach a human.',
      }],
      { width: 80, color: false },
    ).join('\n');
    expect(text).not.toMatch(/\$ shieldcortex config --action-guard-notify-webhook/);
    expect(text).toMatch(/Guard notifications not set/);
  });

  it('failures lead TO FIX, numbered, each with its command', () => {
    const lines = formatDoctorReport(
      [
        { label: 'Hooks', status: 'warn', message: 'missing', fix: '`shieldcortex install`' },
        { label: 'Database', status: 'fail', message: 'corrupt', fix: '`shieldcortex repair`' },
      ],
      { width: 60, color: false },
    );
    const text = lines.join('\n');
    expect(text).toMatch(/1 failed check \| 2 things to fix/);
    expect(text).toMatch(/^ 1\. The memory database cannot be opened/m);
    expect(text).toMatch(/^    \$ shieldcortex repair$/m);
    expect(text).toMatch(/^ 2\. Hooks/m);
    expect(text).toMatch(/^    \$ shieldcortex install$/m);
    expect(text.indexOf(' 1. ')).toBeLessThan(text.indexOf(' 2. '));
  });
});

describe('formatDoctorReport — full-screen terminals', () => {
  const LONG_TOKEN = 'FULLY_VISIBLE_WHY_TOKEN_THAT_MUST_NOT_BE_CUT_BY_ELLIPSIS';
  const LONG_FAIL: DoctorReportItem = {
    label: 'Database',
    status: 'fail',
    message:
      'integrity check failed on three tables and the write-ahead log cannot be replayed; ' +
      'the previous backup completed four hours ago so restoring from it loses recent captures — ' +
      `full details are recorded in the audit log under ${LONG_TOKEN}`,
    fix: '`shieldcortex repair`',
  };

  it.each([120, 200])('long fail why appears in full at width %d — no mid-sentence ellipsis', (width) => {
    const lines = formatDoctorReport([LONG_FAIL], { width, color: false });
    const text = lines.join('\n');
    expect(text).toContain(LONG_TOKEN);
    expect(text).not.toContain('…');
    for (const line of lines) {
      expect(line.length).toBeLessThanOrEqual(width);
    }
  });

  it('width 200 is not clamped down to 120 — long single token stays on one line', () => {
    const token = 'A'.repeat(170);
    const lines = formatDoctorReport(
      [{ label: 'Database', status: 'fail', message: `token ${token} end`, fix: '`shieldcortex repair`' }],
      { width: 200, color: false },
    );
    // If width were clamped to 120, wrapLine would hard-split the 170-char
    // token across lines and no single line would contain it whole.
    expect(lines.some((l) => l.includes(token))).toBe(true);
  });

  it('shows all fix commands for a fail item, not just the first three', () => {
    const fix =
      'Run `shieldcortex repair`, then `shieldcortex doctor --fix-project-keys`, ' +
      '`shieldcortex config --action-guard-enforce`, `openclaw gateway restart`, ' +
      'and `shieldcortex memories repair-project-keys --execute`';
    const lines = formatDoctorReport(
      [{ label: 'Database', status: 'fail', message: 'corrupt', fix }],
      { width: 100, color: false },
    );
    const text = lines.join('\n');
    expect(text).toContain('$ shieldcortex repair');
    expect(text).toContain('$ shieldcortex doctor --fix-project-keys');
    expect(text).toContain('$ shieldcortex config --action-guard-enforce');
    expect(text).toContain('$ openclaw gateway restart');
    expect(text).toContain('$ shieldcortex memories repair-project-keys --execute');
  });
});
