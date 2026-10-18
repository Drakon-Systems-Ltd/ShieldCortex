/**
 * The closing screen of `shieldcortex update` in plain words.
 *
 * Owner report, 15 Oct 2026: the old closing panel said "VERDICT INCOMPLETE"
 * in red because Guard was "unproven" on a host where Guard is OFF by design,
 * and the lines above it read like an incident report ("going nowhere",
 * "roster unread", "index-unreadable"). Users read that as "broken".
 *
 * This module turns the update run's step results into one headline and one
 * row per part. Rules it keeps:
 *   - One headline: green "ShieldCortex updated", yellow "... N things to
 *     check", or red "Update failed ...". Red only for a real failure.
 *   - Every non-OK row says what happened, why it matters, and ONE command.
 *   - Off by design is neutral (○ / [off]), never a warning.
 *   - Couldn't check is yellow, never red.
 *   - Internal words (see BANNED_DEFAULT_PHRASES) stay out of this output.
 *     They live only in the --verbose details.
 *
 * Pure: no process.stdout, no fs. update.ts gathers the facts and prints.
 */

import { wrapText, sanitiseDisplayField, NO_STYLE, type TermStyle } from './term-ui.js';

export type SummaryStepStatus = 'ok' | 'warn' | 'skip' | 'failed' | 'blocked' | 'unproven';

export type RowMark = 'ok' | 'off' | 'check' | 'fail';

export type HeadlineKind = 'updated' | 'check' | 'failed';

export interface UpdateSummaryRow {
  label: string;
  mark: RowMark;
  /** What happened, in plain words. */
  text: string;
  /** Why it matters. Twelve words or fewer. */
  why?: string;
  /** Exactly one command. */
  command?: string;
  /** Word shown before the command: Fix, Check, Turn on. */
  commandLabel?: string;
  /** Short plain note after the command, e.g. where to run it. */
  commandNote?: string;
}

export interface UpdateSummaryInput {
  fromVersion: string;
  toVersion: string;
  /** updated: npm installed the new version. current: already latest.
   *  unknown: the registry could not be asked. failed: npm install failed. */
  packageState: 'updated' | 'current' | 'unknown' | 'failed';
  engine: { ok: boolean; packagedPrebuild?: boolean; remediation?: string | null };
  /** OpenClaw plugin step. 'skip' = OpenClaw plugin not installed. */
  plugin: { status: SummaryStepStatus; rerun?: string };
  skill: { status: SummaryStepStatus; rerun?: string };
  hook?: { status: SummaryStepStatus };
  hermes?: { status: SummaryStepStatus; reason?: string };
  /** Action Guard switch as configured. Off is the default since 4.54.15. */
  guardOn: boolean;
  /** The Guard setting could not be confirmed; takes precedence over guardOn. */
  guardUnknown?: boolean;
  /** End-of-run plugin check on the running OpenClaw gateway. */
  protection: {
    status: SummaryStepStatus;
    /** Plugin seen loaded on the running gateway: yes, no, or unknown. */
    loaded?: 'yes' | 'no' | 'unknown';
    /** False when the running build is older than this CLI. */
    versionOk?: boolean;
    pluginVersion?: string | null;
    /** The plugin version this CLI expects (the CLI's own version). */
    expectedVersion?: string | null;
    gatewayReloaded?: boolean;
    /** The one command the check suggests. */
    nextCommand?: string;
  };
  projectKeysAmbiguous?: boolean;
}

export interface UpdateSummary {
  headline: HeadlineKind;
  title: string;
  rows: UpdateSummaryRow[];
}

/** Words that must not reach the default (non-verbose) update screen. */
export const BANNED_DEFAULT_PHRASES: readonly string[] = [
  'going nowhere',
  'broken',
  'known-broken',
  'unproven',
  'roster',
  'index-unreadable',
  'VERDICT',
  'INCOMPLETE',
  'canary',
  'SoT',
  'pin',
  're-gates',
  'oc-db',
];

/** Raw sha prefixes (12+ hex) and internal issue numbers (#123). */
export const BANNED_DEFAULT_PATTERNS: readonly RegExp[] = [/\b[0-9a-f]{12,}\b/, /#\d{2,}\b/];

/** First version where Action Guard is off unless explicitly enabled. */
export const GUARD_DEFAULT_OFF_SINCE = '4.54.15';

export const GUARD_ON_COMMAND = 'shieldcortex config --action-guard-enable';
export const GUARD_STATUS_COMMAND = 'shieldcortex guard readiness';

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}

function engineFixCommand(engine: UpdateSummaryInput['engine']): string {
  if (engine.packagedPrebuild) return 'npm install -g shieldcortex@latest';
  const first = String(engine.remediation ?? '').split('\n')[0]?.trim() ?? '';
  // The non-prebuild remediation leads with one copy-paste rebuild command.
  if (/npm run build-release/.test(first)) return sanitiseDisplayField(first);
  return 'shieldcortex doctor';
}

/**
 * Turn the run's facts into rows and a headline. Pure.
 */
export function buildUpdateSummary(input: UpdateSummaryInput): UpdateSummary {
  const rows: UpdateSummaryRow[] = [];
  const from = sanitiseDisplayField(input.fromVersion);
  const to = sanitiseDisplayField(input.toVersion);

  // ── Package ──
  if (input.packageState === 'failed') {
    rows.push({
      label: 'Package',
      mark: 'fail',
      text: 'couldn\'t install ' + to,
      why: 'You are still on ' + from + '.',
      command: 'npm install -g shieldcortex@latest',
      commandLabel: 'Fix',
    });
  } else if (input.packageState === 'unknown') {
    rows.push({
      label: 'Package',
      mark: 'check',
      text: 'couldn\'t check for a newer version',
      why: 'You may be missing the latest fixes.',
      command: 'shieldcortex update',
      commandLabel: 'Try again',
    });
  } else {
    rows.push({
      label: 'Package',
      mark: 'ok',
      text: input.packageState === 'current' ? to + ' (already the latest)' : to,
    });
  }

  // ── Engine ──
  if (input.engine.ok) {
    rows.push({ label: 'Engine', mark: 'ok', text: 'ready' });
  } else {
    rows.push({
      label: 'Engine',
      mark: 'fail',
      text: input.engine.packagedPrebuild
        ? 'the database engine won\'t load on this Node version'
        : 'the database engine won\'t start',
      why: 'Memories can\'t be saved or searched until it starts.',
      command: engineFixCommand(input.engine),
      commandLabel: 'Fix',
      commandNote: input.engine.packagedPrebuild ? 'on Node 22.14+ or 24+' : undefined,
    });
  }

  // ── OpenClaw plugin ──
  const p = input.protection;
  const pv = p.pluginVersion ? sanitiseDisplayField(p.pluginVersion) : '';
  const pluginInstalled = input.plugin.status !== 'skip' || (p.status !== 'skip');
  // A plugin older than this CLI is shown whatever the Guard state: with Guard
  // off it used to collapse into a green "installed" row (PR #773 review).
  const pluginBehind = pluginInstalled && p.versionOk === false;
  const pluginFixCommand = p.nextCommand ?? 'shieldcortex repair';
  // The plugin check proved the running gateway has no ShieldCortex plugin.
  // The one red OpenClaw case; it wins over every other OpenClaw row below
  // (PR #773 follow-up: a plugin-step warning used to hide it as yellow).
  const pluginAbsent = p.status === 'failed';
  const pluginStepFailed = input.plugin.status === 'warn' || input.plugin.status === 'failed';
  if (pluginInstalled) {
    const reloaded = p.gatewayReloaded ? ', gateway reloaded' : '';
    if (pluginAbsent) {
      rows.push({
        label: 'OpenClaw',
        mark: 'fail',
        // Keep the plugin step's own problem inside the red row.
        text: (pluginStepFailed ? 'plugin couldn\'t be updated, and ' : '')
          + 'the gateway started without the ShieldCortex plugin',
        why: 'Memory protection is not running in OpenClaw.',
        command: pluginFixCommand,
        commandLabel: 'Fix',
      });
    } else if (pluginStepFailed) {
      rows.push({
        label: 'OpenClaw',
        mark: 'check',
        text: 'plugin couldn\'t be updated',
        why: 'OpenClaw keeps running the previous plugin.',
        command: input.plugin.rerun ?? 'shieldcortex update',
        commandLabel: 'Fix',
      });
    } else if (pluginBehind) {
      const expected = sanitiseDisplayField(p.expectedVersion || input.toVersion);
      rows.push({
        label: 'OpenClaw',
        // Yellow: an update to run, not a broken host. Red is the absent
        // plugin, handled first.
        mark: 'check',
        text: 'plugin ' + (pv ? pv + ' ' : '') + 'is behind ShieldCortex ' + expected,
        why: 'OpenClaw doesn\'t have this update\'s fixes yet.',
        command: pluginFixCommand,
        commandLabel: 'Fix',
      });
    } else if (p.status === 'ok') {
      rows.push({ label: 'OpenClaw', mark: 'ok', text: 'plugin ' + (pv ? pv + ' ' : '') + 'loaded' + reloaded });
    } else {
      // Installed; whether the gateway loaded it was not confirmed. With Guard
      // off that is not a problem worth a line of its own (the Guard row
      // covers the Guard-on case).
      rows.push({ label: 'OpenClaw', mark: 'ok', text: 'plugin ' + (pv ? pv + ' ' : '') + 'installed' + reloaded });
    }
  }

  // ── Skill ──
  if (input.skill.status === 'warn' || input.skill.status === 'failed') {
    rows.push({
      label: 'Skill',
      mark: 'check',
      text: 'couldn\'t be updated',
      why: 'Agents still read the previous ShieldCortex guide.',
      command: input.skill.rerun ?? 'shieldcortex update',
      commandLabel: 'Fix',
    });
  } else if (input.skill.status !== 'skip') {
    rows.push({ label: 'Skill', mark: 'ok', text: 'updated' });
  }

  // ── OpenClaw hook (only when it needs a look) ──
  if (input.hook && (input.hook.status === 'warn' || input.hook.status === 'failed')) {
    rows.push({
      label: 'OpenClaw hook',
      mark: 'check',
      text: 'couldn\'t be refreshed',
      why: 'The previous hook keeps running until it is.',
      command: 'shieldcortex update',
      commandLabel: 'Fix',
    });
  }

  // ── Hermes ──
  if (input.hermes) {
    const h = input.hermes;
    if (h.status === 'warn' || h.status === 'failed') {
      if (h.reason === 'no-interpreter') {
        rows.push({
          label: 'Hermes',
          mark: 'check',
          text: 'couldn\'t find Hermes\' Python, so Hermes wasn\'t updated',
          why: 'Hermes keeps running the previous plugin.',
          command: 'shieldcortex update',
          commandLabel: 'Fix',
          commandNote: 'run it in a terminal where the hermes command works',
        });
      } else {
        rows.push({
          label: 'Hermes',
          mark: 'check',
          text: 'plugin couldn\'t be updated',
          why: 'Hermes keeps running the previous plugin.',
          command: 'shieldcortex doctor',
          commandLabel: 'See why',
        });
      }
    } else if (h.status === 'ok') {
      rows.push({ label: 'Hermes', mark: 'ok', text: 'plugin updated' });
    }
  }

  // ── Guard ──
  if (input.guardUnknown) {
    rows.push({
      label: 'Guard',
      mark: 'check',
      text: 'couldn\'t confirm the Guard setting',
      why: 'The config file could not be read or verified.',
      command: 'shieldcortex doctor',
      commandLabel: 'Check',
    });
  } else if (!input.guardOn) {
    rows.push({
      label: 'Guard',
      mark: 'off',
      text: 'off (the default)',
      command: GUARD_ON_COMMAND,
      commandLabel: 'Turn on',
    });
  } else if (pluginAbsent) {
    // Guard is on, but the gateway it relies on has no plugin. Red, like the
    // OpenClaw row that names the cause; never a tick.
    rows.push({
      label: 'Guard',
      mark: 'fail',
      text: 'on, but OpenClaw isn\'t running the plugin',
      why: 'Risky tool calls in OpenClaw are not being stopped.',
      command: pluginFixCommand,
      commandLabel: 'Fix',
    });
  } else if (pluginBehind) {
    // The OpenClaw row names the cause; this row says what it means for Guard.
    rows.push({
      label: 'Guard',
      mark: 'check',
      text: 'on, but OpenClaw\'s plugin is out of date',
      why: 'Guard needs the plugin from this update.',
      command: pluginFixCommand,
      commandLabel: 'Fix',
    });
  } else if (p.status === 'unproven' || p.status === 'warn' || p.status === 'blocked') {
    rows.push({
      label: 'Guard',
      mark: 'check',
      text: 'on, but couldn\'t confirm OpenClaw is checking tool calls',
      why: 'Risky tool calls might not be stopped.',
      command: p.nextCommand ?? 'shieldcortex doctor',
      commandLabel: 'Check',
    });
  } else {
    rows.push({ label: 'Guard', mark: 'ok', text: p.status === 'ok' ? 'on and checking tool calls' : 'on' });
  }

  // ── Project keys ──
  if (input.projectKeysAmbiguous) {
    rows.push({
      label: 'Memory',
      mark: 'check',
      text: 'some project names clash',
      why: 'Some memories may show under the wrong project.',
      command: 'shieldcortex doctor --fix-project-keys',
      commandLabel: 'Fix',
    });
  }

  const fails = rows.filter((r) => r.mark === 'fail').length;
  const checks = rows.filter((r) => r.mark === 'check').length;
  let headline: HeadlineKind;
  let title: string;
  if (input.packageState === 'failed') {
    headline = 'failed';
    title = 'Update failed \u2014 ShieldCortex is still on ' + from;
  } else if (fails > 0) {
    headline = 'failed';
    title = 'Update failed \u2014 ' + fails + ' ' + plural(fails, 'problem', 'problems') + ' to fix';
  } else {
    const base = input.packageState === 'current' ? 'ShieldCortex is up to date' : 'ShieldCortex updated';
    headline = checks > 0 ? 'check' : 'updated';
    title = checks > 0 ? base + ' \u2014 ' + checks + ' ' + plural(checks, 'thing', 'things') + ' to check' : base;
  }
  return { headline, title, rows };
}

export interface RenderSummaryOpts {
  width?: number;
  style?: TermStyle;
  /** Plain ASCII markers and arrows: NO_COLOR, non-TTY, or no UTF-8. */
  ascii?: boolean;
}

const LABEL_COL = 15;

function markText(mark: RowMark, ascii: boolean): string {
  if (ascii) return mark === 'ok' ? '[ok] ' : mark === 'off' ? '[off]' : mark === 'check' ? '[!]  ' : '[x]  ';
  return mark === 'ok' ? '\u2713' : mark === 'off' ? '\u25cb' : mark === 'check' ? '!' : '\u2717';
}

function markColor(mark: RowMark, style: TermStyle): string {
  return mark === 'ok' ? style.green : mark === 'off' ? style.dim : mark === 'check' ? style.yellow : style.red;
}

function asciiText(s: string, ascii: boolean): string {
  if (!ascii) return s;
  return s.replace(/\u2014/g, '-').replace(/\u2192/g, '->').replace(/\u2019/g, '\'');
}

/**
 * Render the summary. Fits 80 columns; wraps, never clips a command.
 */
export function renderUpdateSummary(
  summary: UpdateSummary,
  input: Pick<UpdateSummaryInput, 'fromVersion' | 'toVersion' | 'packageState'>,
  opts: RenderSummaryOpts = {},
): string[] {
  const style = opts.style ?? NO_STYLE;
  const ascii = opts.ascii === true;
  const width = Math.max(40, Math.min(opts.width ?? 80, 80));
  const out: string[] = [];

  const from = sanitiseDisplayField(input.fromVersion);
  const to = sanitiseDisplayField(input.toVersion);
  let title = summary.title;
  const moved = input.packageState === 'updated' && from && to && from !== to;
  if (summary.headline === 'updated') {
    if (moved) title += '   ' + from + ' \u2192 ' + to;
    else if (to && input.packageState !== 'unknown') title += '   ' + to;
  } else if (summary.headline === 'check' && moved) {
    // "ShieldCortex updated to 5.9.0 — 1 thing to check"
    title = title.replace('ShieldCortex updated', 'ShieldCortex updated to ' + to);
  }
  const hColor = summary.headline === 'updated' ? style.green : summary.headline === 'check' ? style.yellow : style.red;
  const t = asciiText(sanitiseDisplayField(title), ascii);
  const titleLines = t.length <= width ? [t] : wrapText(t, width, 0, 2);
  for (const l of titleLines) out.push(hColor + style.bold + l + style.reset);
  out.push('');

  for (const row of summary.rows) {
    const mark = markText(row.mark, ascii);
    const lead = '  ' + mark + ' ';
    const hang = lead.length + LABEL_COL;
    const label = sanitiseDisplayField(row.label).padEnd(LABEL_COL - 1) + ' ';
    const first = wrapText(asciiText(sanitiseDisplayField(row.text), ascii), width, hang, hang);
    const painted = markColor(row.mark, style) + mark + style.reset;
    out.push('  ' + painted + ' ' + label + first[0].slice(hang));
    for (const l of first.slice(1)) out.push(l);
    if (row.why) {
      for (const l of wrapText(asciiText(sanitiseDisplayField(row.why), ascii), width, hang, hang)) out.push(style.dim + l + style.reset);
    }
    if (row.command) {
      const line = sanitiseDisplayField(row.commandLabel ?? 'Fix') + ': ' + sanitiseDisplayField(row.command);
      for (const l of wrapText(asciiText(line, ascii), width, hang, hang + 2)) out.push(l);
      if (row.commandNote) {
        const safeNote = sanitiseDisplayField(row.commandNote);
        const note = safeNote.charAt(0).toUpperCase() + safeNote.slice(1) + '.';
        for (const l of wrapText(asciiText(note, ascii), width, hang, hang)) out.push(style.dim + l + style.reset);
      }
    }
  }
  return out;
}

/**
 * True when an update from `fromVersion` crosses the release where Action
 * Guard became off by default. Same idea as the 4.11 notice: print a migration
 * note once, on the upgrade that crosses it, never on every update after.
 */
export function crossesGuardDefaultOff(fromVersion: string, compare: (a: string, b: string) => number): boolean {
  if (!/^\d+\.\d+\.\d+/.test(String(fromVersion ?? ''))) return false;
  return compare(fromVersion, GUARD_DEFAULT_OFF_SINCE) < 0;
}

/** The Guard migration notice, plain words, real commands. */
export function renderGuardDefaultOffNotice(opts: { style?: TermStyle; ascii?: boolean } = {}): string[] {
  const style = opts.style ?? NO_STYLE;
  const mark = opts.ascii ? '[off]' : '\u25cb';
  return [
    '  ' + style.dim + mark + style.reset + '  ' + style.bold + 'Action Guard is off by default since ' + GUARD_DEFAULT_OFF_SINCE + '.' + style.reset,
    '     Turn on: ' + style.cyan + GUARD_ON_COMMAND + style.reset,
    '     Status:  ' + style.cyan + GUARD_STATUS_COMMAND + style.reset,
  ];
}

