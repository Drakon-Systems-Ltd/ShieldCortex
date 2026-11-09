/**
 * Plain-English, one-screen default doctor report (#1014).
 *
 * Display layer only. It reads the same rows the exit code and `--json` are
 * computed from and changes none of them: no status, count or fix is altered
 * here. `--verbose` keeps the full report in doctor-report.ts; this module is
 * what `shieldcortex doctor` prints with no flags, plus `--explain <ID>`.
 *
 * Three tiers (#1014 AC1): FAIL rows and warnings with something to do go under
 * TO FIX, each with one plain line on what is wrong, one on why it matters when
 * that is not obvious, and a copy-paste command (or the row's own guidance when
 * no safe command exists). Warnings whose own guidance says not to act move to
 * a one-line EXPECTED section and are never mixed with actionable items.
 *
 * Symbols and colour appear only when the caller passes `symbols`/a styled
 * palette, which doctor.ts does on a TTY with NO_COLOR unset; otherwise the
 * output is plain ASCII.
 */

import {
  cleanWhy,
  extractFixCommands,
  groupItems,
  honestyGuidance,
  isHonestyForbiddenCommand,
  type DoctorReportItem,
  type DoctorReportStyle,
  type DoctorStatus,
  type ThemeGroup,
} from './doctor-report.js';
import {
  guardHeadlineFromPlanes,
  rowGatePosture,
  HOST_TABLE_GATE_LEGEND,
  type GuardHeadline,
  type HostGatePlanes,
  type HostRow,
  type HostTable,
} from '../setup/host-table.js';

/** The default report never wraps wider than this, whatever the terminal is. */
export const MAX_SUMMARY_WIDTH = 100;

export interface DoctorSummaryOpts {
  /** Already clamped by the caller; capped again at MAX_SUMMARY_WIDTH here. */
  width: number;
  version?: string;
  target?: string;
  /** Palette; pass an all-empty palette for plain text. */
  style: DoctorReportStyle;
  /** Unicode symbols (TTY). False = plain ASCII, for pipes and NO_COLOR. */
  symbols: boolean;
  /** Same host table setup/update/uninstall print; drives AGENTS ON THIS HOST. */
  hostTable?: HostTable;
  /** Live Action Guard planes for the header's Guard word and the gate words. */
  gatePlanes?: HostGatePlanes;
}

interface Glyphs {
  ok: string;
  bad: string;
  tick: string;
  cross: string;
  dash: string;
  sep: string;
  bullet: string;
}

const UNICODE: Glyphs = { ok: '✅', bad: '❌', tick: '✔', cross: '✘', dash: '—', sep: ' · ', bullet: '·' };
const ASCII: Glyphs = { ok: '[OK]', bad: '[FAIL]', tick: '[ok]', cross: '[!!]', dash: '[--]', sep: ' | ', bullet: '-' };

const STATUS_WORD: Record<DoctorStatus, string> = { fail: 'FAIL', warn: 'WARN', info: 'INFO', pass: 'PASS' };

const RUNNABLE = /^(?:[\w.-]+\s+)?(?:shieldcortex|openclaw|claude|npm|node|systemctl|launchctl|chown|chmod)\b/i;

/** The full report's fallback guidance for a warning with no safe command. */
const SHRUG = 'No action needed. This is attention';

/**
 * Soft-wrap at spaces with a hanging indent. Unlike the full report's wrapper
 * a token longer than the width is kept whole, so a path or URL in a fix
 * stays copy-pasteable; the line is then longer than the width.
 */
export function wrapSoft(text: string, width: number, indent = 0, hang = 0): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  if (words.length === 0) return [' '.repeat(indent)];
  const lines: string[] = [];
  let cur = '';
  for (const w of words) {
    if (!cur) {
      cur = w;
      continue;
    }
    const pad = lines.length === 0 ? indent : hang;
    if (pad + cur.length + 1 + w.length <= width) {
      cur = `${cur} ${w}`;
    } else {
      lines.push(`${' '.repeat(pad)}${cur}`);
      cur = w;
    }
  }
  lines.push(`${' '.repeat(lines.length === 0 ? indent : hang)}${cur}`);
  return lines;
}

/**
 * Stable, readable id for a check row: its label lower-cased with every run
 * of non-alphanumerics folded to one dash. Never truncated. This is the `<ID>`
 * that `shieldcortex doctor --explain <ID>` takes.
 */
export function doctorRowId(label: string): string {
  return label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'check';
}

export type WarnTier = 'fix' | 'expected';

/**
 * Guidance wording that means "nothing to do here": the honesty / by-design
 * warnings doctor prints so a configured-off feature is never mistaken for a
 * missing one. Matched on the guidance the full report would print, so the
 * two layouts agree on which warnings are actionable.
 */
const EXPECTED_GUIDANCE =
  /^(?:Native memory is still the brain|Cannot read OpenClaw's plugin roster|Guard is off or the plugin is off)|\b(?:do not|don't) (?:run|enable|add|grant|uninstall|restart|install)\b|that is (?:a valid choice|the default)|not unprotected|optional while guard is off|^nothing to do\b/i;

/** Which tier a warning group belongs to. FAIL rows are always TO FIX. */
export function warnTier(g: ThemeGroup): WarnTier {
  if (g.status !== 'warn') return 'fix';
  // #878: an unknown signed posture is a problem to resolve, never "expected".
  if (g.postureUnknown) return 'fix';
  // An enforcing guard with nobody to tell is actionable even though its
  // command is withheld from warnings (#815 A).
  if (/^Action Guard is enforcing/i.test(g.why)) return 'fix';
  if (g.fixCommands.some((c) => !isHonestyForbiddenCommand(c))) return 'fix';
  const guidance = honestyGuidance(g);
  if (guidance === '') return 'expected'; // conversation scanning off
  if (guidance.startsWith(SHRUG)) {
    // No safe command and no guidance of its own. For a Guard row that is a
    // configured posture (its only remedy would turn the guard on, which a
    // warning never prescribes); for any other row it is something the
    // operator has to look at, so it stays under TO FIX with its message.
    return g.theme === 'GUARD' || g.theme === 'NOTIFY' || /action guard/i.test(g.labels.join(' '))
      ? 'expected'
      : 'fix';
  }
  return EXPECTED_GUIDANCE.test(guidance) ? 'expected' : 'fix';
}

/** One short phrase for the EXPECTED line. */
export function expectedPhrase(g: ThemeGroup): string {
  const label = g.labels.join(' ').toLowerCase();
  const blob = `${g.what} ${g.why} ${g.fixNote}`.toLowerCase();
  if (g.theme === 'SCAN' || /conversation scanning/.test(blob)) return 'Conversation scanning off';
  if (/policy lock/.test(label)) return 'Policy lock not set';
  if (/notify/.test(label)) return 'Guard notifications not set';
  if (/action guard/.test(label)) {
    // Label first: the posture row's own fix mentions webhooks too.
    if (/^off\b/.test(g.why.toLowerCase()) || /action guard is off|guard is off/.test(blob)) return 'Action Guard off';
    if (/advisory|warn-mode|watch only/.test(blob)) return 'Action Guard in watch only';
    return 'Action Guard off';
  }
  if (/webhook/.test(blob)) return 'Guard notifications not set';
  if (/import-native|dual.plane|dual_legacy|native agent sot|native memory bus/.test(blob)) {
    return 'Native agent memory stays primary';
  }
  if (/index unreadable|plugin roster|cannot read openclaw/.test(blob)) return 'OpenClaw plugin roster not readable';
  return g.what;
}

/**
 * Drop the internal detail a check message carries for `--verbose`: source
 * references, SQL, issue numbers and dotted config keys inside parentheses,
 * and sentences that exist only to cite an issue. Never ellipsizes.
 */
export function scrubInternal(text: string): string {
  let s = cleanWhy(text);
  s = s.replace(/\s*\((?:[^()]*(?:\.ts\b|\bWHERE\b|#\d+|\b[a-zA-Z_-]+\.[a-zA-Z_-]+\.[a-zA-Z_.-]+)[^()]*)\)/g, '');
  const sentences = s.split(/(?<=\.)\s+/);
  if (sentences.length > 1) s = sentences.filter((sent) => !/#\d+/.test(sent)).join(' ');
  s = s.replace(/\s*\(#\d+\)/g, '').replace(/\s#\d+\b/g, '');
  s = s.replace(/\s+/g, ' ').replace(/\s+([.,;])/g, '$1').trim();
  return s || cleanWhy(text);
}

function scrubIssueRefs(text: string): string {
  return cleanWhy(text).replace(/\s*\(#\d+\)/g, '').replace(/\s#\d+\b/g, '').replace(/\s+/g, ' ').trim();
}

export interface PlainItem {
  what: string;
  why?: string;
}

/**
 * Plain-English "what is wrong" for a TO FIX group, with a "why it matters"
 * line where the label alone does not say. Known checks get a rewritten
 * sentence; any other row keeps its full label as the title and its message,
 * scrubbed of internal detail, as the why line.
 */
export function plainEnglish(g: ThemeGroup): PlainItem {
  const label = g.labels[0] ?? g.what;
  const msg = g.why;
  const is = (re: RegExp) => re.test(label);
  const m = (re: RegExp) => re.exec(msg);

  if (is(/^Semantic coverage$/i)) {
    const x = m(/(\d+) \((\d+)%\) have no vector/);
    if (x) {
      return {
        what: `${x[1]} memories can't be found by meaning search (${x[2]}%)`,
        why: 'they are saved, but a search by meaning will not return them',
      };
    }
  }
  if (is(/^Auto-memory: SessionEnd hook$/i) && /not wired/i.test(msg)) {
    return {
      what: 'Session-end memory capture is switched on but not connected',
      why: 'nothing is saved when a session ends until the hook is wired',
    };
  }
  if (is(/^Auto-memory: Stop hook$/i) && /not wired/i.test(msg)) {
    return {
      what: 'Turn-end memory capture is switched on but not connected',
      why: 'nothing is saved at the end of a turn until the hook is wired',
    };
  }
  if (is(/^Project keys$/i)) {
    const x = m(/(\d+) legacy\/canonical collision/);
    if (x) {
      const one = x[1] === '1';
      return {
        what: `${x[1]} project name${one ? '' : 's'} point${one ? 's' : ''} at the same memories as another`,
        why: 'recall can miss memories filed under the older name',
      };
    }
  }
  if (g.status === 'fail') {
    if (is(/^Node runtime$/i)) return { what: 'This Node.js version is not supported', why: scrubInternal(msg) };
    if (is(/^Database engine$/i)) {
      return { what: 'The database engine does not load on this Node.js version', why: scrubInternal(msg) };
    }
    if (is(/^Database$/i)) return { what: 'The memory database cannot be opened', why: scrubInternal(msg) };
    if (is(/^Schema$/i)) return { what: 'The memory database schema is out of date', why: scrubInternal(msg) };
    if (is(/^Write path$/i)) return { what: 'The memory database refused a test write', why: scrubInternal(msg) };
    if (is(/^Hooks$/i)) return { what: 'Some Claude Code hooks are missing or broken', why: scrubInternal(msg) };
    if (is(/^Disk$/i)) return { what: 'ShieldCortex is using more disk than its limit', why: scrubInternal(msg) };
    if (is(/^Action guard posture$/i)) {
      return { what: 'Action Guard is set differently on different agents', why: scrubInternal(msg) };
    }
    if (is(/^Action guard policy lock$/i)) {
      return {
        what: 'Action Guard is on, but any process running as you could switch it off',
        why: scrubInternal(msg),
      };
    }
    if (is(/^Chained ledger$/i)) return { what: 'The audit ledger has been edited or has gaps', why: scrubInternal(msg) };
  }
  if (is(/^Action guard notify$/i) && /^Action Guard is enforcing/i.test(msg)) {
    return { what: 'Nobody is told when Action Guard blocks something unattended', why: scrubInternal(msg) };
  }
  if (is(/^Stale ShieldCortex copies$/i)) {
    return { what: 'An older ShieldCortex copy could share your database', why: scrubInternal(msg) };
  }
  if (is(/^Recall repetition$/i)) {
    return { what: 'Recent recalls all returned the same memories', why: scrubInternal(msg) };
  }
  if (is(/^(?:OpenClaw plugin version|Hermes plugin|OpenClaw hook|OpenClaw skill version)$/i)
    && /behind|outdated|older|stale|out of date/i.test(msg)) {
    return { what: `${label} is behind this ShieldCortex version`, why: scrubInternal(msg) };
  }
  return { what: label, why: scrubInternal(msg) };
}

function guardWord(h: GuardHeadline): string {
  switch (h) {
    case 'on': return 'on';
    case 'advisory': return 'watch only';
    case 'mixed': return 'mixed (see TO FIX)';
    case 'unknown': return 'unknown';
    case 'off': return 'off (your choice)';
  }
}

function statusColour(status: DoctorStatus, s: DoctorReportStyle): string {
  switch (status) {
    case 'fail': return s.red;
    case 'warn': return s.yellow;
    case 'info': return s.cyan;
    case 'pass': return s.green;
  }
}

function unique(xs: string[]): string[] {
  const out: string[] = [];
  for (const x of xs) if (!out.includes(x)) out.push(x);
  return out;
}

function renderFixItem(g: ThemeGroup, n: number, width: number, s: DoctorReportStyle): string[] {
  const dim = (l: string) => `${s.dim}${l}${s.reset}`;
  const out: string[] = [];
  const { what, why } = plainEnglish(g);
  const id = doctorRowId(g.labels[0] ?? g.what);
  const num = `${String(n).padStart(2)}.`;
  const title = wrapSoft(what, width, 4, 4);
  title[0] = `${statusColour(g.status, s)}${num}${s.reset} ${s.bold}${title[0].slice(4)}${s.reset}`;
  const plainLast = wrapSoft(what, width, 4, 4).at(-1) ?? '';
  const idTag = `[${id}]`;
  if (plainLast.length + 2 + idTag.length <= width) {
    title[title.length - 1] = `${title[title.length - 1]}  ${dim(idTag)}`;
  } else {
    title.push(dim(`    ${idTag}`));
  }
  out.push(...title);
  if (why && why !== what) out.push(...wrapSoft(why, width, 4, 4).map(dim));

  const cmds = g.status === 'warn' ? g.fixCommands.filter((c) => !isHonestyForbiddenCommand(c)) : g.fixCommands;
  if (cmds.length > 0) {
    if (g.fixNoteWithCommands && g.fixNote) {
      out.push(...wrapSoft(scrubIssueRefs(g.fixNote), width, 4, 4).map(dim));
    }
    for (const cmd of cmds) {
      const runnable = RUNNABLE.test(cmd) || cmd.startsWith('SHIELDCORTEX_');
      const text = runnable ? `$ ${cmd}` : cmd;
      out.push(...wrapSoft(text, width, 4, 6).map((l) => (runnable ? `${s.bold}${l}${s.reset}` : dim(l))));
    }
  } else {
    // An enforcing guard with nobody to tell: the row's own fix is the
    // guidance (as prose; a warning never prints a guard-changing `$` line).
    // The full report's text match would read this row as "Guard is off".
    const enforcingNotify = g.status === 'warn' && /^Action Guard is enforcing/i.test(g.why) && g.fixNote;
    const guidance = enforcingNotify
      ? cleanWhy(g.fixNote)
      : g.status === 'warn'
        ? honestyGuidance(g)
        : (g.fixNote ? cleanWhy(g.fixNote) : '');
    if (guidance && !guidance.startsWith(SHRUG)) {
      // Some checks (Node runtime) end their message with the remedy so the
      // full report shows it; here the why line already said it, so say it once.
      const text = scrubIssueRefs(guidance);
      if (!(why ?? '').includes(text.replace(/\.$/, ''))) out.push(...wrapSoft(text, width, 4, 4).map(dim));
    }
  }
  return out;
}

interface SessionCount {
  live: number;
  ended: number;
  more: boolean;
}

const RUNTIME_POSTURE_PREFIX = 'Runtime posture: ';

/** Per-agent session counts from the info-only runtime posture rows (#613). */
export function sessionCounts(results: readonly DoctorReportItem[]): Map<string, SessionCount> {
  const out = new Map<string, SessionCount>();
  for (const r of results) {
    if (!r.label.startsWith(RUNTIME_POSTURE_PREFIX)) continue;
    const host = r.label.slice(RUNTIME_POSTURE_PREFIX.length).split(' (')[0]?.trim();
    if (!host) continue;
    const state = /\((current|ended)\)/.exec(r.message)?.[1];
    if (!state) continue;
    const c = out.get(host) ?? { live: 0, ended: 0, more: false };
    if (state === 'current') c.live += 1; else c.ended += 1;
    if (/further instance report/.test(r.message)) c.more = true;
    out.set(host, c);
  }
  return out;
}

function sessionText(c: SessionCount): string {
  const plus = c.more ? '+' : '';
  if (c.live > 0 && c.ended > 0) return `${c.live} live, ${c.ended}${plus} ended`;
  if (c.live > 0) return `${c.live}${plus} session${c.live === 1 && !c.more ? '' : 's'}`;
  return `${c.ended}${plus} ended`;
}

/** Hermes reads no shared setting; its gate word comes from its own current self-report. */
function hermesSelfReportedGate(results: readonly DoctorReportItem[]): string | undefined {
  for (const r of results) {
    if (!r.label.startsWith(`${RUNTIME_POSTURE_PREFIX}Hermes (`)) continue;
    if (!/\(current\)/.test(r.message)) continue;
    const p = /posture (advisory|enforce|off)/.exec(r.message)?.[1];
    if (p === 'advisory') return 'advisory';
    if (p === 'enforce') return 'enforcing';
    if (p === 'off') return 'gate off';
  }
  return undefined;
}

function gateWord(r: HostRow, planes: HostGatePlanes | undefined, results: readonly DoctorReportItem[]): string | undefined {
  if (r.kind !== 'bound') return undefined;
  if (r.id === 'hermes') return hermesSelfReportedGate(results);
  const p = rowGatePosture(r, planes);
  if (p === undefined) return undefined;
  if (p === 'off') return 'gate off';
  if (p === 'unknown') return 'gate unknown';
  if (p === 'observe-only') return 'observe only';
  return p;
}

function renderAgents(
  table: HostTable,
  planes: HostGatePlanes | undefined,
  results: readonly DoctorReportItem[],
  s: DoctorReportStyle,
  g: Glyphs,
): string[] {
  const sessions = sessionCounts(results);
  const labelW = Math.max(10, ...table.rows.map((r) => r.label.length));
  return table.rows.map((r) => {
    const name = r.label.padEnd(labelW);
    if (!r.present) return ` ${name}  ${s.dim}${g.dash} not installed${s.reset}`;
    if (!r.wired) {
      return ` ${name}  ${s.yellow}${g.cross} not connected${s.reset}${g.sep}run: ${r.wireCommand}`;
    }
    const parts = [
      `${s.green}${g.tick} connected${s.reset}`,
      r.kind === 'bound' ? 'memory + tool gate' : 'memory only',
    ];
    const gate = gateWord(r, planes, results);
    if (gate) parts.push(gate);
    let line = ` ${name}  ${parts.join(g.sep)}`;
    const sc = sessions.get(r.label);
    if (sc) line += `   ${s.dim}(${sessionText(sc)})${s.reset}`;
    return line;
  });
}

/**
 * The default `shieldcortex doctor` report: header and verdict, TO FIX,
 * EXPECTED ON THIS HOST, AGENTS ON THIS HOST, and a footer that points at
 * `--verbose` and `--explain <ID>`. Info rows are counted, not listed.
 */
export function formatDoctorSummary(results: DoctorReportItem[], o: DoctorSummaryOpts): string[] {
  const width = Math.min(o.width, MAX_SUMMARY_WIDTH);
  const s = o.style;
  const g = o.symbols ? UNICODE : ASCII;
  const dim = (l: string) => `${s.dim}${l}${s.reset}`;

  const fails = results.filter((r) => r.status === 'fail');
  const warns = results.filter((r) => r.status === 'warn');
  const infos = results.filter((r) => r.status === 'info');
  const passes = results.filter((r) => r.status === 'pass');

  const warnGroups = groupItems(warns, true);
  const fixGroups = [...groupItems(fails, true), ...warnGroups.filter((w) => warnTier(w) === 'fix')];
  const expectedGroups = warnGroups.filter((w) => warnTier(w) === 'expected');

  const lines: string[] = [];
  const head = ['ShieldCortex Doctor', o.version?.trim() ? `v${o.version.trim()}` : '', o.target?.trim() ?? '']
    .filter(Boolean)
    .join(g.sep);
  lines.push(`${s.bold}${head}${s.reset}`);

  const verdict = fails.length > 0
    ? `${s.red}${g.bad} ${fails.length} failed check${fails.length === 1 ? '' : 's'}${s.reset}`
    : `${s.green}${g.ok} Healthy${s.reset}`;
  const toFix = fixGroups.length === 0
    ? 'nothing to fix'
    : `${fixGroups.length} thing${fixGroups.length === 1 ? '' : 's'} to fix`;
  const guard = o.gatePlanes ? `Guard: ${guardWord(guardHeadlineFromPlanes(o.gatePlanes))}` : '';
  lines.push([verdict, toFix, guard].filter(Boolean).join(g.sep));
  // A fresh install has no database yet. #129 made that an info row so a new
  // user's first doctor run is not a failure; it is still the one info row
  // they need to see without --verbose, in the row's own plain words.
  const freshDb = infos.find((r) => r.label === 'Database' && /not initialised/i.test(r.message));
  if (freshDb) lines.push(...wrapSoft(`Memory database: ${cleanWhy(freshDb.message)}`, width, 0, 2).map(dim));
  lines.push('');

  if (fixGroups.length > 0) {
    lines.push(`${s.bold}TO FIX${s.reset}`);
    fixGroups.forEach((grp, i) => lines.push(...renderFixItem(grp, i + 1, width, s)));
    lines.push('');
  }

  if (expectedGroups.length > 0) {
    lines.push(`${s.bold}EXPECTED ON THIS HOST${s.reset} ${dim('(no action)')}`);
    const phrases = unique(expectedGroups.map(expectedPhrase));
    lines.push(...wrapSoft(`${g.bullet} ${phrases.join(g.sep)}`, width, 1, 3));
    lines.push('');
  }

  if (o.hostTable && o.hostTable.rows.length > 0) {
    lines.push(`${s.bold}AGENTS ON THIS HOST${s.reset}`);
    lines.push(...renderAgents(o.hostTable, o.gatePlanes, results, s, g));
    lines.push('');
  }

  const counts = [
    `${passes.length} check${passes.length === 1 ? '' : 's'} passed`,
    infos.length > 0 ? `${infos.length} informational row${infos.length === 1 ? '' : 's'} hidden` : '',
  ].filter(Boolean).join(g.sep);
  lines.push(...wrapSoft(counts, width, 0, 2).map(dim));
  const details = 'details: shieldcortex doctor --verbose';
  const explain = 'explain one: shieldcortex doctor --explain <ID>';
  const footer = `${details}${g.sep}${explain}`;
  // Keep each command whole: two lines rather than a wrapped command.
  if (footer.length <= width) lines.push(dim(footer));
  else lines.push(dim(details), dim(explain));
  return lines;
}

/** Warn rows the default report lists under EXPECTED, as rows. */
function expectedRows(results: readonly DoctorReportItem[]): DoctorReportItem[] {
  const warns = results.filter((r) => r.status === 'warn');
  const labels = new Set(groupItems(warns, true).filter((w) => warnTier(w) === 'expected').flatMap((w) => w.labels));
  return warns.filter((r) => labels.has(r.label));
}

function explainRow(r: DoctorReportItem, width: number, s: DoctorReportStyle): string[] {
  const dim = (l: string) => `${s.dim}${l}${s.reset}`;
  const out = [
    `${statusColour(r.status, s)}${STATUS_WORD[r.status]}${s.reset}  ${s.bold}${r.label}${s.reset}  ${dim(`[${doctorRowId(r.label)}]`)}`,
    ...wrapSoft(cleanWhy(r.message), width, 4, 4),
  ];
  if (r.fix) {
    out.push(dim('    Fix:'));
    out.push(...wrapSoft(cleanWhy(r.fix), width, 6, 6));
    const cmds = r.status === 'warn'
      ? extractFixCommands(r.fix).filter((c) => !isHonestyForbiddenCommand(c))
      : extractFixCommands(r.fix);
    for (const cmd of cmds) out.push(...wrapSoft(`$ ${cmd}`, width, 6, 8).map((l) => `${s.bold}${l}${s.reset}`));
  }
  if (r.verboseNote) {
    out.push(dim('    Note:'));
    out.push(...wrapSoft(cleanWhy(r.verboseNote), width, 6, 6));
  }
  return out;
}

export interface DoctorExplainOpts {
  width: number;
  style: DoctorReportStyle;
}

/**
 * `shieldcortex doctor --explain [<ID>]`. With no id: every check's id and
 * status, then the HOSTS legend. With `expected`: every warning the default
 * report filed under EXPECTED, in full. With a row id: that row in full
 * (message, fix, verbose note), plus the legend for Guard and posture rows.
 */
export function formatDoctorExplain(results: DoctorReportItem[], id: string | null, o: DoctorExplainOpts): string[] {
  const width = Math.min(o.width, MAX_SUMMARY_WIDTH);
  const s = o.style;
  const dim = (l: string) => `${s.dim}${l}${s.reset}`;
  const lines: string[] = [];

  if (id === null || id.trim() === '') {
    lines.push(`${s.bold}CHECK IDS${s.reset}`);
    lines.push(dim("shieldcortex doctor --explain <ID> prints one check in full; 'expected' prints every no-action warning."));
    for (const r of results) {
      lines.push(`  ${statusColour(r.status, s)}${STATUS_WORD[r.status]}${s.reset}  ${doctorRowId(r.label)}`);
    }
    lines.push('');
    lines.push(`${s.bold}LEGEND${s.reset}`);
    lines.push(...HOST_TABLE_GATE_LEGEND);
    return lines;
  }

  const key = id.trim().toLowerCase();
  const matches = key === 'expected'
    ? expectedRows(results)
    : results.filter((r) => doctorRowId(r.label) === key);
  if (matches.length === 0) {
    lines.push(`No check with id "${id.trim()}". Run shieldcortex doctor --explain to list the ids.`);
    return lines;
  }
  for (const r of matches) {
    lines.push(...explainRow(r, width, s));
    lines.push('');
  }
  if (matches.some((r) => /guard|posture/i.test(r.label))) {
    lines.push(`${s.bold}LEGEND${s.reset}`);
    lines.push(...HOST_TABLE_GATE_LEGEND);
  }
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines;
}
