/**
 * Mobile/tmux-friendly doctor report renderer.
 *
 * Pure display layer only — does not change check logic, exit codes, or
 * severity. Default output collapses passes and duplicate warning themes so a
 * 40-col phone SSH pane shows what matters first. Fail/warn text is never
 * truncated mid-sentence via ellipsis — it wraps in full at any width.
 */

export type DoctorStatus = 'pass' | 'warn' | 'fail' | 'info';

/** Minimal input shape — matches CheckResult fields the renderer needs. */
export interface DoctorReportItem {
  label: string;
  status: DoctorStatus;
  message: string;
  fix?: string;
}

export interface FormatDoctorReportOpts {
  /** Show every pass line and do not collapse themes. */
  verbose?: boolean;
  /** Hard line budget. Default 80. Use 40 for phone landscape. */
  width?: number;
  /** Package version string, e.g. 4.54.2 */
  version?: string;
  /** Optional host/target label (hostname). */
  target?: string;
  /** Colourise when true (TTY). Tests leave false. */
  color?: boolean;
  /**
   * ANSI helpers. Injected so tests can assert plain text without importing
   * doctor.ts colour constants.
   */
  style?: DoctorReportStyle;
}

export interface DoctorReportStyle {
  bold: string;
  reset: string;
  green: string;
  yellow: string;
  red: string;
  cyan: string;
  dim: string;
}

const NO_STYLE: DoctorReportStyle = {
  bold: '',
  reset: '',
  green: '',
  yellow: '',
  red: '',
  cyan: '',
  dim: '',
};

const STATUS_MARK: Record<DoctorStatus, string> = {
  fail: '[x]',
  warn: '[!]',
  info: '[i]',
  pass: '[ok]',
};

const STATUS_ORDER: Record<DoctorStatus, number> = {
  fail: 0,
  warn: 1,
  info: 2,
  pass: 3,
};

/** Theme codes kept short for 40-col panes. */
export function themeForLabel(label: string): string {
  const l = label.toLowerCase();
  if (l.includes('project key')) return 'KEY';
  if (l.includes('conversation')) return 'SCAN';
  if (l.includes('plugin loaded') && l.includes('openclaw')) return 'LOAD';
  if (l.includes('action guard') && l.includes('config')) return 'GUARD';
  if (l.includes('action guard') && l.includes('notify')) return 'NOTIFY';
  if (l.includes('action guard')) return 'GUARD';
  if (l.includes('attestation')) return 'ATTEST';
  if (l.includes('threat graph')) return 'GRAPH';
  if (l.includes('database') || l === 'schema' || l.includes('write path')) return 'DB';
  if (l.includes('hook')) return 'HOOK';
  if (l.includes('openclaw config')) return 'OC-CFG';
  if (l.includes('openclaw residue')) return 'OC-RES';
  if (l.includes('plugin version') || l.includes('running version')) return 'PLUGIN';
  if (l.includes('skill')) return 'SKILL';
  if (l.includes('disk')) return 'DISK';
  if (l.includes('lock')) return 'LOCK';
  if (l.includes('dashboard')) return 'UI';
  if (l.includes('api server')) return 'API';
  if (l.includes('brain')) return 'BRAIN';
  if (l.includes('defence') || l.includes('defense') || l.includes('canary')) return 'DEF';
  if (l.includes('claude')) return 'CLAUDE';
  if (l.includes('embedding') || l.includes('model')) return 'MODEL';
  if (l.includes('permission') || l.includes('state permission')) return 'PERM';
  if (l.includes('approval')) return 'APPROVE';
  if (l.includes('memory')) return 'MEM';
  // fallback: first word upper, max 6
  const word = label.replace(/[^A-Za-z0-9]+/g, ' ').trim().split(/\s+/)[0] || 'CHK';
  return word.slice(0, 6).toUpperCase();
}

/**
 * Collapse key for duplicate themes. Conversation scanning often emits two
 * checks that are one operator decision — collapse them.
 */
export function collapseKey(item: DoctorReportItem): string {
  const theme = themeForLabel(item.label);
  // Same posture decision, two check sites.
  if (theme === 'SCAN' || /conversation scanning/i.test(item.label) || /conversation scanning/i.test(item.message)) {
    return `${item.status}:SCAN`;
  }
  if (theme === 'LOAD' && /conversation/i.test(item.message)) {
    return `${item.status}:SCAN`;
  }
  // Same fix text = same root cause.
  if (item.fix) return `${item.status}:fix:${normaliseFixKey(item.fix)}`;
  return `${item.status}:${theme}:${item.label}`;
}

function normaliseFixKey(fix: string): string {
  return fix
    .toLowerCase()
    .replace(/[`'"]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 160);
}

/** Pull copy-pasteable commands out of a free-form fix string. */
export function extractFixCommands(fix: string | undefined): string[] {
  if (!fix) return [];
  const cmds: string[] = [];
  const re = /`([^`]+)`/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(fix)) !== null) {
    const c = m[1].trim();
    if (!c) continue;
    // Prefer real shell-ish snippets
    if (
      /^(?:[\w.-]+\s+)?(?:shieldcortex|openclaw|claude|npm|node|systemctl|launchctl|chown|chmod)\b/i.test(c) ||
      c.startsWith('SHIELDCORTEX_')
    ) {
      cmds.push(c);
    }
  }
  if (cmds.length > 0) return unique(cmds);

  // Bare shieldcortex/openclaw multi-word commands without backticks.
  // Stop before English glue words so we don't swallow the rest of the sentence.
  const bareRe = /\b((?:shieldcortex|openclaw)(?:\s+(?:--?[\w-]+(?:=[\w./:@+=,-]+)?|[\w./:@+=,-]+))+)/g;
  const stop = new Set([
    'to', 'and', 'or', 'then', 'so', 'for', 'while', 'the', 'a', 'an', 'on', 'in',
    'with', 'from', 'after', 'before', 'because', 'if', 'when', 'this', 'that',
    'auto-repair', 'migrate', 'please',
  ]);
  let bm: RegExpExecArray | null;
  while ((bm = bareRe.exec(fix)) !== null) {
    const parts = bm[1].trim().split(/\s+/);
    const kept: string[] = [parts[0]];
    for (let i = 1; i < parts.length; i++) {
      const p = parts[i].replace(/[.,;:]+$/, '');
      if (stop.has(p.toLowerCase())) break;
      if (/^\(/.test(p)) break;
      kept.push(p);
    }
    const c = kept.join(' ').replace(/[.,;:]+$/, '').trim();
    if (c.split(/\s+/).length >= 2 && !cmds.includes(c)) cmds.push(c);
  }
  if (cmds.length > 0) return unique(cmds);

  // Config / restart guidance. Only emit a real binary — never English
  // that a phone user will copy after `$`.
  // Conversation access: config grant FIRST, then restart. Restart alone
  // never sticks (Edith 2026-08-18 — operators kept restarting, warn remained).
  if (/allowConversationAccess/i.test(fix)) {
    return [
      'shieldcortex openclaw install --allow-conversation-access',
      'openclaw gateway restart',
    ];
  }
  if (/restart.{0,40}gateway/i.test(fix) || /restart long-running/i.test(fix)) {
    return ['openclaw gateway restart'];
  }

  return [];
}

function unique(xs: string[]): string[] {
  const out: string[] = [];
  for (const x of xs) if (!out.includes(x)) out.push(x);
  return out;
}

/** Collapse whitespace and strip backticks — never ellipsizes. */
export function cleanWhy(message: string): string {
  return message
    .replace(/\s+/g, ' ')
    .replace(/`/g, '')
    .trim();
}

/** Compact one-liner — used only for the INFO compact path and pass lines. */
export function oneLineWhy(message: string, width: number): string {
  return ellipsize(cleanWhy(message), Math.max(12, width - 4));
}

export function ellipsize(s: string, max: number): string {
  if (s.length <= max) return s;
  if (max <= 1) return '…';
  return `${s.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** Soft-wrap at spaces; hanging indent on continuation. Never split mid-token if possible. */
export function wrapLine(text: string, width: number, indent = 0, hang = 0): string[] {
  const budget = Math.max(8, width - indent);
  const words = text.split(/\s+/).filter(Boolean);
  if (words.length === 0) return [' '.repeat(indent)];
  const lines: string[] = [];
  let cur = '';
  const push = () => {
    if (cur) lines.push(`${' '.repeat(lines.length === 0 ? indent : hang)}${cur}`);
    cur = '';
  };
  for (const w of words) {
    if (!cur) {
      if (w.length > budget) {
        // hard-split long tokens (URLs/paths) rather than overflow
        let rest = w;
        while (rest.length > budget) {
          lines.push(`${' '.repeat(lines.length === 0 ? indent : hang)}${rest.slice(0, budget)}`);
          rest = rest.slice(budget);
        }
        cur = rest;
      } else {
        cur = w;
      }
      continue;
    }
    if (`${cur} ${w}`.length <= budget) {
      cur = `${cur} ${w}`;
    } else {
      push();
      if (w.length > budget) {
        let rest = w;
        while (rest.length > budget) {
          lines.push(`${' '.repeat(hang)}${rest.slice(0, budget)}`);
          rest = rest.slice(budget);
        }
        cur = rest;
      } else {
        cur = w;
      }
    }
  }
  push();
  return lines.length ? lines : [' '.repeat(indent)];
}

interface ThemeGroup {
  status: DoctorStatus;
  theme: string;
  what: string;
  why: string;
  fixCommands: string[];
  count: number;
  labels: string[];
}

function groupItems(items: DoctorReportItem[], collapse: boolean): ThemeGroup[] {
  if (!collapse) {
    return items.map((it) => ({
      status: it.status,
      theme: themeForLabel(it.label),
      what: shortWhat(it),
      why: it.message.replace(/\s+/g, ' ').trim(),
      fixCommands: extractFixCommands(it.fix),
      count: 1,
      labels: [it.label],
    }));
  }

  const map = new Map<string, ThemeGroup>();
  const order: string[] = [];
  for (const it of items) {
    const key = collapseKey(it);
    const existing = map.get(key);
    if (!existing) {
      const g: ThemeGroup = {
        status: it.status,
        theme: themeForLabel(it.label),
        what: shortWhat(it),
        why: it.message.replace(/\s+/g, ' ').trim(),
        fixCommands: extractFixCommands(it.fix),
        count: 1,
        labels: [it.label],
      };
      // Prefer SCAN theme when collapsing conversation-related load warnings
      if (key.endsWith(':SCAN')) g.theme = 'SCAN';
      map.set(key, g);
      order.push(key);
    } else {
      existing.count += 1;
      if (!existing.labels.includes(it.label)) existing.labels.push(it.label);
      // Prefer a non-empty fix
      const cmds = extractFixCommands(it.fix);
      for (const c of cmds) if (!existing.fixCommands.includes(c)) existing.fixCommands.push(c);
      // Prefer the dedicated conversation-scanning label over plugin-loaded note
      if (/conversation scanning/i.test(it.label) && !/conversation scanning/i.test(existing.what)) {
        existing.what = shortWhat(it);
        existing.why = it.message.replace(/\s+/g, ' ').trim();
      } else if (it.message.length > existing.why.length && !/conversation scanning/i.test(existing.labels.join(' '))) {
        existing.why = it.message.replace(/\s+/g, ' ').trim();
        existing.what = shortWhat(it);
      }
    }
  }
  return order.map((k) => map.get(k)!);
}

function shortWhat(it: DoctorReportItem): string {
  // Label is the "what"; strip redundant prefixes
  return it.label.replace(/^Action guard\s+/i, 'Action Guard ').trim();
}

function statusColor(status: DoctorStatus, s: DoctorReportStyle): string {
  switch (status) {
    case 'fail': return s.red;
    case 'warn': return s.yellow;
    case 'info': return s.cyan;
    case 'pass': return s.green;
  }
}

function renderIssueBlock(g: ThemeGroup, width: number, style: DoctorReportStyle): string[] {
  const mark = STATUS_MARK[g.status];
  const col = statusColor(g.status, style);
  const xN = g.count > 1 ? `  x${g.count}` : '';
  const lines: string[] = [];
  // Title: wrap in full — never ellipsize fail/warn headings mid-label.
  const titlePlain = `${mark} ${g.theme.padEnd(6)} ${g.what}${xN}`;
  const titleWrapped = wrapLine(titlePlain, width, 0, 4);
  for (let i = 0; i < titleWrapped.length; i++) {
    const ln = titleWrapped[i]!;
    if (i === 0) {
      // Re-apply colour to mark only; body stays plain after theme.
      const rest = ln.replace(mark, '').replace(/^\s*/, '');
      lines.push(`${col}${mark}${style.reset} ${rest}`);
    } else {
      lines.push(ln);
    }
  }
  // Why: full text, wrapped. Ellipsis here is what made full-screen doctor look "cut off".
  const why = cleanWhy(g.why);
  lines.push(...wrapLine(why, width, 4, 4).map((l) => `${style.dim}${l}${style.reset}`));
  // Fix commands — all of them. `$` only on a real binary. English notes stay notes.
  if (g.fixCommands.length === 0) {
    lines.push(`${style.dim}    (no single copy-paste command)${style.reset}`);
  } else {
    for (const cmd of g.fixCommands) {
      const runnable = /^(?:[\w.-]+\s+)?(?:shieldcortex|openclaw|claude|npm|node|systemctl|launchctl|chown|chmod)\b/i.test(cmd)
        || cmd.startsWith('SHIELDCORTEX_');
      const prefixed = runnable ? `$ ${cmd}` : cmd;
      for (const wl of wrapLine(prefixed, width, 4, 6)) {
        lines.push(runnable ? `${style.bold}${wl}${style.reset}` : `${style.dim}${wl}${style.reset}`);
      }
    }
  }
  if (g.theme === 'SCAN') {
    // Prefer the install flag command (already in fixCommands). Footnote only
    // when the extractor failed to surface a conversation-access grant.
    const note = 'manual alt: set plugins.entries.shieldcortex-realtime.hooks.allowConversationAccess=true';
    if (!g.fixCommands.some((c) => /allow-conversation-access|allowConversationAccess/i.test(c))) {
      lines.push(...wrapLine(note, width, 4, 4).map((l) => `${style.dim}${l}${style.reset}`));
    }
  }
  return lines;
}

function renderPassLine(it: DoctorReportItem, width: number, style: DoctorReportStyle): string[] {
  const head = `${style.green}${STATUS_MARK.pass}${style.reset} ${themeForLabel(it.label).padEnd(6)} ${it.label}`;
  const msg = oneLineWhy(it.message, Math.max(12, width - 4));
  return [
    `${style.green}${STATUS_MARK.pass}${style.reset} ${themeForLabel(it.label).padEnd(6)} ${ellipsize(it.label, Math.max(8, width - 12))}`,
    ...wrapLine(msg, width, 4, 4).map((l) => `${style.dim}${l}${style.reset}`),
  ];
}

/**
 * Format a full doctor report as lines (no trailing newline on last join —
 * caller prints with console.log per line or join('\\n')).
 */
export function formatDoctorReport(
  results: DoctorReportItem[],
  opts: FormatDoctorReportOpts = {},
): string[] {
  const width = clampWidth(opts.width ?? detectWidth());
  const verbose = opts.verbose === true;
  const style = opts.color ? (opts.style ?? defaultColorStyle()) : (opts.style ?? NO_STYLE);
  const version = opts.version?.trim() || '';
  const target = opts.target?.trim() || '';

  const fails = results.filter((r) => r.status === 'fail');
  const warns = results.filter((r) => r.status === 'warn');
  const infos = results.filter((r) => r.status === 'info');
  const passes = results.filter((r) => r.status === 'pass');

  const failGroups = groupItems(fails, !verbose);
  const warnGroups = groupItems(warns, !verbose);
  const infoGroups = groupItems(infos, !verbose);

  // Sort groups: keep original relative order (stable from groupItems)
  const lines: string[] = [];

  // Header
  lines.push(`${style.bold}ShieldCortex Doctor${style.reset}${version ? `  v${version}` : ''}`);
  if (target) lines.push(`target  ${target}`);
  lines.push('');

  // Tally — use raw counts (operator expects Edith-style 5 warnings, not collapsed)
  const tally = [
    `${style.red}${fails.length} fail${style.reset}`,
    `${style.yellow}${warns.length} warn${style.reset}`,
    `${style.green}${passes.length} pass${style.reset}`,
    infos.length ? `${style.cyan}${infos.length} info${style.reset}` : '',
  ].filter(Boolean);
  lines.push(tally.join('  '));
  lines.push('');

  const emitGroups = (groups: ThemeGroup[], title: string) => {
    if (groups.length === 0) return;
    lines.push(`${style.bold}${title}${style.reset}`);
    for (let i = 0; i < groups.length; i++) {
      lines.push(...renderIssueBlock(groups[i], width, style));
      if (i !== groups.length - 1) lines.push('');
    }
    lines.push('');
  };

  emitGroups(failGroups, 'FAILURES');
  emitGroups(warnGroups, 'NEEDS ATTENTION');
  if (verbose) {
    emitGroups(infoGroups, 'INFO');
  } else if (infoGroups.length > 0) {
    // Compact info: one line each, no big section unless verbose
    lines.push(`${style.bold}INFO${style.reset}`);
    for (const g of infoGroups) {
      const bit = `${STATUS_MARK.info} ${g.theme} ${g.what}${g.count > 1 ? ` x${g.count}` : ''}`;
      lines.push(...wrapLine(bit, width, 0, 4).map((l, idx) => (idx === 0 ? `${style.cyan}${STATUS_MARK.info}${style.reset} ${g.theme.padEnd(6)} ${ellipsize(`${g.what}${g.count > 1 ? ` x${g.count}` : ''}`, Math.max(8, width - 12))}` : `${style.dim}${l}${style.reset}`)));
      lines.push(...wrapLine(oneLineWhy(g.why, width), width, 4, 4).map((l) => `${style.dim}${l}${style.reset}`));
      lines.push('');
    }
  }

  if (verbose) {
    if (passes.length > 0) {
      lines.push(`${style.bold}HEALTHY${style.reset}`);
      for (const p of passes) {
        lines.push(...renderPassLine(p, width, style));
      }
      lines.push('');
    }
  } else if (passes.length > 0) {
    const labels = passes.map((p) => themeForLabel(p.label));
    const uniq = unique(labels).slice(0, 10);
    const more = unique(labels).length > 10 ? '…' : '';
    const summary = `${passes.length} pass hidden — ${uniq.join(' · ')}${more}`;
    lines.push(...wrapLine(summary, width, 0, 2).map((l) => `${style.dim}${l}${style.reset}`));
    lines.push(`${style.dim}rerun: shieldcortex doctor --verbose${style.reset}`);
    lines.push('');
  }

  // All clear
  if (fails.length === 0 && warns.length === 0) {
    lines.push(`${style.green}All clear.${style.reset}`);
    lines.push('');
  }

  // Drop trailing blank
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines;
}

function clampWidth(w: number): number {
  if (!Number.isFinite(w) || w < 40) return 40;
  // Full-screen terminals are often 160–200+; 120 forced mid-sentence cutoffs.
  if (w > 240) return 240;
  return Math.floor(w);
}

function detectWidth(): number {
  const cols = Number(process.env.COLUMNS || process.stdout?.columns || 80);
  return clampWidth(cols || 80);
}

function defaultColorStyle(): DoctorReportStyle {
  return {
    bold: '\x1b[1m',
    reset: '\x1b[0m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    cyan: '\x1b[36m',
    dim: '\x1b[2m',
  };
}

/** True when stdout looks like a TTY and NO_COLOR is unset. */
export function shouldColorDoctor(env: NodeJS.ProcessEnv = process.env, stdoutIsTTY = !!process.stdout?.isTTY): boolean {
  if (env.NO_COLOR != null && env.NO_COLOR !== '') return false;
  if (env.FORCE_COLOR === '0') return false;
  if (env.FORCE_COLOR) return true;
  return stdoutIsTTY;
}
