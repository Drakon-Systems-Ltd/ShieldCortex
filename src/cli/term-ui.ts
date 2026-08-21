/**
 * Shared terminal UX primitives for ShieldCortex CLI.
 *
 * Design lock: docs/design/2026-08-21-terminal-ux.md (v3).
 * Pure helpers + pure renderers (string[]). No process.stdout inside renderers.
 * Mobile SSH (40-col) is first-class. No Ink/Blessed/new runtime deps.
 */

export type TermStyle = {
  bold: string;
  reset: string;
  green: string;
  yellow: string;
  red: string;
  cyan: string;
  dim: string;
};

export const NO_STYLE: TermStyle = {
  bold: '',
  reset: '',
  green: '',
  yellow: '',
  red: '',
  cyan: '',
  dim: '',
};

export function defaultColorStyle(): TermStyle {
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

export interface WidthOpts {
  width?: number;
  env?: NodeJS.ProcessEnv;
  columns?: number;
}

/** Clamp display width: floor 40, cap 240. */
export function clampWidth(w: number): number {
  if (!Number.isFinite(w) || w < 40) return 40;
  if (w > 240) return 240;
  return Math.floor(w);
}

export function getWidth(opts: WidthOpts = {}): number {
  if (typeof opts.width === 'number') return clampWidth(opts.width);
  const env = opts.env ?? process.env;
  const fromEnv = Number(env.COLUMNS || '');
  if (Number.isFinite(fromEnv) && fromEnv > 0) return clampWidth(fromEnv);
  if (typeof opts.columns === 'number') return clampWidth(opts.columns);
  const cols = Number(process.stdout?.columns || 80);
  return clampWidth(cols || 80);
}

/** Frame width for boxes — never wider than 72. */
export function frameWidth(contentWidth: number): number {
  return Math.min(clampWidth(contentWidth), 72);
}

export function supportsColor(
  env: NodeJS.ProcessEnv = process.env,
  stdoutIsTTY = !!process.stdout?.isTTY,
): boolean {
  if (env.NO_COLOR != null && env.NO_COLOR !== '') return false;
  if (env.FORCE_COLOR === '0') return false;
  if (String(env.TERM || '').toLowerCase() === 'dumb') return false;
  if (env.FORCE_COLOR) return true;
  return stdoutIsTTY;
}

export function supportsUnicode(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  if (String(env.TERM || '').toLowerCase() === 'dumb') return false;
  if (env.SHIELDCORTEX_ASCII === '1' || env.SC_ASCII === '1') return false;
  const loc = `${env.LC_ALL || ''}${env.LC_CTYPE || ''}${env.LANG || ''}`;
  if (loc && !/utf-?8/i.test(loc)) return false;
  return true;
}

const ANSI_RE = /\u001b\[[0-9;?]*[ -/]*[@-~]|\u001b\][^\u0007]*(?:\u0007|\u001b\\)?|\u001b./g;

export function stripAnsi(s: string): string {
  return String(s ?? '').replace(ANSI_RE, '');
}

export function visibleWidth(s: string): number {
  return stripAnsi(s).length;
}

/** Display safety for untrusted fields (paths, job names, sources). Not secret redaction. */
export function sanitiseDisplayField(s: string): string {
  return String(s ?? '')
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)?/g, '')
    .replace(/\u001b./g, '')
    .replace(/[\r\n]/g, '⏎')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]/g, '');
}

export function ellipsize(s: string, max: number): string {
  const t = String(s ?? '');
  if (t.length <= max) return t;
  if (max <= 1) return '…';
  return `${t.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

/** Soft-wrap at spaces; hanging indent on continuation. Same contract as doctor wrapLine. */
export function wrapText(text: string, width: number, indent = 0, hang = 0): string[] {
  // Per-line budget: first line uses indent, continuations use hang — so
  // hang+token never exceeds width (phone SSH regression).
  const words = String(text ?? '').split(/\s+/).filter(Boolean);
  if (words.length === 0) return [' '.repeat(Math.min(indent, Math.max(0, width)))];
  const lines: string[] = [];
  let cur = '';
  let lineIndex = 0;
  const pad = () => (lineIndex === 0 ? indent : hang);
  const budget = () => Math.max(1, width - pad());
  const push = () => {
    if (!cur) return;
    lines.push(`${' '.repeat(pad())}${cur}`);
    cur = '';
    lineIndex += 1;
  };
  for (const w of words) {
    if (!cur) {
      let rest = w;
      while (rest.length > budget()) {
        const b = budget();
        lines.push(`${' '.repeat(pad())}${rest.slice(0, b)}`);
        rest = rest.slice(b);
        lineIndex += 1;
      }
      cur = rest;
      continue;
    }
    if (`${cur} ${w}`.length <= budget()) {
      cur = `${cur} ${w}`;
    } else {
      push();
      let rest = w;
      while (rest.length > budget()) {
        const b = budget();
        lines.push(`${' '.repeat(pad())}${rest.slice(0, b)}`);
        rest = rest.slice(b);
        lineIndex += 1;
      }
      cur = rest;
    }
  }
  push();
  return lines.length ? lines : [' '.repeat(Math.min(indent, Math.max(0, width)))];
}

export function wrapLine(text: string, width: number, indent = 0, hang = 0): string[] {
  return wrapText(text, width, indent, hang);
}

export function basenameOf(p: string): string {
  const s = String(p ?? '').replace(/\\/g, '/');
  const i = s.lastIndexOf('/');
  return i >= 0 ? s.slice(i + 1) || s : s;
}

export function homeToTilde(p: string, home?: string): string {
  const h = home ?? (typeof process.env.HOME === 'string' ? process.env.HOME : '');
  if (h && (p === h || p.startsWith(h + '/') || p.startsWith(h + '\\'))) {
    return `~${p.slice(h.length).replace(/\\/g, '/')}`;
  }
  return p.replace(/\\/g, '/');
}

/** Secondary-list path truncate: keep basename, head…tail. */
export function truncatePath(p: string, width: number, home?: string): string {
  const raw = homeToTilde(sanitiseDisplayField(p), home);
  if (raw.length <= width) return raw;
  const base = basenameOf(raw);
  if (width <= 4) return ellipsize(base, width);
  if (base.length + 2 >= width) return ellipsize(base, width);
  const room = width - base.length - 1; // for …
  const headLen = Math.max(1, Math.ceil(room * 0.45));
  const tailFromBase = base.length;
  // path without basename
  const prefix = raw.slice(0, Math.max(0, raw.length - base.length));
  const head = prefix.slice(0, headLen);
  return `${head}…/${base}`.length <= width
    ? `${head}…/${base}`
    : ellipsize(`${head}…${base}`, width);
}

export function truncateMiddle(s: string, width: number): string {
  const t = String(s ?? '');
  if (t.length <= width) return t;
  if (width <= 1) return '…';
  if (width === 2) return `${t[0]}…`;
  const keep = width - 1;
  const head = Math.ceil(keep / 2);
  const tail = Math.floor(keep / 2);
  return `${t.slice(0, head)}…${t.slice(t.length - tail)}`;
}

export function hr(width: number, ch = '─', unicode = true): string {
  const c = unicode ? ch : '-';
  return c.repeat(Math.max(8, Math.min(width, 72)));
}

export function box(title: string, bodyLines: string[], width: number, unicode = true): string[] {
  const w = frameWidth(width);
  const inner = Math.max(8, w - 2);
  const t = ellipsize(sanitiseDisplayField(title), Math.max(4, inner - 4));
  const top = unicode ? `┌─ ${t} ${'─'.repeat(Math.max(0, inner - 3 - t.length))}┐` : `+- ${t} ${'-'.repeat(Math.max(0, inner - 3 - t.length))}+`;
  const bot = unicode ? `└${'─'.repeat(inner)}┘` : `+${'-'.repeat(inner)}+`;
  const sideL = unicode ? '│' : '|';
  const sideR = unicode ? '│' : '|';
  const lines = [top];
  for (const raw of bodyLines) {
    const plain = stripAnsi(raw);
    const pad = Math.max(0, inner - plain.length);
    // if overflow, hard clip plain measurement — callers should wrap first
    const cell = plain.length > inner ? `${plain.slice(0, inner - 1)}…` : raw + ' '.repeat(pad);
    if (plain.length > inner) {
      lines.push(`${sideL}${ellipsize(plain, inner)}${sideR}`);
    } else {
      lines.push(`${sideL}${raw}${' '.repeat(pad)}${sideR}`);
    }
  }
  lines.push(bot);
  return lines;
}

export type ChipStatus = 'new' | 'changed' | 'current' | 'missing' | 'too_large';

export function chip(status: ChipStatus, style: TermStyle = NO_STYLE): string {
  const label =
    status === 'new' ? 'NEW' :
    status === 'changed' ? 'CHANGED' :
    status === 'current' ? 'CURRENT' :
    status === 'missing' ? 'MISSING' :
    'TOO_LARGE';
  const color =
    status === 'current' ? style.green :
    status === 'new' || status === 'changed' ? style.yellow :
    style.red;
  return `${color}${label}${style.reset}`;
}

export type VerdictKind = 'OK' | 'NEEDS ATTENTION' | 'INCOMPLETE' | 'FAILED';

export function verdictLine(kind: VerdictKind, style: TermStyle = NO_STYLE): string {
  if (kind === 'OK') return `${style.green}${style.bold}VERDICT  OK${style.reset}`;
  if (kind === 'NEEDS ATTENTION') return `${style.yellow}${style.bold}VERDICT  NEEDS ATTENTION${style.reset}`;
  if (kind === 'INCOMPLETE') return `${style.red}${style.bold}VERDICT  INCOMPLETE${style.reset}`;
  return `${style.red}${style.bold}VERDICT  FAILED${style.reset}`;
}

export function shortSourceLabel(source: string): string {
  const s = String(source || '');
  if (s === 'hermes-cron') return 'hermes';
  if (s === 'openclaw-cron') return 'oc';
  if (s === 'openclaw-cron-db') return 'oc-db';
  if (s === 'glob') return 'glob';
  return s;
}

export interface PinCardInput {
  index: number;
  total: number;
  status: 'new' | 'changed';
  path: string;
  sha256?: string;
  pinnedSha256?: string;
  sources: string[];
  networkHint?: boolean;
  deniedNote?: string;
  /** When set, show this preview page (already sanitised lines). */
  previewLines?: string[];
  previewPage?: number;
  previewTotalLines?: number;
}

export function renderPinCard(item: PinCardInput, opts: {
  width?: number;
  style?: TermStyle;
  unicode?: boolean;
} = {}): string[] {
  const width = getWidth({ width: opts.width });
  const style = opts.style ?? NO_STYLE;
  const path = sanitiseDisplayField(item.path);
  const base = basenameOf(path);
  const lines: string[] = [];
  const head = `── ${item.index}/${item.total} · ${item.status === 'changed' ? 'CHANGED' : 'NEW'} · ${base}`;
  for (const l of wrapText(head, width, 0, 2)) {
    lines.push(`${style.bold}${l}${style.reset}`);
  }
  // Full path, wrapped
  for (const l of wrapText(path, width, 0, 2)) lines.push(l);
  const sha = (item.sha256 ?? '').slice(0, 16);
  if (sha) {
    const shaLine = item.status === 'changed' && item.pinnedSha256
      ? `sha   ${sha}…  was ${(item.pinnedSha256).slice(0, 16)}…`
      : `sha   ${sha}…`;
    lines.push(...wrapText(shaLine, width, 0, 6));
  }
  if (item.sources?.length) {
    const src = `src   ${item.sources.map(shortSourceLabel).map(sanitiseDisplayField).join(' · ')}`;
    lines.push(...wrapText(src, width, 0, 6));
  }
  if (item.networkHint) {
    lines.push(...wrapText(`${style.yellow}[!]${style.reset} network calls likely (advisory)`, width, 0, 4));
  }
  if (item.deniedNote) {
    lines.push(...wrapText(`${style.yellow}[!]${style.reset} ${sanitiseDisplayField(item.deniedNote)}`, width, 0, 4));
  }
  if (item.previewLines && item.previewLines.length > 0) {
    const total = item.previewTotalLines ?? item.previewLines.length;
    const page = item.previewPage ?? 1;
    const start = (page - 1) * item.previewLines.length + 1;
    const end = Math.min(total, start + item.previewLines.length - 1);
    lines.push(`${style.dim}source lines ${start}–${end} of ${total}${style.reset}`);
    for (const pl of item.previewLines) {
      const safe = sanitiseDisplayField(pl);
      for (const wl of wrapText(`${style.dim}│${style.reset} ${safe}`, width, 0, 2)) lines.push(wl);
    }
  }
  lines.push('');
  for (const l of wrapText('[y] pin  [n] skip  [v]iew  [q]uit', width, 0, 0)) {
    lines.push(l.replace('[y]', `${style.bold}[y]${style.reset}`)
      .replace('[n]', `${style.bold}[n]${style.reset}`)
      .replace('[v]', `${style.bold}[v]${style.reset}`)
      .replace('[q]', `${style.bold}[q]${style.reset}`));
  }
  return lines;
}

export function renderBatchIdentity(item: {
  status: ChipStatus;
  path: string;
  sha256?: string;
  networkHint?: boolean;
  deniedNote?: boolean;
  /** Full source ids (kept for --json parity / tests); short labels also shown. */
  sources?: string[];
}, opts: { width?: number; style?: TermStyle } = {}): string[] {
  const width = getWidth({ width: opts.width });
  const style = opts.style ?? NO_STYLE;
  const path = sanitiseDisplayField(item.path);
  const base = basenameOf(path);
  const flags: string[] = [];
  if (item.networkHint) flags.push('net');
  if (item.deniedNote) flags.push('denied');
  const sha = item.sha256 ? item.sha256.slice(0, 12) + '…' : '';
  const srcFull = (item.sources ?? []).map(sanitiseDisplayField).join(',');
  const line1 = `${chip(item.status, style)}  ${style.bold}${base}${style.reset}`;
  // Full path wrapped (macOS tests + operators need the canonical path visible;
  // never rely on truncatePath alone in the scan summary).
  const out = [line1, ...wrapText(path, width, 2, 2)];
  const meta = [sha, srcFull, ...flags].filter(Boolean).join(' · ');
  if (meta) out.push(...wrapText(`${style.dim}${meta}${style.reset}`, width, 2, 2));
  return out;
}

/** Closed-vocab status tokens allowed inside update panel frames. */
const PANEL_STATUS = new Set(['ok', 'warn', 'blocked', 'unproven', 'failed', 'skipped', 'attention']);

export interface UpdatePanelRow {
  /** Short label, SC-generated */
  label: string;
  /** Closed vocabulary status */
  status: string;
}

export interface UpdatePanelInput {
  fromVersion?: string;
  toVersion?: string;
  verdict: VerdictKind;
  rows: UpdatePanelRow[];
  /** Frameless detail lines (already should be sanitised by caller). */
  details?: string[];
  /** Frameless next-step commands — never truncated mid-command. */
  next?: string[];
}

function safeVersion(v: string | undefined): string {
  const s = String(v ?? '').trim();
  if (/^[\w.+-]{1,32}$/.test(s)) return s;
  return '';
}

export function renderUpdatePanel(input: UpdatePanelInput, opts: {
  width?: number;
  style?: TermStyle;
  unicode?: boolean;
} = {}): string[] {
  const width = getWidth({ width: opts.width });
  const style = opts.style ?? NO_STYLE;
  const unicode = opts.unicode !== false;
  const from = safeVersion(input.fromVersion);
  const to = safeVersion(input.toVersion);
  const title = from && to ? `update ${from} -> ${to}` : from ? `update ${from}` : 'update';
  const body: string[] = [];
  // verdict row without relying on ANSI inside box measurement much
  body.push(stripAnsi(verdictLine(input.verdict, NO_STYLE)));
  for (const r of input.rows) {
    const lab = sanitiseDisplayField(r.label).slice(0, 12).padEnd(10);
    const st = PANEL_STATUS.has(r.status) ? r.status : 'attention';
    body.push(`${lab}${st}`);
  }
  const fw = frameWidth(width);
  const out = box(title, body.map((l) => ellipsize(l, fw - 2)), width, unicode);
  // colorize verdict line inside box roughly by rebuilding first body — keep simple: paint after
  const painted: string[] = [];
  for (const line of out) {
    if (line.includes('VERDICT')) {
      painted.push(line.replace('VERDICT  OK', `${style.green}VERDICT  OK${style.reset}`)
        .replace('VERDICT  NEEDS ATTENTION', `${style.yellow}VERDICT  NEEDS ATTENTION${style.reset}`)
        .replace('VERDICT  INCOMPLETE', `${style.red}VERDICT  INCOMPLETE${style.reset}`)
        .replace('VERDICT  FAILED', `${style.red}VERDICT  FAILED${style.reset}`));
    } else {
      painted.push(line);
    }
  }
  for (const d of input.details ?? []) {
    for (const wl of wrapText(`detail  ${sanitiseDisplayField(d)}`, width, 0, 8)) painted.push(`${style.dim}${wl}${style.reset}`);
  }
  for (const n of input.next ?? []) {
    // never ellipsize commands — wrap only
    for (const wl of wrapText(`next    ${sanitiseDisplayField(n)}`, width, 0, 8)) painted.push(wl);
  }
  return painted;
}

export function deriveUpdateVerdict(args: {
  exitCode: number;
  failed?: boolean;
  incomplete?: boolean;
  attention?: boolean;
}): VerdictKind {
  if (args.exitCode !== 0 && args.incomplete) return 'INCOMPLETE';
  if (args.exitCode !== 0 || args.failed) return 'FAILED';
  if (args.attention) return 'NEEDS ATTENTION';
  return 'OK';
}
