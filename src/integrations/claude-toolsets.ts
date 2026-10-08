/**
 * ShieldCortex — Action Guard surface for the Claude SDK browser-use and
 * computer-use toolsets (issue #678, phase P1: observe-only).
 *
 * The Python and TypeScript Anthropic SDKs (7 Oct 2026) ship abstract classes
 * for `browser_toolset_20260801` and `computer_toolset_20260801`. The SDK runs
 * the tool loop and offers three host-side hook points per call:
 *
 *   urlPolicy(ctx, url)   — browser only, `navigate` only
 *   confirm(ctx)          — every call; `true` runs it, anything else refuses
 *   execute(ctx, name, input) override — around every call, AFTER confirm
 *
 * (See https://platform.claude.com/docs/en/agents-and-tools/tool-use/browser-use-sdk)
 *
 * This module plugs the Action Guard into those three points WITHOUT a runtime
 * dependency on the SDK: everything is typed structurally, and a type-level
 * conformance test (`claude-toolsets-sdk-types.test.ts`) checks those shapes
 * against the real `@anthropic-ai/sdk` classes (a devDependency only).
 * It classifies each member call into ADR-002 effect kinds, keeps the ref
 * catalogue that is the only way to know what a `ref` click does, scans every
 * page read with the tool-response scanner, taints the session on the first
 * untrusted read, and emits values-free audit events.
 *
 * P1 contract: in `observe` mode the guard NEVER changes behaviour. `confirm`
 * returns the host's own answer (or `true`), `execute` returns the driver's
 * result unchanged. Verdicts are computed and audited only. `enforce` mode is
 * implemented so the tests can prove the decision function, but it is not the
 * default and the bounded-approval/card wiring is phase P2.
 */

import { createHash } from 'node:crypto';
import { isIP } from 'node:net';
import { scanForCredentials } from '../defence/credential-leak/index.js';
import { scanToolResponse } from '../defence/tool-response-scanner.js';

// ── Types ─────────────────────────────────────────────────────────────────

export type ToolsetName = 'browser' | 'computer';
export type ToolsetGuardMode = 'observe' | 'enforce';
export type ToolsetDecision = 'allow' | 'require_approval' | 'block';

/**
 * Effect kinds. The named ones are the ADR-002 §2.4 minimum taxonomy;
 * `irreversible-ui-action` is the one addition this surface needs (a click
 * that pays, sends, deletes or accepts), and `observe` is "no effect".
 */
export type ToolsetEffectKind =
  | 'observe'
  | 'ui-action'
  | 'input'
  | 'submit'
  | 'irreversible-ui-action'
  | 'network-fetch'
  | 'egress'
  | 'credential-read'
  | 'code-exec-opaque'
  | 'unclassified';

/**
 * What the SDK passes to a member and to the `execute` override
 * (`BetaToolsetCallContext`): the tool_use being served, absent only when the
 * host calls `run()` without one, and the run's abort signal. It does NOT
 * carry the member, its input or the tab: those reach `confirm` only.
 */
export interface ToolsetCallContext {
  /** The tool_use being served; used only for its id. */
  readonly toolUse?: { readonly id?: string } | undefined;
  readonly signal?: AbortSignal | null | undefined;
}

/** The `confirm` context shape (`BetaConfirmContext` / `BetaComputerConfirmContext`), structurally. */
export interface ToolsetConfirmContext {
  readonly member: string;
  readonly input: unknown;
  /** Browser only: the target tab's URL from the LAST state report the SDK collected. */
  readonly tabURL?: string | undefined;
  /** Browser only: the target tab (else the active tab) from that report. */
  readonly tabId?: string | undefined;
  readonly toolUse?: { readonly id?: string } | null | undefined;
  readonly signal?: AbortSignal | null | undefined;
}

/** The first argument of the SDK's `urlPolicy(context, url)` (`BetaURLContext`). */
export interface ToolsetUrlContext {
  readonly member?: string | undefined;
  readonly tabId?: string | undefined;
  readonly toolUseId?: string | undefined;
}

export interface ToolsetRequester {
  /** ADR-002 band of whoever started the task. A declaration, never attestation. */
  band: 'operator' | 'signed-peer' | 'agent' | 'unknown';
  identifier?: string;
}

export interface ToolsetVerdict {
  decision: ToolsetDecision;
  effects: ToolsetEffectKind[];
  signals: string[];
  /** One-line, values-free reason for the audit row. */
  reason: string;
  /** Plain-English approval card (values-free, bounded). */
  card: string;
  /** Session taint state at decision time. */
  tainted: boolean;
  /** sha256 of the canonical input, so an approval binds to exact bytes. */
  inputHash: string;
}

export interface ToolsetAuditEvent {
  kind: 'call' | 'result';
  toolset: ToolsetName;
  member: string;
  mode: ToolsetGuardMode;
  decision: ToolsetDecision;
  effects: ToolsetEffectKind[];
  signals: string[];
  tainted: boolean;
  requestedBy: ToolsetRequester;
  /** Host (never path or query) of the tab or navigation target. */
  host?: string;
  /** Element role and bounded, escaped label when a ref click was resolved. */
  elementRole?: string;
  elementLabel?: string;
  inputHash: string;
  /** What actually happened: observe mode records the host's answer. */
  outcome: 'observed' | 'allowed' | 'asked' | 'refused' | 'scanned' | 'neutralised';
  /** Host's own confirm answer, when one was consulted. */
  hostAnswer?: boolean;
  /** For `result` events: whether the scan found anything, and what. */
  scanClean?: boolean;
  scanIndicators?: string[];
  at: number;
}

export interface ToolsetGuardOptions {
  toolset: ToolsetName;
  /** Default `observe` (P1). */
  mode?: ToolsetGuardMode;
  /**
   * Hosts the browser may navigate to (exact or subdomain match). When unset,
   * no host check runs (navigation is still scheme/range checked and audited).
   */
  urlAllowlist?: string[];
  /** Extra words that mark a clicked element as irreversible. */
  irreversibleLexicon?: string[];
  requestedBy?: ToolsetRequester;
  /** Values-free audit sink. Must not throw; exceptions are swallowed. */
  audit?: (event: ToolsetAuditEvent) => void;
  /**
   * Constructor to throw from `urlPolicy` / `execute` refusals. Pass the SDK's
   * `ToolError` so Claude reads a tool error; defaults to `Error`.
   */
  toolError?: new (message: string) => Error;
  /** Clock, for tests. */
  now?: () => number;
}

export type ToolsetConfirmInner = (
  ctx: ToolsetConfirmContext,
  verdict: ToolsetVerdict,
) => boolean | Promise<boolean>;

/**
 * The SDK's own `execute` (`(c, n, i) => super.execute(c, n, i)`). Generic so
 * the override keeps the SDK's context, member-name, input and result types.
 */
export type ToolsetExecuteNext<C extends ToolsetCallContext, N extends string, I, R> = (
  ctx: C,
  name: N,
  input: I,
) => R | Promise<R>;

/**
 * The browser report the SDK attaches to every tool result as the
 * `browser_state` block (`BetaBrowserState`), structurally. Tab titles, URLs and
 * dialog messages in it are page-supplied and reach the model.
 */
export interface ToolsetBrowserState {
  readonly tabs: ReadonlyArray<{
    readonly tab_id?: string;
    readonly title?: string;
    readonly url?: string;
    readonly active?: boolean;
  }>;
  readonly state_changes?: ReadonlyArray<unknown> | undefined;
}

interface RefCatalogue {
  /** The tab's URL (fragment dropped) when it was read; unknown when no report named it. */
  url?: string;
  entries: Map<string, { role: string; label: string }>;
}

/** Same page for ref purposes: a fragment change does not reload it. */
function pageKey(url: string | undefined): string | undefined {
  if (!url) return undefined;
  const hash = url.indexOf('#');
  return hash === -1 ? url : url.slice(0, hash);
}

/**
 * Where `confirm` records a call for `execute` to find: the tool_use id, else
 * the member name alone (the SDK runs one call per toolset at a time). Never
 * the input: a mutated input must land on the same record and fail its hash.
 */
function confirmKey(toolUseId: string | undefined, member: string): string {
  return toolUseId ? `id:${toolUseId}` : `member:${member}`;
}

/** What `confirm` saw for a call, so `execute` can bind to it. */
interface ConfirmedCall {
  inputHash: string;
  tabURL?: string;
  tabId?: string;
}

// ── Member tables ─────────────────────────────────────────────────────────

/** Members whose results are page/screen content the model will read. */
const READING_MEMBERS = new Set([
  'read_page', 'get_page_text', 'find', 'read_console', 'read_network',
  'javascript_exec', 'screenshot', 'zoom',
]);
/**
 * Members whose result is a tab record (`navigate`: final URL and title;
 * `new_tab` / `switch_tab` / `list_tabs`: tab entries). The title and URL are
 * page-supplied and the model reads them, so these taint like a page read.
 */
const PAGE_STATE_MEMBERS = new Set(['navigate', 'new_tab', 'switch_tab', 'list_tabs']);
/** Reading members whose result is text we can scan (not an image). */
const TEXT_RESULT_MEMBERS = new Set([
  'read_page', 'get_page_text', 'find', 'read_console', 'read_network', 'javascript_exec',
]);
/** Members that only observe or move the pointer: no effect. */
const NO_EFFECT_MEMBERS = new Set([
  'screenshot', 'zoom', 'cursor_position', 'wait', 'list_tabs', 'read_page',
  'get_page_text', 'find', 'read_console', 'read_network', 'scroll', 'scroll_to',
  'hover', 'mouse_move', 'switch_tab', 'close_tab',
]);
const CLICK_MEMBERS = new Set([
  'left_click', 'right_click', 'middle_click', 'double_click', 'triple_click',
  'left_click_drag', 'left_mouse_down', 'left_mouse_up',
]);
const KEYBOARD_MEMBERS = new Set(['type', 'type_', 'key', 'hold_key', 'form_input']);

const DEFAULT_IRREVERSIBLE_LEXICON = [
  'pay', 'buy', 'purchase', 'order', 'checkout', 'confirm', 'delete', 'remove',
  'send', 'submit', 'publish', 'post', 'transfer', 'approve', 'accept', 'agree',
  'sign', 'unsubscribe', 'cancel', 'subscribe', 'donate', 'wire', 'withdraw',
];

/** Upload paths that are credentials or guard state. Refused outright. */
const SENSITIVE_UPLOAD_PATH = /(^|\/)(\.ssh|\.aws|\.gnupg|\.config\/gh|\.npmrc|\.netrc|\.env(\.|$)|\.shieldcortex|\.openclaw|id_(rsa|ed25519|ecdsa)|keychain|\.docker\/config\.json)/i;

const SUBMIT_KEYS = /^(return|enter|kp_enter|cmd\+return|ctrl\+return|cmd\+enter|ctrl\+enter)$/i;

// ── Helpers ───────────────────────────────────────────────────────────────

function canonical(value: unknown): string {
  const seen = new WeakSet<object>();
  const walk = (v: unknown): unknown => {
    if (v === null || typeof v !== 'object') return v;
    if (seen.has(v as object)) return '[cycle]';
    seen.add(v as object);
    if (Array.isArray(v)) return v.map(walk);
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      if (k === '__proto__' || k === 'constructor' || k === 'prototype') continue;
      out[k] = walk((v as Record<string, unknown>)[k]);
    }
    return out;
  };
  return JSON.stringify(walk(value)) ?? 'undefined';
}

export function hashInput(member: string, input: unknown): string {
  return createHash('sha256').update(`${member}\n${canonical(input)}`).digest('hex');
}

/** Escape everything outside printable ASCII (Anthropic's guidance for cards). */
export function escapeForCard(text: string, max = 60): string {
  const clipped = text.length > max ? `${text.slice(0, max)}…` : text;
  return clipped.replace(/[^\x20-\x7e]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function asRecord(v: unknown): Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}

function hostOf(url: string | undefined): string | undefined {
  if (!url) return undefined;
  const parsed = parseUrlLikeBrowser(url);
  return parsed?.hostname || undefined;
}

const SCHEME_PREFIX = /^[a-z][a-z0-9+.-]*:/i;

function parseUrlLikeBrowser(raw: string): URL | null {
  const withScheme = SCHEME_PREFIX.test(raw) ? raw : `https://${raw}`;
  try {
    return new URL(withScheme.replaceAll('\\', '/'));
  } catch {
    return null;
  }
}

function isPrivateIPv4(ip: string): boolean {
  const [a, b, c] = ip.split('.').map(Number);
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true; // link-local, incl. cloud metadata 169.254.169.254
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT / Tailscale
  if (a === 192 && b === 0 && c === 0) return true; // IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast, reserved, broadcast
  return false;
}

/** Eight 16-bit groups of an IPv6 literal (`isIPv6` already passed), embedded IPv4 tail included. */
function ipv6Groups(ip: string): number[] {
  let text = ip;
  const tail = text.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (tail) {
    const [a, b, c, d] = tail[1].split('.').map(Number);
    text = `${text.slice(0, -tail[1].length)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, rest] = text.includes('::') ? text.split('::') : [text, undefined];
  const left = head ? head.split(':') : [];
  const right = rest ? rest.split(':') : [];
  const fill = rest === undefined ? [] : new Array(8 - left.length - right.length).fill('0');
  return [...left, ...fill, ...right].map((g) => parseInt(g, 16));
}

function isPrivateIPv6(ip: string): boolean {
  const g = ipv6Groups(ip);
  const v4 = (): string => [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff].join('.');
  if (g.every((x) => x === 0)) return true; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return isPrivateIPv4(v4()); // ::ffff:a.b.c.d
  if (g.slice(0, 6).every((x) => x === 0)) return true; // ::a.b.c.d (deprecated compatible)
  if (g[0] === 0x64 && g[1] === 0xff9b && g.slice(2, 6).every((x) => x === 0)) return isPrivateIPv4(v4()); // NAT64
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local (deprecated)
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  return false;
}

/**
 * Whether a URL hostname is loopback, private, link-local or otherwise not a
 * public site. Only an IP literal is classified by address: a DNS name such as
 * `fdic.gov` is a name, never an address prefix. Pure: no DNS lookup.
 */
export function isPrivateOrLocalHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.+$/, '');
  if (isIP(h) === 4) return isPrivateIPv4(h);
  if (isIP(h) === 6) return isPrivateIPv6(h.replace(/%.*$/, ''));
  if (h.includes(':')) return true; // a zone id or anything else no public host carries
  return h === '' || h === 'localhost' || h.endsWith('.localhost');
}

export interface UrlCheck {
  allowed: boolean;
  /** `block` = never; `ask` = off-allowlist; `allow` = fine. */
  verdict: 'allow' | 'ask' | 'block';
  reason: string;
  effects: ToolsetEffectKind[];
  host?: string;
}

/** Shared by `urlPolicy` and the driver's request-interception hook. */
export function checkUrl(url: string, allowlist?: string[]): UrlCheck {
  if (/[\s\x00-\x1f\x7f]/.test(url)) {
    return { allowed: false, verdict: 'block', reason: 'url-control-characters', effects: ['network-fetch'] };
  }
  if (url.toLowerCase() === 'about:blank') {
    return { allowed: true, verdict: 'allow', reason: 'about-blank', effects: ['observe'] };
  }
  const parsed = parseUrlLikeBrowser(url);
  if (!parsed) {
    return { allowed: false, verdict: 'block', reason: 'url-unparseable', effects: ['network-fetch'] };
  }
  const scheme = parsed.protocol;
  if (scheme === 'javascript:' || scheme === 'data:' || scheme === 'blob:' || scheme === 'vbscript:') {
    return { allowed: false, verdict: 'block', reason: `url-scheme-script:${scheme.slice(0, -1)}`, effects: ['code-exec-opaque'] };
  }
  if (scheme === 'file:' || scheme === 'view-source:' || scheme === 'chrome:' || scheme === 'about:') {
    return { allowed: false, verdict: 'block', reason: `url-scheme-local:${scheme.slice(0, -1)}`, effects: ['credential-read'] };
  }
  if (scheme !== 'http:' && scheme !== 'https:') {
    return { allowed: false, verdict: 'block', reason: `url-scheme-unknown:${scheme.slice(0, -1)}`, effects: ['network-fetch'] };
  }
  const host = parsed.hostname.toLowerCase();
  if (parsed.username || parsed.password) {
    return { allowed: false, verdict: 'block', reason: 'url-embedded-credentials', effects: ['credential-read', 'egress'], host };
  }
  if (isPrivateOrLocalHost(host)) {
    return { allowed: false, verdict: 'block', reason: 'url-private-or-local-range', effects: ['network-fetch'], host };
  }
  if (allowlist && allowlist.length > 0) {
    const hosts = allowlist.map((h) => h.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
    const listed = hosts.some((h) => host === h || host.endsWith(`.${h}`));
    if (!listed) {
      return { allowed: false, verdict: 'ask', reason: 'url-host-not-allowlisted', effects: ['network-fetch'], host };
    }
  }
  return { allowed: true, verdict: 'allow', reason: 'url-allowed', effects: ['network-fetch'], host };
}

/** Parse the `read_page` / `find` output into ref → {role, label}. */
export function parseRefCatalogue(text: string): Map<string, { role: string; label: string }> {
  const out = new Map<string, { role: string; label: string }>();
  // `button "Pay now" [ref_4]`  or  `[ref_4] button "Pay now"`
  const a = /([A-Za-z_][\w-]*)\s+"((?:[^"\\]|\\.)*)"[^\n\[]*\[(ref_[\w-]+)\]/g;
  const b = /\[(ref_[\w-]+)\]\s*([A-Za-z_][\w-]*)\s+"((?:[^"\\]|\\.)*)"/g;
  let m: RegExpExecArray | null;
  while ((m = a.exec(text)) !== null) out.set(m[3], { role: m[1].toLowerCase(), label: m[2] });
  while ((m = b.exec(text)) !== null) if (!out.has(m[1])) out.set(m[1], { role: m[2].toLowerCase(), label: m[3] });
  return out;
}

/** Page-supplied text in a tab record or browser report: titles, URLs, dialog messages. */
function pageSuppliedText(value: unknown): string[] {
  const out: string[] = [];
  const tab = (v: unknown): void => {
    const r = asRecord(v);
    if (typeof r.title === 'string' && r.title.trim()) out.push(r.title);
    if (typeof r.url === 'string' && r.url.trim() && r.url.trim().toLowerCase() !== 'about:blank') out.push(r.url);
  };
  if (Array.isArray(value)) value.forEach(tab);
  else tab(value);
  const r = asRecord(value);
  if (Array.isArray(r.tabs)) r.tabs.forEach(tab);
  if (Array.isArray(r.state_changes)) {
    for (const change of r.state_changes) {
      const c = asRecord(change);
      if (typeof c.message === 'string' && c.message.trim()) out.push(c.message);
    }
  }
  return out;
}

function textOfKeyboardInput(member: string, input: unknown): string {
  const r = asRecord(input);
  if (typeof r.text === 'string') return r.text;
  if (typeof r.value === 'string') return r.value;
  if (typeof r.key === 'string') return r.key;
  // form_input and unknown shapes: scan every string leaf.
  const parts: string[] = [];
  const walk = (v: unknown, depth: number): void => {
    if (depth > 4) return;
    if (typeof v === 'string') parts.push(v);
    else if (Array.isArray(v)) v.forEach((x) => walk(x, depth + 1));
    else if (v && typeof v === 'object') Object.values(v as Record<string, unknown>).forEach((x) => walk(x, depth + 1));
  };
  walk(input, 0);
  return parts.join('\n');
}

// ── The guard ─────────────────────────────────────────────────────────────

export class ToolsetGuard {
  readonly toolset: ToolsetName;
  readonly mode: ToolsetGuardMode;
  private readonly allowlist?: string[];
  private readonly lexicon: RegExp;
  private readonly requestedBy: ToolsetRequester;
  private readonly sink?: (event: ToolsetAuditEvent) => void;
  private readonly ErrorCtor: new (message: string) => Error;
  private readonly now: () => number;

  /** Session taint (ADR-002 §2.2): set on the first untrusted read, never cleared. */
  private tainted = false;
  /**
   * Ref catalogue per resolved tab id, for the page that tab showed when it was
   * read. A full `read_page` replaces it; navigating the tab or a report showing
   * a different URL drops it. A tab never borrows another tab's refs.
   */
  private readonly refs = new Map<string, RefCatalogue>();
  /** The active tab in the last `browserState` report, when wrapped. */
  private activeTab: string | undefined;
  /** Previous member seen, for `type` → `key Enter` = submit. */
  private previousMember: string | null = null;
  /** What `confirm` saw per call, so `execute` can detect a mutated input and knows the tab. */
  private readonly confirmed = new Map<string, ConfirmedCall>();

  constructor(options: ToolsetGuardOptions) {
    this.toolset = options.toolset;
    this.mode = options.mode ?? 'observe';
    this.allowlist = options.urlAllowlist;
    const words = [...DEFAULT_IRREVERSIBLE_LEXICON, ...(options.irreversibleLexicon ?? [])]
      .map((w) => w.toLowerCase().replace(/[^\p{L}\p{N} ]/gu, ''))
      .filter(Boolean);
    this.lexicon = new RegExp(`(^|[^\\p{L}])(${words.map((w) => w.replace(/ /g, '\\s+')).join('|')})([^\\p{L}]|$)`, 'iu');
    this.requestedBy = options.requestedBy ?? { band: 'unknown' };
    this.sink = options.audit;
    this.ErrorCtor = options.toolError ?? Error;
    this.now = options.now ?? Date.now;
  }

  get isTainted(): boolean {
    return this.tainted;
  }

  // ── Classification (pure apart from reading guard state) ──

  classify(ctx: ToolsetConfirmContext): ToolsetVerdict {
    const member = ctx.member;
    const input = asRecord(ctx.input);
    const inputHash = hashInput(member, ctx.input);
    const host = hostOf(ctx.tabURL);
    const where = host ? ` on ${escapeForCard(host, 80)}` : this.toolset === 'computer' ? ' (desktop)' : ' on an unknown page';
    const tainted = this.tainted;
    const who = this.requestedBy.band === 'unknown' ? 'unknown' : this.requestedBy.band.replace('-', ' ');
    const because = tainted
      ? 'The agent is working from content it read from the web or screen, which could be steering it.'
      : 'No web or screen content has been read yet in this session.';
    const finish = (
      decision: ToolsetDecision,
      effects: ToolsetEffectKind[],
      signals: string[],
      reason: string,
      card: string,
    ): ToolsetVerdict => ({ decision, effects, signals, reason, card, tainted, inputHash });

    // 1. Navigation.
    if (member === 'navigate' || member === 'new_tab') {
      const url = typeof input.url === 'string' ? input.url : '';
      if (!url || /^(back|forward|reload)$/i.test(url)) {
        return finish('allow', ['observe'], [], 'navigate-history', `Go ${url || 'to a new tab'}${where}.`);
      }
      const check = checkUrl(url, this.allowlist);
      const target = check.host ? escapeForCard(check.host, 80) : 'an address that is not a web page';
      if (check.verdict === 'block') {
        return finish('block', check.effects, [check.reason], check.reason,
          `Open ${target}? ShieldCortex does not allow this kind of address. Denied; nothing was opened.`);
      }
      if (check.verdict === 'ask') {
        return finish('require_approval', check.effects, [check.reason], check.reason,
          `Open ${target}? It is not on the list of sites this task may use. Requested by: ${who}. Approve once / Deny.`);
      }
      return finish('allow', check.effects, [], check.reason, `Open ${target}.`);
    }

    // 2. Script execution with the page's authority.
    if (member === 'javascript_exec') {
      return finish('require_approval', ['code-exec-opaque'], ['page-script-exec'], 'page-script-exec',
        `Run page script${where}? Scripts run with the page's own cookies and logins. Requested by: ${who}. Approve once / Deny.`);
    }

    // 3. Local files leaving the host.
    if (member === 'file_upload') {
      const paths = Array.isArray(input.paths) ? input.paths.filter((p): p is string => typeof p === 'string') : [];
      if (paths.some((p) => SENSITIVE_UPLOAD_PATH.test(p))) {
        return finish('block', ['credential-read', 'egress'], ['upload-sensitive-path'], 'upload-sensitive-path',
          `Upload a file${where}? The file is a credential or configuration file. Denied; nothing was uploaded.`);
      }
      return finish('require_approval', ['egress'], ['file-upload'], 'file-upload',
        `Upload ${paths.length || 'some'} file(s) from this machine${where}? Requested by: ${who}. Approve once / Deny.`);
    }

    // 4. Keyboard: secrets must never be typed; Enter after typing is a submit.
    if (KEYBOARD_MEMBERS.has(member)) {
      const text = textOfKeyboardInput(member, ctx.input);
      const creds = scanForCredentials(text);
      if (creds.leaked) {
        const types = [...new Set(creds.findings.map((f) => f.type))];
        return finish('block', ['credential-read', 'egress'], types.map((t) => `typed-secret:${t}`), 'typed-secret',
          `Type into a field${where}? The text looks like a ${types[0] ?? 'secret'}. ShieldCortex does not allow secrets to be typed into pages or apps. Denied; nothing was typed.`);
      }
      const isSubmitKey = (member === 'key' || member === 'hold_key') && SUBMIT_KEYS.test(text.trim());
      const typedNewline = (member === 'type' || member === 'type_') && /[\r\n]/.test(text);
      if (isSubmitKey || typedNewline) {
        const afterTyping = this.previousMember === 'type' || this.previousMember === 'type_' || this.previousMember === 'form_input';
        const effects: ToolsetEffectKind[] = afterTyping ? ['submit', 'irreversible-ui-action'] : ['submit'];
        const decision: ToolsetDecision = afterTyping || this.toolset === 'computer' ? 'require_approval' : 'allow';
        return finish(decision, effects, ['submit-key'], afterTyping ? 'submit-after-typing' : 'submit-key',
          `Press Enter${where}? ${afterTyping ? 'This submits what was just typed.' : ''} ${because} Requested by: ${who}. Approve once / Deny.`.replace(/\s+/g, ' '));
      }
      if (this.toolset === 'computer') {
        // The desktop may have a terminal or run dialog focused: unclassifiable.
        return finish(tainted ? 'require_approval' : 'allow', ['input', 'unclassified'], ['desktop-keyboard'], 'desktop-keyboard',
          `Type on the desktop? ShieldCortex cannot tell which window has focus. ${because} Requested by: ${who}. Approve once / Deny.`);
      }
      return finish('allow', ['input'], [], 'typed-text', `Type into a field${where}.`);
    }

    // 5. Clicks: resolve a ref through the catalogue; a coordinate is opaque.
    if (CLICK_MEMBERS.has(member)) {
      const target = asRecord(input.target);
      const ref = typeof target.ref === 'string' ? target.ref : typeof input.ref === 'string' ? input.ref : null;
      if (this.toolset === 'browser' && ref) {
        const el = this.lookupRef(ctx, ref);
        if (el) {
          const label = escapeForCard(el.label);
          if (this.lexicon.test(el.label)) {
            return finish('require_approval', ['irreversible-ui-action'], ['irreversible-click', `role:${el.role}`], 'irreversible-click',
              `Click the ${el.role} labelled "${label}"${where}? ${because} This could spend money, send something or delete something. Requested by: ${who}. Approve once / Deny.`);
          }
          if (el.role === 'link' || el.role === 'a') {
            return finish('allow', ['network-fetch'], [`role:${el.role}`], 'click-link',
              `Follow the link "${label}"${where}.`);
          }
          return finish('allow', ['ui-action'], [`role:${el.role}`], 'click-element',
            `Click the ${el.role} labelled "${label}"${where}.`);
        }
        return finish(tainted ? 'require_approval' : 'allow', ['unclassified'], ['click-unresolved-ref'], 'click-unresolved-ref',
          `Click an element${where}? ShieldCortex has no record of what this element is. ${because} Requested by: ${who}. Approve once / Deny.`);
      }
      const kind = this.toolset === 'computer' ? 'on the screen (desktop)' : `at a point${where}`;
      return finish(tainted ? 'require_approval' : 'allow', ['unclassified'], ['click-coordinate'], 'click-coordinate',
        `Click ${kind}? ShieldCortex cannot tell what this click does. ${because} Requested by: ${who}. Approve once / Deny.`);
    }

    // 6. Observation and pointer movement: no effect, but untrusted content.
    if (NO_EFFECT_MEMBERS.has(member)) {
      return finish('allow', ['observe'], [], 'observe', `Read or look${where}.`);
    }

    // 7. Anything else: fail closed on classification (ADR-002 §2.4).
    return finish(tainted ? 'require_approval' : 'allow', ['unclassified'], ['member-unknown'], 'member-unknown',
      `Run "${escapeForCard(member, 40)}"${where}? ShieldCortex does not recognise this action. ${because} Requested by: ${who}. Approve once / Deny.`);
  }

  // ── Hook adapters ──

  /** A `confirm` callable for the SDK class. */
  confirm(inner?: ToolsetConfirmInner): (ctx: ToolsetConfirmContext) => Promise<boolean> {
    return async (ctx: ToolsetConfirmContext): Promise<boolean> => {
      const verdict = this.classify(ctx);
      this.confirmed.set(confirmKey(ctx.toolUse?.id, ctx.member), { inputHash: verdict.inputHash, tabURL: ctx.tabURL, tabId: ctx.tabId });
      this.previousMember = ctx.member;

      let answer: boolean;
      let hostAnswer: boolean | undefined;
      let outcome: ToolsetAuditEvent['outcome'];
      if (this.mode === 'observe') {
        hostAnswer = inner ? (await inner(ctx, verdict)) === true : undefined;
        answer = inner ? hostAnswer === true : true;
        outcome = 'observed';
      } else if (verdict.decision === 'block') {
        answer = false;
        outcome = 'refused';
      } else if (verdict.decision === 'require_approval') {
        hostAnswer = inner ? (await inner(ctx, verdict)) === true : false;
        answer = hostAnswer;
        outcome = answer ? 'asked' : 'refused';
      } else {
        answer = true;
        outcome = 'allowed';
      }
      this.emit({ kind: 'call', ctx, verdict, outcome, hostAnswer });
      return answer;
    };
  }

  /** A `urlPolicy` callable for the browser class. */
  urlPolicy(): (ctx: ToolsetUrlContext, url: string) => void {
    return (_ctx: ToolsetUrlContext, url: string): void => {
      const check = checkUrl(url, this.allowlist);
      if (this.mode === 'observe') return;
      if (check.verdict === 'block') throw new this.ErrorCtor('blocked: this address is not allowed');
      if (check.verdict === 'ask') throw new this.ErrorCtor('blocked: this site is not on the allowed list');
    };
  }

  /**
   * Wrap the browser toolset's required `browserState` option. The SDK attaches
   * its report to every tool result, so tab titles, URLs and dialog messages are
   * page-supplied text the model reads: any of it taints the session, and the
   * text is scanned and audited. The report itself is returned unchanged.
   */
  browserState<S extends ToolsetBrowserState>(
    inner: (ctx: ToolsetCallContext) => S | Promise<S>,
  ): (ctx: ToolsetCallContext) => Promise<S> {
    return async (ctx: ToolsetCallContext): Promise<S> => {
      const state = await inner(ctx);
      this.activeTab = state.tabs.find((t) => t.active)?.tab_id ?? this.activeTab;
      // A tab now showing a different page, or gone, loses its refs.
      for (const [tab, catalogue] of this.refs) {
        const now = state.tabs.find((t) => t.tab_id === tab);
        if (!now || (catalogue.url !== undefined && pageKey(now.url) !== catalogue.url)) this.refs.delete(tab);
      }
      this.observePageText('browser_state', pageSuppliedText(state), { member: 'browser_state', input: {}, toolUse: ctx.toolUse });
      return state;
    };
  }

  /** The tab a call acts on: the SDK's resolved `tabId`, else the model's `tab_id`, else the reported active tab. */
  private resolveTab(ctx: ToolsetConfirmContext): string | undefined {
    if (ctx.tabId) return ctx.tabId;
    const asked = asRecord(ctx.input).tab_id;
    if (typeof asked === 'string' && asked) return asked;
    return this.activeTab;
  }

  /** Record a `read_page` / `find` result against the tab and page it read. */
  private recordRefs(ctx: ToolsetConfirmContext, name: string, text: string): void {
    const tab = this.resolveTab(ctx);
    if (tab === undefined) return; // unknown tab: record nothing, so clicks stay unresolved
    const url = pageKey(ctx.tabURL);
    const parsed = parseRefCatalogue(text);
    const fullRead = name === 'read_page' && !asRecord(ctx.input).ref;
    const current = this.refs.get(tab);
    if (fullRead || !current || current.url !== url) {
      this.refs.set(tab, { url, entries: parsed });
      return;
    }
    for (const [k, v] of parsed) current.entries.set(k, v);
  }

  /** Resolve a ref only in the catalogue of the tab the click targets, and only for the same page. */
  private lookupRef(ctx: ToolsetConfirmContext, ref: string): { role: string; label: string } | undefined {
    const tab = this.resolveTab(ctx);
    if (tab === undefined) return undefined;
    const catalogue = this.refs.get(tab);
    if (!catalogue) return undefined;
    const url = pageKey(ctx.tabURL);
    if (catalogue.url !== undefined && url !== undefined && catalogue.url !== url) return undefined;
    return catalogue.entries.get(ref);
  }

  /** Taint on page-supplied text the model will read, and scan it for the audit row. */
  private observePageText(source: string, parts: string[], callCtx: ToolsetConfirmContext): void {
    if (parts.length === 0) return;
    this.tainted = true;
    const scan = scanToolResponse(`toolset:${this.toolset}:${source}`, parts.join('\n'), 'advisory');
    this.emit({
      kind: 'result',
      ctx: callCtx,
      verdict: this.classify(callCtx),
      outcome: 'scanned',
      scanClean: scan.clean,
      scanIndicators: scan.threatIndicators,
    });
  }

  /** The URL check for the driver's request-interception hook. */
  isUrlAllowed(url: string): boolean {
    return checkUrl(url, this.allowlist).allowed;
  }

  /**
   * Wrap the SDK's `execute`. Call from the driver's override:
   *   execute(ctx, name, input) { return guard.execute(ctx, name, input, (c, n, i) => super.execute(c, n, i)); }
   * `ctx` is the SDK's `BetaToolsetCallContext`; the tab and the approved bytes
   * come from what `confirm` recorded for the same call.
   */
  async execute<C extends ToolsetCallContext, N extends string, I, R>(
    ctx: C,
    name: N,
    input: I,
    next: ToolsetExecuteNext<C, N, I, R>,
  ): Promise<R> {
    // Pre: the SDK re-checks nothing after confirm; we check the bytes match.
    // The key never involves the input, so changed bytes cannot reach a fresh key.
    const hash = hashInput(name, input);
    const key = confirmKey(ctx.toolUse?.id, name);
    const seen = this.confirmed.get(key);
    const callCtx: ToolsetConfirmContext = {
      member: name,
      input,
      tabURL: seen?.tabURL,
      tabId: seen?.tabId,
      toolUse: ctx.toolUse,
    };
    this.confirmed.delete(key);
    if (seen === undefined || seen.inputHash !== hash) {
      const verdict = this.classify(callCtx);
      const signal = seen === undefined ? 'unconfirmed' : 'mutated_input';
      this.emit({ kind: 'call', ctx: callCtx, verdict: { ...verdict, signals: [...verdict.signals, signal] }, outcome: this.mode === 'enforce' ? 'refused' : 'observed' });
      if (this.mode === 'enforce') {
        throw new this.ErrorCtor(seen === undefined
          ? 'blocked: this action was not approved'
          : 'blocked: the action changed after it was approved');
      }
    }

    const result = await next(ctx, name, input);

    // Post: a navigation ends the page lifetime of the tab it ran in.
    if (name === 'navigate' || name === 'close_tab') {
      const tab = this.resolveTab(callCtx);
      if (tab === undefined) this.refs.clear();
      else this.refs.delete(tab);
    }
    // Post: a tab record's title and URL are page-supplied and reach the model.
    if (PAGE_STATE_MEMBERS.has(name)) {
      this.observePageText(name, pageSuppliedText(result), callCtx);
    }
    // Post: every read taints; text reads are scanned; the ref catalogue updates.
    if (READING_MEMBERS.has(name)) {
      this.tainted = true;
      if (TEXT_RESULT_MEMBERS.has(name) && typeof result === 'string') {
        if (name === 'read_page' || name === 'find') this.recordRefs(callCtx, name, result);
        const scan = scanToolResponse(`toolset:${this.toolset}:${name}`, result, this.mode === 'enforce' ? 'enforce' : 'advisory');
        const verdict = this.classify(callCtx);
        const neutralised = this.mode === 'enforce' && scan.sanitisedContent !== null;
        this.emit({
          kind: 'result',
          ctx: callCtx,
          verdict,
          outcome: neutralised ? 'neutralised' : 'scanned',
          scanClean: scan.clean,
          scanIndicators: scan.threatIndicators,
        });
        // A text member's declared result type includes `string`.
        if (neutralised) return scan.sanitisedContent as R;
      } else {
        const verdict = this.classify(callCtx);
        this.emit({ kind: 'result', ctx: callCtx, verdict, outcome: 'scanned', scanClean: true, scanIndicators: [] });
      }
    }
    return result;
  }

  // ── Audit ──

  private emit(args: {
    kind: ToolsetAuditEvent['kind'];
    ctx: ToolsetConfirmContext;
    verdict: ToolsetVerdict;
    outcome: ToolsetAuditEvent['outcome'];
    hostAnswer?: boolean;
    scanClean?: boolean;
    scanIndicators?: string[];
  }): void {
    if (!this.sink) return;
    const { ctx, verdict } = args;
    const input = asRecord(ctx.input);
    let host = hostOf(ctx.tabURL);
    if ((ctx.member === 'navigate' || ctx.member === 'new_tab') && typeof input.url === 'string') {
      host = hostOf(input.url) ?? host;
    }
    let elementRole: string | undefined;
    let elementLabel: string | undefined;
    const roleSignal = verdict.signals.find((s) => s.startsWith('role:'));
    if (roleSignal) {
      elementRole = roleSignal.slice(5);
      const m = verdict.card.match(/labelled "((?:[^"\\]|\\.)*)"/);
      if (m) elementLabel = m[1];
    }
    const event: ToolsetAuditEvent = {
      kind: args.kind,
      toolset: this.toolset,
      member: ctx.member,
      mode: this.mode,
      decision: verdict.decision,
      effects: verdict.effects,
      signals: verdict.signals,
      tainted: verdict.tainted,
      requestedBy: this.requestedBy,
      host,
      elementRole,
      elementLabel,
      inputHash: verdict.inputHash,
      outcome: args.outcome,
      hostAnswer: args.hostAnswer,
      scanClean: args.scanClean,
      scanIndicators: args.scanIndicators,
      at: this.now(),
    };
    try {
      this.sink(event);
    } catch {
      /* the audit sink must never affect the action */
    }
  }
}
