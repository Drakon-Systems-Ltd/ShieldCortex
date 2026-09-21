/**
 * Credential Leak Detection — Layer 6
 *
 * Detects credentials, secrets, and sensitive tokens accidentally
 * persisted in AI agent memory writes. Supports known API key formats,
 * generic secrets, private keys, connection strings, environment
 * variable patterns, and high-entropy string heuristics.
 */

import {
  ALL_CREDENTIAL_PATTERNS,
  type CredentialPattern,
  type CredentialType,
  type CredentialSeverity,
} from './patterns.js';
import { extractHighEntropyTokens, isWellKnownNonSecret } from './entropy.js';

// ── Public Types ──

export interface CredentialFinding {
  type: CredentialType;
  provider?: string;
  confidence: number;
  severity: CredentialSeverity;
  /** Redacted version showing first/last 4 chars */
  match: string;
  /** Char offset in content */
  position: number;
  action: 'blocked' | 'warned' | 'logged';
  /**
   * #543 — set when the value only matched after separators (whitespace,
   * zero-width / format characters) were collapsed out of the text. `position`
   * and the redaction range still refer to the ORIGINAL content and span the
   * inserted separators too.
   */
  evasion?: 'separator_split';
}

export interface CredentialScanResult {
  leaked: boolean;
  findings: CredentialFinding[];
  redactedContent?: string;
}

export interface CredentialDetectionConfig {
  enabled: boolean;
  blockOnCritical: boolean;
  blockOnHigh: boolean;
  warnOnMedium: boolean;
  customPatterns: CredentialPattern[];
  allowlist: string[];
}

export const DEFAULT_CREDENTIAL_CONFIG: CredentialDetectionConfig = {
  enabled: true,
  blockOnCritical: true,
  blockOnHigh: true,
  warnOnMedium: true,
  customPatterns: [],
  allowlist: [],
};

// ── Redaction ──

/**
 * Redact a matched secret, showing first and last 4 chars.
 * Very short matches get fully redacted.
 */
function redactMatch(value: string, type: CredentialType): string {
  if (value.length <= 12) return `[REDACTED-${type}]`;
  return `${value.slice(0, 4)}...${value.slice(-4)}`;
}

/**
 * Determine action based on severity and config.
 */
function actionForSeverity(
  severity: CredentialSeverity,
  config: CredentialDetectionConfig,
): 'blocked' | 'warned' | 'logged' {
  if (severity === 'critical' && config.blockOnCritical) return 'blocked';
  if (severity === 'high' && config.blockOnHigh) return 'blocked';
  if (severity === 'medium' && config.warnOnMedium) return 'warned';
  return 'logged';
}

/**
 * Check if a match is in the allowlist.
 * Allowlist entries can be literal prefixes or glob-like patterns.
 */
function isAllowlisted(value: string, allowlist: string[]): boolean {
  for (const entry of allowlist) {
    if (value.startsWith(entry) || value === entry) return true;
  }
  return false;
}

/**
 * #205 — documentation / template placeholders are not secrets.
 *
 * ENV_SECRET patterns match `API_KEY=…` assignments at 0.82–0.85 confidence.
 * Without a denylist they fire on every README (`your-api-key-here`,
 * `changeme_in_production`, `replace-with-your-token`).
 *
 * Conservative on purpose (dual-review #280): only obvious template language.
 * Do NOT match bare words like "change"/"replace"/"set" inside real values
 * (`Spring-Change-2024`, `my-secret-prod-7f3a`). Prefer exacts + anchored
 * phrase shapes with length caps.
 */
export function isDocumentationPlaceholder(value: string): boolean {
  const raw = value.trim();
  const v = raw.toLowerCase();
  if (!v) return true;

  // Exact common placeholders (whole value)
  const exact = new Set([
    'changeme',
    'change_me',
    'changeme!',
    'password',
    'secret',
    'secret123',
    'password123',
    'admin',
    'root',
    'todo',
    'fixme',
    'fix_me',
    'example',
    'sample',
    'dummy',
    'placeholder',
    'redacted',
    'xxx',
    'xxxx',
    'xxxxxxxx',
    '<password>',
    '<secret>',
    '<token>',
    '<api_key>',
    'your_password',
    'your_secret',
    'your_token',
    'your_api_key',
    'your-api-key',
    'your-api-key-here',
    'your_api_key_here',
    'insert_here',
    'insert-here',
    'replace-with-your-token',
    'replace_with_your_token',
    'replace-with-your-secret',
    'replace_with_your_secret',
    'replace-with-your-password',
    'changeme_in_production',
    'change_me_in_production',
    'changeme-in-production',
  ]);
  if (exact.has(v)) return true;

  // Angle-bracket template tokens: <your-token>, <API_KEY>
  if (/^<[^>]{1,40}>$/.test(raw)) return true;

  // Pure mask runs
  if (/^(x{4,}|\*{4,}|\.{4,}|-{4,}|_{4,})$/i.test(raw)) return true;
  if (/^(xxx+|yyy+|zzz+|asdf|qwerty)([0-9!@._-]*)?$/i.test(v)) return true;

  // Anchored "your/my … key/secret/token/password" whole-value templates.
  // Requires a template tail (here|example|placeholder|xxx|sample) OR ends
  // exactly at the credential noun — not "my-secret-prod-abc123".
  if (
    /^(your|my)[-_ ]+(api[-_ ]?key|secret|token|password|passwd|key)([-_ ]+(here|example|sample|placeholder|xxx+))?$/i.test(v)
  ) {
    return true;
  }

  // Anchored "replace/insert … with your …" whole-value templates only.
  if (
    v.length < 48
    && /^(replace|insert)[-_ ]+(with[-_ ]+)?(your|my|a|the)[-_ ]+(api[-_ ]?key|secret|token|password|key|value)([-_ ]*(here)?)?$/.test(v)
  ) {
    return true;
  }

  // changeme / change_me as a PREFIX of a short template (changeme_in_production)
  if (/^change[-_]?me([-_].{0,24})?$/.test(v) && v.length < 40) return true;

  // *_in_production / *_here when the stem is a known placeholder word
  if (
    /^(change[-_]?me|password|secret|token|api[-_]?key|example|sample|dummy|placeholder|todo|fixme)[-_](in[-_]production|here|example|sample|placeholder|todo)$/.test(v)
    && v.length < 48
  ) {
    return true;
  }

  return false;
}

/**
 * Expand a match span to the full contiguous identifier token it sits in, then
 * test it against the well-known-non-secret allowlist (git SHA / UUID).
 *
 * Generic hex patterns (e.g. the 32-hex "Azure" rule) match a SUBSTRING of a
 * 40-hex commit SHA, so checking only the captured value misses it — we must
 * look at the surrounding contiguous run. The token boundary is the usual
 * credential alphabet ([A-Za-z0-9-]); we deliberately do NOT cross `/`, `+`,
 * `=` etc. so a real base64 secret that merely contains a hex-looking run is
 * not whitelisted.
 */
function matchIsWellKnownNonSecret(content: string, start: number, end: number): boolean {
  const tokenChar = /[A-Za-z0-9-]/;
  let s = start;
  let e = end;
  // The longest token the allowlist accepts is 64 characters, so the walk
  // stops as soon as the token is longer than that: a run of 80,000
  // alphanumerics (space-separated keys in the collapsed view, #544 F4) used
  // to be walked whole for every match, which made the pass quadratic.
  while (s > 0 && tokenChar.test(content[s - 1])) {
    s--;
    if (e - s > MAX_WELL_KNOWN_TOKEN) return false;
  }
  while (e < content.length && tokenChar.test(content[e])) {
    e++;
    if (e - s > MAX_WELL_KNOWN_TOKEN) return false;
  }
  return isWellKnownNonSecret(content.slice(s, e));
}

/** SHA-256 hex is the longest form `isWellKnownNonSecret` accepts. */
const MAX_WELL_KNOWN_TOKEN = 64;

// ── #543: separator-split evasion ──
//
// The provider patterns match contiguous text only. Writing a key as
// `sk-T3st K3yA bCdE …` — or splitting it with a tab, newline, NBSP or a
// zero-width character — produced zero findings, yet removing the separators
// rebuilds the identical value. The fix is NOT to strip whitespace and rescan
// (that loses match positions, so the redaction range would land on the wrong
// bytes) but to scan a collapsed VIEW that remembers where each surviving
// character came from, and act on the original span.

/**
 * Characters treated as separators: every Unicode whitespace (`\s`), the soft
 * hyphen, zero-width space / non-joiner / joiner, the word joiner and the BOM
 * (zero-width no-break space). Visible punctuation is deliberately excluded —
 * `sk-abc.def` reads as a different value; `sk-abc def` does not.
 */
const SEPARATOR_CHAR = /[\s­​-‍⁠﻿]/;

interface CollapsedView {
  /** `content` with every separator removed. */
  text: string;
  /** `map[i]` is the offset in the original content of `text[i]`. */
  map: number[];
}

/**
 * Build the separator-collapsed view. Returns null when the content has no
 * separators at all — the direct pass has already seen everything.
 */
function buildCollapsedView(content: string): CollapsedView | null {
  const chars: string[] = [];
  const map: number[] = [];
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (SEPARATOR_CHAR.test(ch)) continue;
    chars.push(ch);
    map.push(i);
  }
  if (chars.length === content.length) return null;
  return { text: chars.join(''), map };
}

/**
 * Precision gate for the collapsed pass only. Collapsing whitespace turns
 * ordinary prose into key-shaped runs — `ASIA PACIFIC REGIONAL SALES` becomes
 * `ASIA` + 21 capitals, `key-value pairs are stored …` becomes the Mailgun
 * shape, a line ending in `sk-` glues onto the next sentence. Issued key
 * material of every format the patterns cover carries digits as well as
 * letters (the odds of a 16-char base-32 body with no digit at all are ~4%;
 * for the base-62 bodies they are negligible), while prose has letters only.
 * Requiring both classes in the collapsed value keeps the direct pass exactly
 * as it was and stops the collapsed pass from firing on words.
 */
function collapsedValueLooksLikeKeyMaterial(value: string): boolean {
  return /[0-9]/.test(value) && /[A-Za-z]/.test(value);
}

type MatchedRange = {
  start: number;
  end: number;
  replacement: string;
  /** Severity of the finding that produced the range (pattern layer only). */
  severity?: CredentialSeverity;
};

const SEVERITY_RANK: Record<CredentialSeverity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/**
 * Patterns that consult whitespace themselves (`\s*` around an `=`, a
 * `[^\s"']+` value class, `BEGIN\s+RSA`) define their own token boundaries;
 * collapsing the separators out from under them changes what they mean, so
 * they take no part in the collapsed pass. The provider key formats — the
 * subject of #543 — are all contiguous-alphabet patterns.
 */
function patternConsultsWhitespace(pattern: CredentialPattern): boolean {
  return /\\s/.test(pattern.regex.source);
}

/**
 * A run of characters between separators that reads as key material rather
 * than as a word: it carries a digit, a non-letter (`_ - . / + =`), or mixed
 * case that is not merely Capitalised. `ASIA`, `PACIFIC`, `end`, `Store` are
 * words; `Ab1C`, `sk-`, `WxYz`, `4B1T` are not.
 */
function fragmentLooksLikeKeyMaterial(fragment: string): boolean {
  if (/[0-9]/.test(fragment)) return true;
  if (/[^A-Za-z]/.test(fragment)) return true;
  if (/[A-Z]/.test(fragment) && /[a-z]/.test(fragment) && !/^[A-Z][a-z]+$/.test(fragment)) return true;
  return false;
}

/**
 * Letter pairs that English words almost never contain: the pairs making up
 * the rarest 1% of adjacent-letter occurrences in a 100k-word list (310 of the
 * 676). 93% of dictionary words hold none of them; a random three-letter run
 * avoids them 29% of the time, a six-letter run 5%. Keyed by first letter.
 */
const RARE_BIGRAMS: Record<string, string> = {
  a: 'ajoq',
  b: 'cdfghjkmnpqtvwxz',
  c: 'bdfgjmnpqvwxz',
  d: 'cfhjkpqtxz',
  e: 'j',
  f: 'bcdghjkmnpqvwxz',
  g: 'bcdfjkpqtvwxz',
  h: 'bcdfghjkpqvxz',
  i: 'hijwy',
  j: 'bcdfghjklmnpqrstvwxyz',
  k: 'bcdfgjkmpqtvwxz',
  l: 'hjqrwxz',
  m: 'cdfghjklqrtvwxz',
  n: 'xz',
  o: 'jq',
  p: 'bcdfgjkmnqvwxz',
  q: 'abcdefghijklmnopqrstvwxyz',
  r: 'jqxz',
  s: 'dgjrvxz',
  t: 'dgjkpqvx',
  u: 'hjquvwxy',
  v: 'bcdfghjklmnpqrstuvwxyz',
  w: 'bcdfgjkmpqtuvwxyz',
  x: 'bdfghjklmnoqrsuvwxyz',
  y: 'fghjkquvwxyz',
  z: 'bcdfghjklmnpqrstuvwxy',
};

/**
 * A fragment that reads as an English word: three or more letters, one case or
 * Capitalised, and no letter pair that English does not use. `REGIONAL`,
 * `legacy`, `Store` are words; `QXZJ`, `IOSF`, `Ab1C`, `sk-` are not.
 */
function fragmentReadsAsProse(fragment: string): boolean {
  if (fragment.length < 3 || fragmentLooksLikeKeyMaterial(fragment)) return false;
  const lower = fragment.toLowerCase();
  for (let i = 0; i < lower.length - 1; i++) {
    if (RARE_BIGRAMS[lower[i]]?.includes(lower[i + 1])) return false;
  }
  return true;
}

/**
 * Two-letter English function words. A fragment this short cannot be judged
 * by its letter pairs, so a small closed list stands in: `BY`, `in`, `To` read
 * as words; `VS`, `Qx`, `AB` do not.
 */
const FUNCTION_WORDS_2 = new Set([
  'of', 'by', 'in', 'to', 'on', 'at', 'is', 'as', 'or', 'an',
  'we', 'it', 'be', 'so', 'no', 'up', 'us', 'do', 'go', 'my', 'me', 'if',
]);

/**
 * Short period / ordinal tokens that headings carry next to words: a year or
 * a count (`2026`, `7`), a period designator with a number (`Q1`, `H2`, `W12`,
 * `M3`, `FY26`, `CY2026`, `WK4`, `fy26`), or the number first (`1H`, `3Q`,
 * `1st`, `4TH`). The designator is a closed list in one case — `AU6`, `N6`,
 * `aB7` are not periods. Measured against attacker-chosen splits of random
 * AWS ids, letting ANY one or two letters carry a number (`[A-Za-z]{1,2}\d{1,2}`)
 * left 14% of ids dismissible; the closed list leaves 1.3%.
 */
const PERIOD_TOKEN = /^(?:\d{1,4}|(?:[QHWMYDPT]|FY|CY|WK|[qhwmydpt]|fy|cy|wk)\d{1,4}|\d{1,2}(?:[QHWMYD]|ST|ND|RD|TH|[qhwmyd]|st|nd|rd|th))$/;

type FragmentClass = 'word' | 'period' | 'letters' | 'other';

/** Letters only, in one case or Capitalised: `GDP`, `HR`, `Headcount`, `q`. */
const LETTERS_ONLY = /^(?:[A-Z]+|[a-z]+|[A-Z][a-z]+)$/;

/**
 * Classify one whole fragment (the run between two separators) for the prose
 * decision below. WORD: reads as an English word (`fragmentReadsAsProse`), or
 * a two-letter function word in one case or Capitalised. PERIOD: a short
 * period token. LETTERS: letters only, one case or Capitalised, but not a
 * word by the letter-pair test — an abbreviation (`GDP`, `HR`), a word with a
 * pair English rarely uses (`BUDGET`, `PROJECT`), or a lone letter. OTHER:
 * everything else — a digit-and-letter mix, punctuation, mixed case.
 */
function classifyFragment(fragment: string): FragmentClass {
  if (fragmentReadsAsProse(fragment)) return 'word';
  if (fragment.length === 2) {
    const lower = fragment.toLowerCase();
    if (
      FUNCTION_WORDS_2.has(lower)
      && (fragment === lower || fragment === fragment.toUpperCase() || fragment === lower[0].toUpperCase() + lower[1])
    ) {
      return 'word';
    }
  }
  if (PERIOD_TOKEN.test(fragment)) return 'period';
  if (LETTERS_ONLY.test(fragment)) return 'letters';
  return 'other';
}

/**
 * Number of leading characters a pattern matches literally: `sk-proj-` is 8,
 * `A[KS]IA…` is 1, `(?<!…)key-…` is 4, `[a-f0-9]{8}-…` is 0. A leading
 * look-around is skipped; the count stops at the first class, group,
 * alternation, wildcard or quantified character. Under-counting only makes
 * the prose dismissal below rarer, so the parser errs that way.
 */
function literalPrefixLength(source: string): number {
  let i = 0;
  while (/^\(\?<?[=!]/.test(source.slice(i))) {
    const close = source.indexOf(')', i);
    if (close === -1) return 0;
    i = close + 1;
  }
  let length = 0;
  while (i < source.length) {
    const ch = source[i];
    let next = i + 1;
    if (ch === '\\') {
      const escaped = source[i + 1];
      // `\.` `\-` `\/` are literals; `\d` `\w` `\1` `\u…` are not.
      if (escaped === undefined || /[A-Za-z0-9]/.test(escaped)) break;
      next = i + 2;
    } else if (/[[\]()|.^$*+?{}]/.test(ch)) {
      break;
    }
    if (/[*+?{]/.test(source[next] ?? '')) break;
    length++;
    i = next;
  }
  return length;
}

interface CompiledPattern {
  /** Global copy for discovery over the collapsed text. */
  global: RegExp;
  /** Sticky copy for exact-span checks; compiled once per pattern (#544 B3). */
  sticky: RegExp;
  prefixLength: number;
  /**
   * Fixed length in one letter case (`A[KS]IA[0-9A-Z]{16}`): no open-ended
   * quantifier, and the letters it admits are upper OR lower, not both. Such
   * a pattern cuts a 20-character window out of any shouted heading, so its
   * collapsed hits are judged by the window's alignment (see `hitReadsAsProse`).
   */
  fixedSingleCase: boolean;
}

const COMPILED_PATTERNS = new WeakMap<CredentialPattern, CompiledPattern>();

/** No `{n,}` / `{n,m}` / `+` / `*` outside look-arounds, and not both `a-z` and `A-Z`. */
function isFixedSingleCase(source: string): boolean {
  const body = source.replace(/\(\?<?[=!][^)]*\)/g, '');
  if (/\{\d+,\d*\}/.test(body) || /(?<!\\)[+*]/.test(body)) return false;
  return !(/a-z/.test(body) && /A-Z/.test(body));
}

function compilePattern(pattern: CredentialPattern): CompiledPattern {
  let compiled = COMPILED_PATTERNS.get(pattern);
  if (!compiled) {
    const flags = pattern.regex.flags.replace(/[gy]/g, '');
    compiled = {
      global: new RegExp(pattern.regex.source, flags + 'g'),
      sticky: new RegExp(pattern.regex.source, flags + 'y'),
      prefixLength: literalPrefixLength(pattern.regex.source),
      fixedSingleCase: isFixedSingleCase(pattern.regex.source),
    };
    COMPILED_PATTERNS.set(pattern, compiled);
  }
  return compiled;
}

/**
 * How far before a span the exact-span check lets a lookbehind see. No
 * pattern looks back more than one character; 256 is generous and bounded.
 */
const LOOKBEHIND_WINDOW = 256;

/** Does `pattern` match `text` starting exactly at `start` and ending exactly at `end`? */
function matchesSpanExactly(compiled: CompiledPattern, text: string, start: number, end: number): RegExpExecArray | null {
  // The window keeps a bounded run of characters BEFORE `start` so lookbehinds
  // see context, and makes `end` the end of input so a greedy quantifier stops
  // there. Slicing from 0 made every check O(position) (#544 B3).
  const base = Math.max(0, start - LOOKBEHIND_WINDOW);
  const window = text.slice(base, end);
  const sticky = compiled.sticky;
  sticky.lastIndex = start - base;
  const m = sticky.exec(window);
  return m !== null && m.index === start - base && m[0].length === end - start ? m : null;
}

/**
 * A fragment of a collapsed hit: `[cs, ce)` is the part inside the hit,
 * `[fullCs, fullCe)` the whole word it belongs to. They differ only for the
 * first and last fragment when the hit starts or ends mid-word (`SALE|S`):
 * prose-ness is judged on the whole word, counts use the part inside the hit.
 *
 * The word is extended outward across alphanumerics only, never across the
 * punctuation that wraps it (`"…"`, `**…**`, `(…)`, a trailing `:` or `,`,
 * a JSON string's closing quote). Extending across the whole run between
 * separators made `"ASIA Q3 GDP GROWTH FORECAST"` a key while the bare
 * heading was clean: the boundary word became `FORECAST"`, which is neither a
 * word nor letters-only (#544 F3). The hit's own characters are untouched —
 * a `-` or `_` inside a key prefix stays inside its fragment.
 */
interface Fragment { cs: number; ce: number; fullCs: number; fullCe: number }

/** Longest run still judged as a possible word; beyond it a fragment is OTHER. */
const MAX_WORD_FRAGMENT = 48;

const WORD_CHAR = /[A-Za-z0-9]/;

function fragmentsOf(view: CollapsedView, cStart: number, cEnd: number): Fragment[] {
  const { text, map } = view;
  const frags: Fragment[] = [];
  for (let c = cStart; c < cEnd; c++) {
    const last = frags[frags.length - 1];
    if (last && map[c] === map[c - 1] + 1) last.ce = c + 1;
    else frags.push({ cs: c, ce: c + 1, fullCs: c, fullCe: c + 1 });
  }
  if (frags.length === 0) return frags;
  for (const f of frags) f.fullCe = f.ce;
  const first = frags[0];
  while (
    first.fullCs > 0
    && first.ce - first.fullCs <= MAX_WORD_FRAGMENT
    && map[first.fullCs] === map[first.fullCs - 1] + 1
    && WORD_CHAR.test(text[first.fullCs - 1])
  ) first.fullCs--;
  const last = frags[frags.length - 1];
  while (
    last.fullCe < text.length
    && last.fullCe - last.cs <= MAX_WORD_FRAGMENT
    && map[last.fullCe] === map[last.fullCe - 1] + 1
    && WORD_CHAR.test(text[last.fullCe])
  ) last.fullCe++;
  return frags;
}

function fullText(text: string, f: Fragment): string {
  return text.slice(f.fullCs, f.fullCe);
}

/**
 * Does a collapsed hit read as a heading or a sentence rather than a key?
 * Two structural rules, chosen by the shape of the pattern; neither consults
 * a vocabulary beyond the letter-pair test in `fragmentReadsAsProse`.
 *
 * Open-ended or mixed-case patterns (`sk-…{20,}`, `AIza` + 35 of base-62,
 * `ghp_…`), the strict rule (#544 B4):
 *
 *   - every fragment must be a WORD or a PERIOD token — one fragment that is
 *     neither (a lone letter, an abbreviation, `4K2M`, `Ab1C`) and the hit is
 *     a key. A fragment that lies wholly inside the pattern's literal prefix
 *     (`sk-proj-`) is exempt;
 *   - at least one WORD of three or more letters must sit beyond that prefix;
 *   - WORD characters must make up half the hit or more.
 *
 * The decision cannot be diluted: filler around a split key leaves the key's
 * own fragments in the hit, and a random mixed-case body does not partition
 * into words. Measured with the exact attacker-optimal split (dynamic
 * programme over every partition, plus a glued letter at either end) in
 * `scripts/lab/credential-split-evasion.mts`: 0 of 20,000 random `sk-` and
 * 0 of 20,000 `AIza` bodies can be dismissed.
 *
 * Fixed-length single-case patterns (`A[KS]IA[0-9A-Z]{16}`), the alignment
 * rule. Such a pattern cuts a window of fixed width out of any shouted
 * heading, and with a `Q3` or an `FY26` in the window the strict rule has to
 * decide whether `GDP`, `PROJECT` or `HEADCOUNT` is a word — a vocabulary
 * question with no structural answer (round 4 of #544). So the window itself
 * is judged instead:
 *
 *   - a hit that starts or ends inside a letters-only word (`FOREC|AST`,
 *     `EUR|ASIA`) is a heading cut mid-word, not a key. The word is the
 *     alphanumeric run around the boundary, so quoting, bold or bracketing the
 *     heading, or ending it with `:` or `,`, changes nothing (#544 F3);
 *   - an aligned hit is a key only if some fragment beyond the literal prefix
 *     is key material — mixes letters and digits, is punctuated or mixed
 *     case, or is a digit run that is no period token — or the hit holds two
 *     or more lone letters (a key split after every character).
 *
 * A split key keeps its own fragments, and a fragment of a random base-32 body
 * is key material unless the split happens to isolate letters from digits.
 * Measured (same script, 19,312 random AWS ids that hold a digit): a key split
 * after every 1, 4, 5 or 8 characters, once in the middle, or across newlines
 * is found for 99.9–100% of ids; split after every 3, for 98.3%; after every
 * 2, for 89.7%. On the generated heading corpus in the #543 test (6,000
 * headings led by `ASIA`/`AKIA`, all-caps, Title and lower case, each also
 * wrapped thirteen ways: double or single quotes, `**`, `_`, backticks,
 * parentheses, brackets, a `# ` or `- ` prefix, a trailing `:` `.` `,`, and
 * as a JSON string value; 78,000 texts) the rule fires on none. The price
 * of judging the boundary word on its letters is that a delimiter no longer
 * rescues an id whose fragments all read as words or period tokens:
 * comma-delimited every-4 splits went from 100% to 99.89% found, the plain
 * space rate. Counting the delimiter as evidence would fire on 1,564 of the
 * 78,000 wrapped headings, so it is not done.
 *
 * Residual, by design and measured: an attacker who chooses the split points
 * AND glues one letter onto either end of the id evades this rule for every
 * id, and one who only inserts whitespace evades it for 94.2% of ids (the
 * strict rule, which cannot clear the heading corpus, is evaded for 1.7% but
 * blocks about one all-caps heading in ten of that corpus). The
 * collapsed pass therefore catches an AWS id that was wrapped, tabulated or
 * spaced out — not one hidden by an adversary who knows this rule. A heading
 * whose abbreviation carries a digit (`B2B`, `B2C`, `3PL`) is key material
 * by this rule and still fires when the window lands on it.
 */
function hitReadsAsProse(text: string, frags: Fragment[], cStart: number, cEnd: number, compiled: CompiledPattern): boolean {
  const prefixEnd = cStart + compiled.prefixLength;

  if (compiled.fixedSingleCase) {
    const first = frags[0];
    const last = frags[frags.length - 1];
    if (first.cs > first.fullCs && LETTERS_ONLY.test(fullText(text, first))) return true;
    if (last.ce < last.fullCe && LETTERS_ONLY.test(fullText(text, last))) return true;
    let lone = 0;
    for (const f of frags) {
      if (f.ce <= prefixEnd) continue;
      const full = fullText(text, f);
      const cls = classifyFragment(full);
      if (cls === 'other') return false;
      if (cls === 'letters' && full.length === 1 && ++lone >= 2) return false;
    }
    return true;
  }

  let wordChars = 0;
  let bodyWord = false;
  for (const f of frags) {
    const cls = classifyFragment(fullText(text, f));
    const inHit = f.ce - f.cs;
    if (cls === 'word') {
      wordChars += inHit;
      if (inHit >= 3 && f.cs >= prefixEnd) bodyWord = true;
    } else if (cls !== 'period' && f.ce > prefixEnd) {
      return false;
    }
  }
  return bodyWord && wordChars * 2 >= cEnd - cStart;
}

/** Upper bound on exact-span checks per side while trimming a hit (#544 B3). */
const MAX_TRIM_ATTEMPTS = 32;

interface CollapsedCandidate {
  pattern: CredentialPattern;
  compiled: CompiledPattern;
  cStart: number;
  cEnd: number;
  secretValue: string;
  /** Original-content span. */
  start: number;
  end: number;
}

/**
 * Turn a raw collapsed hit into a candidate finding, or null.
 *
 * Collapsing glues a key to the words around it, and an open-ended pattern
 * (`{20,}`) happily swallows `end` in `sk-… end`. So the hit is trimmed at
 * both ends, innermost prose fragment first (#544 B2): within the trailing
 * (resp. leading) run of fragments that hold no key material, find the
 * fragment nearest the key that reads as a word and cut there; one- and
 * two-letter fragments inward of it (`U v W x` in a key split every
 * character) are the key's own tail and stay. A cut is accepted only if the
 * pattern still matches the remaining span exactly and the value still passes
 * the length and key-material gates; otherwise the next word outward is
 * tried, and if none works the hit is left whole. Trimming never turns a
 * finding into no finding. Fragments in the middle are never dropped — an
 * attacker chooses the split points, and the only thing they cannot choose is
 * the key's own characters.
 *
 * A hit reduced to a single contiguous fragment is the direct pass's business
 * and is dropped here.
 */
function validateCandidate(
  view: CollapsedView,
  pattern: CredentialPattern,
  compiled: CompiledPattern,
  cfg: CredentialDetectionConfig,
  cStart: number,
  cEnd: number,
  exact: RegExpExecArray,
): CollapsedCandidate | null {
  const { text, map } = view;
  let frags = fragmentsOf(view, cStart, cEnd);
  if (frags.length < 2) return null;

  const isKeyMaterial = (f: Fragment) => fragmentLooksLikeKeyMaterial(fullText(text, f));
  const isProse = (f: Fragment) => fragmentReadsAsProse(fullText(text, f));
  const valueGates = (m: RegExpExecArray): boolean => {
    const v = m[1] ?? m[0];
    return !(pattern.minLength && v.length < pattern.minLength)
      && collapsedValueLooksLikeKeyMaterial(v)
      && (!pattern.collapsedValuePattern || pattern.collapsedValuePattern.test(v));
  };

  // Trailing trim.
  let k = frags.length;
  while (k > 1 && !isKeyMaterial(frags[k - 1])) k--;
  for (let i = k, attempts = 0; i < frags.length && attempts < MAX_TRIM_ATTEMPTS; i++) {
    if (!isProse(frags[i])) continue;
    attempts++;
    const newEnd = frags[i - 1].ce;
    const m = matchesSpanExactly(compiled, text, cStart, newEnd);
    if (m && valueGates(m)) {
      exact = m;
      cEnd = newEnd;
      frags = frags.slice(0, i);
      break;
    }
  }

  // Leading trim.
  let j = 0;
  while (j < frags.length - 1 && !isKeyMaterial(frags[j])) j++;
  for (let i = j - 1, attempts = 0; i >= 0 && attempts < MAX_TRIM_ATTEMPTS; i--) {
    if (!isProse(frags[i])) continue;
    attempts++;
    const newStart = frags[i + 1].cs;
    const m = matchesSpanExactly(compiled, text, newStart, cEnd);
    if (m && valueGates(m)) {
      exact = m;
      cStart = newStart;
      frags = frags.slice(i + 1);
      break;
    }
  }

  if (frags.length < 2) return null;

  const secretValue = exact[1] ?? exact[0];
  if (pattern.minLength && secretValue.length < pattern.minLength) return null;
  if (isAllowlisted(secretValue, cfg.allowlist)) return null;
  if (pattern.type === 'env_secret' && isDocumentationPlaceholder(secretValue)) return null;
  if (!collapsedValueLooksLikeKeyMaterial(secretValue)) return null;
  // A fact about issued values the discovery regex is looser than (AWS ids
  // are base-32). Collapsed pass only; the direct pass never consults it.
  if (pattern.collapsedValuePattern && !pattern.collapsedValuePattern.test(secretValue)) return null;
  if (hitReadsAsProse(text, frags, cStart, cEnd, compiled)) return null;
  // Git SHA / UUID with a separator inside is still a public identifier.
  // The token is only contiguous in the collapsed view, so test it there.
  if (matchIsWellKnownNonSecret(text, cStart, cEnd)) return null;

  return {
    pattern,
    compiled,
    cStart,
    cEnd,
    secretValue,
    start: map[cStart],
    end: map[cEnd - 1] + 1,
  };
}

/** First collapsed index in `[cStart, cEnd)` whose original offset is >= `at`. */
function collapsedIndexAtOrAfter(map: number[], cStart: number, cEnd: number, at: number): number {
  let lo = cStart;
  let hi = cEnd;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (map[mid] < at) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** First index in `sorted` (ascending by `key`) whose key is >= `at`. */
function lowerBound<T>(sorted: T[], key: (x: T) => number, at: number): number {
  let lo = 0;
  let hi = sorted.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (key(sorted[mid]) < at) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/**
 * "Is `[start, end)` covered whole by a recorded range of severity >= rank?"
 * answered in O(log n) (#544 round 4). Starts are discretised up front; one
 * Fenwick tree per severity level holds, per start, the furthest end recorded
 * at or before it, so a query is a prefix maximum over the levels that count.
 */
class CoverageIndex {
  private readonly starts: number[];
  private readonly trees: Int32Array[];

  constructor(starts: Iterable<number>) {
    this.starts = [...new Set(starts)].sort((a, b) => a - b);
    this.trees = Object.keys(SEVERITY_RANK).map(() => new Int32Array(this.starts.length + 1).fill(-1));
  }

  add(start: number, end: number, severity: CredentialSeverity): void {
    const tree = this.trees[SEVERITY_RANK[severity]];
    for (let i = lowerBound(this.starts, x => x, start) + 1; i < tree.length; i += i & -i) {
      if (tree[i] < end) tree[i] = end;
    }
  }

  covers(start: number, end: number, rank: number): boolean {
    const upto = lowerBound(this.starts, x => x, start + 1);
    for (let level = rank; level < this.trees.length; level++) {
      const tree = this.trees[level];
      for (let i = upto; i > 0; i -= i & -i) {
        if (tree[i] >= end) return true;
      }
    }
    return false;
  }
}

/**
 * Second pattern pass over the collapsed view. Each hit is mapped back to its
 * original span, which is what gets recorded (position) and redacted (range).
 *
 * Discovery runs every pattern over the collapsed text independently and
 * validates each hit (`validateCandidate`: trim, gates, prose dismissal). Two
 * rules apply against the direct pass during discovery: a direct range that
 * BEGINS where the run begins means the pattern layer already matched — and
 * redacts — a value here, so the run is left alone and scanning resumes after
 * that range (`sk-… customer123` redacts the key only; if what follows really
 * is the rest of the key, redacting the head has already destroyed it); and a
 * direct range that begins strictly inside the run says where a token starts,
 * so the run is cut there when the pattern still matches the cut span
 * (`sk-… and ghp_…` is two keys and a word, not one key). Both lookups bisect
 * the direct ranges sorted by start.
 *
 * Resolution then works over the whole candidate set (#544 B1):
 *
 *   (i)  a validated candidate's start is a token start: a candidate holding
 *        another pattern's candidate strictly inside it is cut at that start
 *        if the cut span still matches and re-validates; otherwise it stays
 *        whole. An open-ended pattern therefore cannot swallow a neighbour
 *        (`sk_test_… AIza…` is a Stripe key and a Google key). The inner
 *        starts are read off the candidates sorted by start, so the pass is
 *        linear in the candidates plus the containments, not quadratic;
 *   (ii) coverage suppression only ever goes downward: candidates are taken
 *        by severity, then length, and one is dropped only when an already
 *        accepted range of equal or higher severity covers it whole
 *        (`CoverageIndex`, logarithmic per candidate). Nothing already found
 *        — by the direct pass or here — is ever removed, so a lower-severity
 *        finding can never hide a higher one. Overlapping ranges are merged
 *        at redaction time.
 *
 * Measured on N AWS ids each split after every 4 characters (the round-4
 * reviewer's shape): 1k / 2k / 4k / 8k ids joined by ` | ` took 23 / 120 /
 * 393 / 2404 ms before this change and grow linearly after it (see the #543
 * test). Joined by a single space the whole input is one alphanumeric run in
 * the collapsed view, and the well-known-identifier check walked that run
 * whole for every hit: 800 / 1600 / 3200 ids took 415 / 1704 / 6551 ms. The
 * walk now stops past the longest token the allowlist accepts (#544 F4), and
 * that shape is linear too.
 */
function scanCollapsedView(
  view: CollapsedView,
  patterns: CredentialPattern[],
  cfg: CredentialDetectionConfig,
  findings: CredentialFinding[],
  matchedRanges: MatchedRange[],
): { findings: CredentialFinding[]; matchedRanges: MatchedRange[] } {
  const { text, map } = view;
  const candidates: CollapsedCandidate[] = [];
  const direct = [...matchedRanges].sort((a, b) => a.start - b.start || a.end - b.end);
  const directStart = (r: MatchedRange) => r.start;

  // ── Discovery ──
  for (const pattern of patterns) {
    if (patternConsultsWhitespace(pattern)) continue;

    const compiled = compilePattern(pattern);
    const regex = compiled.global;
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      if (match[0].length === 0) {
        regex.lastIndex++;
        continue;
      }

      const cStart = match.index;
      let cEnd = cStart + match[0].length;
      let exact: RegExpExecArray = match;
      const spanStart = map[cStart];
      const spanEnd = map[cEnd - 1] + 1;

      // Direct ranges starting at `spanStart`, then the first starting inside.
      let i = lowerBound(direct, directStart, spanStart);
      let anchored: MatchedRange | undefined;
      for (; i < direct.length && direct[i].start === spanStart; i++) {
        if (direct[i].end < spanEnd) anchored = direct[i];
      }
      if (anchored) {
        regex.lastIndex = collapsedIndexAtOrAfter(map, cStart, cEnd, anchored.end);
        continue;
      }

      if (i < direct.length && direct[i].start < spanEnd) {
        const cc = collapsedIndexAtOrAfter(map, cStart, cEnd, direct[i].start);
        const m = matchesSpanExactly(compiled, text, cStart, cc);
        if (m) {
          regex.lastIndex = cc;
          exact = m;
          cEnd = cc;
        }
      }

      const candidate = validateCandidate(view, pattern, compiled, cfg, cStart, cEnd, exact);
      if (candidate) candidates.push(candidate);
    }
  }

  // ── Resolution (i): cut at another pattern's token start ──
  const byStart = [...candidates].sort((a, b) => a.start - b.start);
  const candidateStart = (c: CollapsedCandidate) => c.start;
  for (let idx = 0; idx < candidates.length; idx++) {
    const x = candidates[idx];
    let lastAt = -1;
    for (let j = lowerBound(byStart, candidateStart, x.start + 1); j < byStart.length && byStart[j].start < x.end; j++) {
      const y = byStart[j];
      if (y.pattern === x.pattern || y.start === lastAt) continue;
      lastAt = y.start;
      const cc = collapsedIndexAtOrAfter(map, x.cStart, x.cEnd, y.start);
      if (cc <= x.cStart) continue;
      const m = matchesSpanExactly(x.compiled, text, x.cStart, cc);
      if (!m) continue;
      const cut = validateCandidate(view, x.pattern, x.compiled, cfg, x.cStart, cc, m);
      if (cut) {
        candidates[idx] = cut;
        break;
      }
    }
  }

  // ── Resolution (ii): accept by severity, suppress only downward ──
  candidates.sort((a, b) =>
    SEVERITY_RANK[b.pattern.severity] - SEVERITY_RANK[a.pattern.severity]
    || (b.end - b.start) - (a.end - a.start)
    || a.start - b.start);

  const coverage = new CoverageIndex([...direct.map(r => r.start), ...candidates.map(c => c.start)]);
  for (const r of direct) coverage.add(r.start, r.end, r.severity ?? 'low');

  for (const c of candidates) {
    if (coverage.covers(c.start, c.end, SEVERITY_RANK[c.pattern.severity])) continue;

    findings.push({
      type: c.pattern.type,
      provider: c.pattern.provider,
      confidence: c.pattern.confidence,
      severity: c.pattern.severity,
      match: redactMatch(c.secretValue, c.pattern.type),
      position: c.start,
      action: actionForSeverity(c.pattern.severity, cfg),
      evasion: 'separator_split',
    });
    matchedRanges.push({
      start: c.start,
      end: c.end,
      replacement: `[REDACTED-${c.pattern.type}${c.pattern.provider ? `-${c.pattern.provider}` : ''}]`,
      severity: c.pattern.severity,
    });
    coverage.add(c.start, c.end, c.pattern.severity);
  }

  return { findings, matchedRanges };
}

/**
 * Building blocks of the collapsed-pass prose decision, exported for the
 * measurement script (`scripts/lab/credential-split-evasion.mts`) and tests.
 * Not part of the public API.
 */
export const collapsedPassInternals = {
  classifyFragment,
  fragmentReadsAsProse,
  hitReadsAsProse,
  literalPrefixLength,
  PERIOD_TOKEN,
  RARE_BIGRAMS,
};

// ── Scanner ──

/**
 * Scan content for credential leaks.
 *
 * Checks known API key formats, generic secrets, private keys,
 * connection strings, env variable patterns, and high-entropy strings.
 *
 * @param content - The text content to scan
 * @param config - Optional credential detection configuration
 * @returns Scan result with findings and optional redacted content
 */
export function scanForCredentials(
  content: string,
  config?: Partial<CredentialDetectionConfig>,
): CredentialScanResult {
  const cfg: CredentialDetectionConfig = { ...DEFAULT_CREDENTIAL_CONFIG, ...config };

  if (!cfg.enabled || !content || content.length === 0) {
    return { leaked: false, findings: [] };
  }

  let findings: CredentialFinding[] = [];
  let matchedRanges: MatchedRange[] = [];

  const patterns = [...ALL_CREDENTIAL_PATTERNS, ...cfg.customPatterns];

  // Run all pattern matchers
  for (const pattern of patterns) {
    // Reset regex lastIndex for each scan
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(content)) !== null) {
      const fullMatch = match[0];
      // For patterns with capture groups, use the group; otherwise the full match
      const secretValue = match[1] ?? fullMatch;

      // Skip if below minimum length
      if (pattern.minLength && secretValue.length < pattern.minLength) continue;

      // Skip allowlisted values
      if (isAllowlisted(secretValue, cfg.allowlist)) continue;

      // #205: documentation placeholders are not secrets.
      // Only for env-style assignment CAPTURES — never for full connection
      // strings / API keys (those can contain the word "example" in a host).
      if (pattern.type === 'env_secret' && isDocumentationPlaceholder(secretValue)) continue;

      // Skip if this range is already covered by a higher-priority pattern
      const start = match.index;
      const end = start + fullMatch.length;
      if (matchedRanges.some(r => start >= r.start && end <= r.end)) continue;

      // Skip well-known PUBLIC identifiers (git SHA / UUID). Generic hex rules
      // match a substring of these, so expand to the full token before testing
      // (Phase 17 A5 / #205 empty digests).
      if (matchIsWellKnownNonSecret(content, start, end)) continue;

      const action = actionForSeverity(pattern.severity, cfg);
      const redacted = redactMatch(secretValue, pattern.type);

      findings.push({
        type: pattern.type,
        provider: pattern.provider,
        confidence: pattern.confidence,
        severity: pattern.severity,
        match: redacted,
        position: start,
        action,
      });

      const replacement = `[REDACTED-${pattern.type}${pattern.provider ? `-${pattern.provider}` : ''}]`;
      matchedRanges.push({ start, end, replacement, severity: pattern.severity });
    }
  }

  // #543: second pattern pass over the separator-collapsed view, before the
  // entropy net so a split key's fragments are inside a range by the time the
  // tokeniser sees them.
  const collapsed = buildCollapsedView(content);
  if (collapsed) {
    ({ findings, matchedRanges } = scanCollapsedView(
      collapsed, patterns, cfg, findings, matchedRanges,
    ));
  }

  // Run entropy-based detection for anything not already caught.
  //
  // `extractHighEntropyTokens` returns EVERY occurrence, so the two concerns
  // are separated deliberately here:
  //
  //   redaction — every occurrence gets a range. Missing one leaves the secret
  //               verbatim in output the caller believes is redacted.
  //   reporting — one finding per distinct secret. Turning a repeat into N
  //               findings would inflate audit counts and severity grades
  //               (`medium > 0` drops the grade to C, which exits 1) without
  //               telling the operator anything they did not already know.
  const entropyTokens = extractHighEntropyTokens(content);
  const reportedEntropyTokens = new Set<string>();
  // Snapshot the pattern layer's ranges BEFORE the entropy loop mutates
  // matchedRanges: finding-emission (below) discriminates against these, and
  // entropy ranges pushed for earlier tokens must never suppress later ones.
  // Merged into disjoint intervals so two overlapping pattern matches cannot
  // double-subtract coverage in the uncovered-length arithmetic.
  const patternRanges = matchedRanges
    .map(r => ({ start: r.start, end: r.end }))
    .sort((a, b) => a.start - b.start)
    .reduce<Array<{ start: number; end: number }>>((merged, r) => {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end) last.end = Math.max(last.end, r.end);
      else merged.push({ ...r });
      return merged;
    }, []);
  for (const token of entropyTokens) {
    const start = token.position;
    const end = start + token.token.length;

    // Skip only when an earlier pattern already covers the ENTIRE entropy
    // token. A low-confidence pattern can match just the repeated filler prefix
    // of a padded secret (`aaaa...` as a generic hex/Azure key). Treating that
    // partial overlap as "already caught" left the real high-entropy suffix raw
    // in redacted output — exactly the #257 bypass shape.
    if (matchedRanges.some(r => start >= r.start && end <= r.end)) continue;

    // Skip allowlisted
    if (isAllowlisted(token.token, cfg.allowlist)) continue;

    // Range FIRST, and unconditionally — a repeat must still be redacted even
    // though it will not produce a second finding below. Drop narrower pattern
    // ranges contained inside this entropy token so a filler-only match cannot
    // split or shrink the redaction span.
    matchedRanges = matchedRanges.filter(r => !(r.start >= start && r.end <= end));
    matchedRanges.push({ start, end, replacement: '[REDACTED-high_entropy]' });

    if (reportedEntropyTokens.has(token.token)) continue;
    reportedEntropyTokens.add(token.token);

    // #256 invariant: one finding per DISTINCT secret. An env-style assignment
    // (`FOO=<secret>`) tokenises key+secret into one entropy token that extends
    // past the pattern match by a few boilerplate chars, so it is not "fully
    // nested" above — but it is still the SAME secret the pattern already
    // reported. Emit a second finding only when the pattern layer leaves ≥ 20
    // uncovered chars of this token (the tokeniser's own minimum secret
    // length — anything smaller cannot be a distinct secret by the net's own
    // definition). The redaction RANGE above is recorded unconditionally
    // either way: #257 completeness and #256 reporting are separate concerns.
    let uncovered = end - start;
    for (const r of patternRanges) {
      const overlap = Math.min(end, r.end) - Math.max(start, r.start);
      if (overlap > 0) uncovered -= overlap;
    }
    if (uncovered < 20 && uncovered < end - start) continue;

    const severity: CredentialSeverity = token.confidence >= 0.8 ? 'medium' : 'low';
    const action = actionForSeverity(severity, cfg);

    findings.push({
      type: 'high_entropy',
      confidence: token.confidence,
      severity,
      match: redactMatch(token.token, 'high_entropy'),
      position: start,
      action,
    });
  }

  // Sort findings by position
  findings.sort((a, b) => a.position - b.position);

  const leaked = findings.length > 0;
  const hasBlocked = findings.some(f => f.action === 'blocked');

  // Build redacted content if any findings
  let redactedContent: string | undefined;
  if (leaked) {
    redactedContent = buildRedactedContent(content, matchedRanges);
  }

  return {
    leaked,
    findings,
    redactedContent: hasBlocked ? redactedContent : redactedContent,
  };
}

// ── Redaction Helper ──

/**
 * Replace all detected secrets in content with [REDACTED-{type}] placeholders.
 * Useful for agents that want to store memory but strip the secrets.
 */
export function redactCredentials(
  content: string,
  config?: Partial<CredentialDetectionConfig>,
): string {
  const result = scanForCredentials(content, config);
  return result.redactedContent ?? content;
}

/**
 * Build redacted content by replacing matched ranges.
 */
function buildRedactedContent(
  content: string,
  ranges: Array<{ start: number; end: number; replacement: string }>,
): string {
  const merged = mergeOverlappingRanges(ranges);
  // One left-to-right pass over the merged, disjoint ranges: splicing the
  // content once per range copied the whole string each time, which made
  // redacting N findings cost N × content length (#544 round 4).
  const sorted = [...merged].sort((a, b) => a.start - b.start);
  const parts: string[] = [];
  let cursor = 0;
  for (const range of sorted) {
    parts.push(content.slice(cursor, range.start), range.replacement);
    cursor = range.end;
  }
  parts.push(content.slice(cursor));
  return parts.join('');
}

/**
 * Collapse overlapping (not just nested) ranges into a single span before
 * replacement.
 *
 * `buildRedactedContent` replaces right-to-left on the assumption that ranges
 * never overlap, using offsets computed against the ORIGINAL content. A
 * PARTIAL overlap — e.g. a pattern match whose captured charset stops short
 * of a longer entropy token, so the pattern's end falls strictly inside the
 * entropy token's span while neither range contains the other — breaks that
 * assumption: replacing the first range shrinks/reshapes the working string,
 * and the second range's original-content `end` then lands on the wrong
 * position in that already-mutated string, silently truncating or duplicating
 * output. The two-range-removal dance in `scanForCredentials` only handles
 * the fully-NESTED case (one range wholly inside another); it does not — and
 * structurally cannot, since it only sees one new range at a time — catch a
 * crossing overlap. Merging here makes "ranges never overlap" true by
 * construction for every caller, instead of relying on every producer of
 * `matchedRanges` to keep it true by hand.
 */
function mergeOverlappingRanges(
  ranges: Array<{ start: number; end: number; replacement: string }>,
): Array<{ start: number; end: number; replacement: string }> {
  if (ranges.length <= 1) return ranges;

  const sorted = [...ranges].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: Array<{ start: number; end: number; replacement: string }> = [sorted[0]];

  for (let i = 1; i < sorted.length; i++) {
    const next = sorted[i];
    const last = merged[merged.length - 1];
    if (next.start < last.end) {
      // Overlapping (or one nested in the other) — union the span. Keep
      // whichever replacement corresponds to the wider original range: it
      // covers strictly more of the underlying secret and is the more
      // complete redaction of the two.
      const wider = next.end - next.start > last.end - last.start ? next : last;
      merged[merged.length - 1] = {
        start: last.start,
        end: Math.max(last.end, next.end),
        replacement: wider.replacement,
      };
    } else {
      merged.push(next);
    }
  }

  return merged;
}

// Re-export types and utilities
export type { CredentialPattern, CredentialType, CredentialSeverity } from './patterns.js';
export { shannonEntropy, checkHighEntropy } from './entropy.js';
export { ALL_CREDENTIAL_PATTERNS } from './patterns.js';
