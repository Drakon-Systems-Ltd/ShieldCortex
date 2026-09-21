/**
 * #543 / #544 — how much of the separator-split credential detection can an
 * attacker who chooses the split points evade, and how much of a naively
 * split key is still found?
 *
 *   npx tsx scripts/lab/credential-split-evasion.mts [ids-per-class]
 *
 * Attacker-optimal figures for the strict rule come from an exact search: a
 * dynamic programme over every partition of the collapsed key into
 * whitespace-separated fragments, plus a letter glued onto the first or last
 * fragment, evaluated against the same fragment classifier the scanner uses.
 * Every predicted evasion is then re-run through `scanForCredentials`, and
 * only confirmed evasions are counted. Naive-split recall runs the scanner
 * directly.
 *
 * The AWS id (round 5 policy) has no partition-dependent rule: split by
 * visible whitespace alone it is never claimed (the stated gap — reported
 * here as 0% recall), and split by an invisible separator it gets no prose
 * escape, so the split points cannot matter and the search does not apply.
 * Its recall is measured directly for every naive shape, with and without a
 * glued letter.
 *
 * Numbers quoted in the CHANGELOG and in `hitReadsAsProse` come from this
 * script at 20,000 ids per class.
 */
import { scanForCredentials, collapsedPassInternals } from '../../src/defence/credential-leak/index.js';

const { classifyFragment, PERIOD_TOKEN, RARE_BIGRAMS } = collapsedPassInternals;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE62 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

interface KeyClass {
  name: string;
  prefix: string;
  /** Characters the pattern matches literally (`literalPrefixLength`). */
  prefixLength: number;
  alphabet: string;
  bodyLength: number;
  provider: string;
  /** Which policy the scanner applies to this pattern's collapsed hits. */
  rule: 'strict' | 'whitespace-gap';
}

const CLASSES: KeyClass[] = [
  { name: 'AWS access key id (AKIA + 16 base-32)', prefix: 'AKIA', prefixLength: 1, alphabet: BASE32, bodyLength: 16, provider: 'aws', rule: 'whitespace-gap' },
  { name: 'OpenAI legacy (sk- + 48 base-62)', prefix: 'sk-', prefixLength: 3, alphabet: BASE62, bodyLength: 48, provider: 'openai', rule: 'strict' },
  { name: 'Google (AIza + 35 base-62)', prefix: 'AIza', prefixLength: 4, alphabet: BASE62, bodyLength: 35, provider: 'google', rule: 'strict' },
];

const LETTERS_ONLY = /^(?:[A-Z]+|[a-z]+|[A-Z][a-z]+)$/;
const PERIOD_PREFIX = /^(?:\d{0,4}|(?:[QHWMYDPT]|F|FY|C|CY|W|WK|[qhwmydpt]|f|fy|c|cy|w|wk)\d{0,4}|\d{1,2}(?:[QHWMYD]|S|ST|N|ND|R|RD|T|TH|[qhwmyd]|s|st|n|nd|r|rd|t|th)?)$/;

function noRareBigram(t: string): boolean {
  const l = t.toLowerCase();
  for (let i = 0; i < l.length - 1; i++) if (RARE_BIGRAMS[l[i]]?.includes(l[i + 1])) return false;
  return true;
}

/** Letters that can be appended to `t` so the whole reads as a word, or null. */
function wordCompletion(t: string): string | null {
  if (!LETTERS_ONLY.test(t) || !noRareBigram(t)) return null;
  const upper = /^[A-Z]+$/.test(t);
  let out = '';
  let last = t[t.length - 1].toLowerCase();
  while (t.length + out.length < 3 || out.length < 1) {
    const pick = [...'abcdefghijklmnopqrstuvwxyz'].find(c => !RARE_BIGRAMS[last]?.includes(c)) ?? 'a';
    out += upper ? pick.toUpperCase() : pick;
    last = pick;
  }
  return out;
}

/** A letter that can be prepended to `t` so the whole reads as a word, or null. */
function wordPrefix(t: string): string | null {
  if (!/^[A-Z]+$|^[a-z]+$/.test(t) || !noRareBigram(t)) return null;
  const first = t[0].toLowerCase();
  const pick = [...'abcdefghijklmnopqrstuvwxyz'].find(c => !RARE_BIGRAMS[c]?.includes(first));
  if (!pick) return null;
  return /^[A-Z]/.test(t) ? pick.toUpperCase() : pick;
}

function periodCompletion(t: string): string | null {
  if (PERIOD_TOKEN.test(t) || !PERIOD_PREFIX.test(t)) return null;
  for (const add of ['3', '33', 'ST', 'st', 'T', 't', 'D', 'H', 'Y3', 'y3', 'K3']) if (PERIOD_TOKEN.test(t + add)) return add;
  return null;
}

/** Aggregate features of one partition; enough to evaluate both rules. */
interface State {
  wordChars: number;
  bodyWord: boolean;
  /** A fragment beyond the prefix that is neither word nor period (strict rule: key). */
  nonProse: boolean;
  /** A fragment beyond the prefix classified OTHER (alignment rule: key material). */
  other: boolean;
  lone: number;
  misaligned: boolean;
  pre: string;
  post: string;
  cuts: number[];
}

/** Can the fragment `t` never become a word or a period token, however it is extended? */
function deadEnd(t: string): boolean {
  const hasDigit = /[0-9]/.test(t);
  const hasLetter = /[A-Za-z]/.test(t);
  if (/[^A-Za-z0-9]/.test(t)) return true;
  if (hasDigit && hasLetter) return !PERIOD_PREFIX.test(t);
  if (hasLetter) return !LETTERS_ONLY.test(t);
  return t.length > 4;
}

/**
 * Every reachable feature state over all partitions of `s` (and the glue
 * moves), deduplicated. `n` is at most 52 and most fragments are dead ends
 * after two characters, so this is fast.
 */
function reachable(s: string, prefixEnd: number): State[] {
  const n = s.length;
  const layers: Map<string, State>[] = Array.from({ length: n + 1 }, () => new Map());
  layers[0].set('', { wordChars: 0, bodyWord: false, nonProse: false, other: false, lone: 0, misaligned: false, pre: '', post: '', cuts: [] });
  for (let i = 0; i < n; i++) {
    for (const st of layers[i].values()) {
      for (let j = i + 1; j <= n; j++) {
        const t = s.slice(i, j);
        const insidePrefix = j <= prefixEnd;
        if (!insidePrefix && deadEnd(t) && i >= prefixEnd) break;
        const opts: Array<[ReturnType<typeof classifyFragment>, string, string]> = [[classifyFragment(t), '', '']];
        if (i === 0) { const pre = wordPrefix(t); if (pre) opts.push(['word', pre, '']); }
        if (j === n) {
          const wc = wordCompletion(t); if (wc) opts.push(['word', '', wc]);
          const pc = periodCompletion(t); if (pc) opts.push(['period', '', pc]);
          if (LETTERS_ONLY.test(t)) opts.push([classifyFragment(t), '', /^[A-Z]+$/.test(t) ? 'X' : 'x']);
        }
        for (const [cls, pre, post] of opts) {
          const f: State = { ...st, cuts: [...st.cuts, j] };
          if (pre) { f.pre = pre; f.misaligned = true; }
          if (post) { f.post = post; if (LETTERS_ONLY.test(t + post)) f.misaligned = true; }
          if (cls === 'word') {
            f.wordChars += j - i;
            if (j - i >= 3 && i >= prefixEnd) f.bodyWord = true;
          } else if (cls !== 'period' && !insidePrefix) {
            f.nonProse = true;
            if (cls === 'other') f.other = true;
            if (cls === 'letters' && t.length === 1 && !pre && !post) f.lone++;
          }
          const key = `${f.wordChars}|${f.bodyWord ? 1 : 0}|${f.nonProse ? 1 : 0}|${f.other ? 1 : 0}|${Math.min(f.lone, 2)}|${f.misaligned ? 1 : 0}`;
          if (!layers[j].has(key)) layers[j].set(key, f);
        }
      }
    }
  }
  return [...layers[n].values()];
}

function strictDismisses(f: State, n: number): boolean {
  return !f.nonProse && f.bodyWord && f.wordChars * 2 >= n;
}

function witness(s: string, f: State): string {
  const parts: string[] = [];
  let prev = 0;
  for (const c of f.cuts) { parts.push(s.slice(prev, c)); prev = c; }
  parts[0] = f.pre + parts[0];
  parts[parts.length - 1] += f.post;
  return parts.join(' ');
}

function confirmed(text: string, provider: string): boolean {
  return !scanForCredentials(text).findings.some(f => f.provider === provider);
}

const N = Number(process.argv[2] ?? 20000);
const rnd = mulberry32(543);

for (const cls of CLASSES) {
  let matched = 0;
  let strictEvade = 0;
  const naive: Record<string, number> = { 'every 1': 0, 'every 2': 0, 'every 3': 0, 'every 4': 0, 'every 5': 0, 'every 8': 0, 'once': 0, 'newline every 4': 0 };
  const ZWSP = '\u200b';
  const invisible: Record<string, number> = { 'ZWSP every 1': 0, 'ZWSP every 2': 0, 'ZWSP every 3': 0, 'ZWSP every 4': 0, 'ZWSP every 8': 0, 'BOM once': 0, 'soft hyphen every 4': 0, 'X + ZWSP every 4 + Y': 0, 'ZWSP every 4 in quotes': 0, 'space + ZWSP mixed': 0 };
  const splitEvery = (k: string, sep: string, e: number) => k.match(new RegExp(`.{1,${e}}`, 'g'))!.join(sep);
  const t0 = performance.now();
  for (let i = 0; i < N; i++) {
    let body = '';
    for (let c = 0; c < cls.bodyLength; c++) body += cls.alphabet[Math.floor(rnd() * cls.alphabet.length)];
    if (!/[0-9]/.test(body) || !/[A-Za-z]/.test(body)) continue; // letter+digit gate: never claimed, documented residual
    matched++;
    const key = cls.prefix + body;

    if (cls.rule === 'strict') {
      const states = reachable(key, cls.prefixLength);
      const strictHit = states.find(f => strictDismisses(f, key.length));
      if (strictHit && confirmed(witness(key, strictHit), cls.provider)) strictEvade++;
    } else {
      const shapes: Record<string, string> = {
        'ZWSP every 1': splitEvery(key, ZWSP, 1), 'ZWSP every 2': splitEvery(key, ZWSP, 2), 'ZWSP every 3': splitEvery(key, ZWSP, 3),
        'ZWSP every 4': splitEvery(key, ZWSP, 4), 'ZWSP every 8': splitEvery(key, ZWSP, 8),
        'BOM once': key.slice(0, key.length >> 1) + '\ufeff' + key.slice(key.length >> 1),
        'soft hyphen every 4': splitEvery(key, '\u00ad', 4),
        'X + ZWSP every 4 + Y': `X${splitEvery(key, ZWSP, 4)}Y`,
        'ZWSP every 4 in quotes': `"${splitEvery(key, ZWSP, 4)}"`,
        'space + ZWSP mixed': `${key.slice(0, 8)} ${key.slice(8, 12)}${ZWSP}${key.slice(12, 16)} ${key.slice(16)}`,
      };
      for (const [name, text] of Object.entries(shapes)) {
        if (scanForCredentials(`id: ${text} end`).findings.some(f => f.provider === cls.provider && f.evasion === 'separator_split')) invisible[name]++;
      }
    }

    const shapes: Record<string, string> = {
      'every 1': splitEvery(key, ' ', 1), 'every 2': splitEvery(key, ' ', 2), 'every 3': splitEvery(key, ' ', 3),
      'every 4': splitEvery(key, ' ', 4), 'every 5': splitEvery(key, ' ', 5), 'every 8': splitEvery(key, ' ', 8),
      'once': key.slice(0, key.length >> 1) + ' ' + key.slice(key.length >> 1), 'newline every 4': splitEvery(key, '\n', 4),
    };
    for (const [name, text] of Object.entries(shapes)) {
      // Found by either pass: a split that leaves a head long enough for the direct regex is an ordinary finding.
      if (scanForCredentials(`id: ${text} end`).findings.some(f => f.provider === cls.provider)) naive[name]++;
    }
  }
  const pct = (x: number) => `${(100 * x / matched).toFixed(2)}%`;
  console.log(`\n${cls.name} — rule: ${cls.rule}; ${matched} of ${N} random ids pass the letter+digit gate; ${((performance.now() - t0) / 1000).toFixed(0)}s`);
  if (cls.rule === 'strict') {
    console.log(`  attacker-optimal split (whitespace and a glued letter), strict rule dismisses: ${pct(strictEvade)}`);
    console.log('  naive whitespace splits found:', Object.entries(naive).map(([k, v]) => `${k} ${pct(v)}`).join('; '));
  } else {
    console.log('  visible whitespace splits found (stated gap, never claimed):', Object.entries(naive).map(([k, v]) => `${k} ${pct(v)}`).join('; '));
    console.log('  invisible-separator splits found (no prose escape):', Object.entries(invisible).map(([k, v]) => `${k} ${pct(v)}`).join('; '));
  }
}
