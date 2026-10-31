/**
 * #923 r7 — the ONE shell-word tokenizer and path normaliser
 * (scripts/lib/shell-words.mjs) that both Action Guard planes use.
 *
 * 1. It splits words the way bash does. A seeded fuzz corpus of escape- and
 *    quote-heavy operands is compared against bash's own argv (`printf
 *    '%s\0'`, which only prints; nothing is expanded or executed — the
 *    alphabet holds no `$`, backtick, glob, brace, `~` or operator).
 * 2. It is shared, not copied: the live guard (source and dist) and the
 *    pre-tool hook import the same file, and neither defines its own
 *    tokenizer or backslash-mapping normaliser any more. So the two planes
 *    cannot drift; the claude-transcript-floor-923 suite asserts identical
 *    live and outage verdicts on top of this.
 */
import { describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { CLAUDE_TRANSCRIPT_NAMED_RE, claudeJoinedWordMayBeTranscript, claudeWordExpands, EXPANSION_MARK, expansionWords, lexicalPathNormalise, shellTokens, shellWords } from '../../scripts/lib/shell-words.mjs';
import { CLAUDE_TRANSCRIPT_PATH_RE, lexicalPathNormalise as guardNormalise, claudeTranscriptNamed } from '../defence/iron-dome/tool-action-guard.js';
import { joinedControls, joinedSpellings } from './support/transcript-joins-923.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const words = (s: string) => shellTokens(s).tokens.filter(t => t.type === 'word').map(t => t.value);

/** bash's argv for `printf '%s\0' <text>`, or null when bash rejects the text. */
function bashWords(text: string): string[] | null {
  const r = spawnSync('bash', ['--noprofile', '--norc', '-c', `printf '%s\\0' ${text}`], { encoding: 'utf8', timeout: 10_000 });
  if (r.status !== 0) return null;
  return r.stdout.split('\0').slice(0, -1);
}

/** Small deterministic PRNG (mulberry32), so a failure is reproducible. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const PIECES = ['a', 'x', '.claude', '/', '/', '.', '..', ' ', '\t', ',', '=', '-', '\\ ', '\\(', '\\)', '\\,', '\\=', '\\\\', '\\\'', '\\"', '\\;', '\\a',
  "'a b'", "'a\\b'", '"a b"', '"a\\b"', '"a\\"b"', '"a\\\\b"', '"(x)"', "''", '""', '\\\n', "$'a\\x20b'", "$'\\101\\n'"];

function fuzzCase(next: () => number): string {
  let s = 'w';
  const n = 2 + Math.floor(next() * 12);
  for (let i = 0; i < n; i++) s += PIECES[Math.floor(next() * PIECES.length)];
  return s;
}

describe('#923 r7 — shellTokens splits words as bash does', () => {
  const bash = spawnSync('bash', ['--version'], { encoding: 'utf8' });
  const itBash = bash.status === 0 ? it : it.skip;

  const HAND: string[] = [
    String.raw`/h/.claude/x\ y/../projects/p/s.jsonl`,
    String.raw`/h/.claude/x\(y\)/../projects/p/s.jsonl`,
    String.raw`/h/.claude/x\,y/../projects/p/s.jsonl a\=b`,
    String.raw`"/h/.claude/x y/../p" 'a\b' "a\b\"c\\d"`,
    String.raw`a\'b "x'y" 'x"y'`,
    'a\\\nb c',
    String.raw`$'a\x20b\nc\101'`,
    String.raw`x\\y \\ \#z`,
    'tab\tsep  multi',
    String.raw`.claude/"projects"/p/s.jsonl`,
    String.raw`a\ \ b`,
  ];

  itBash.each(HAND)('hand case %j', (text) => {
    expect(words(text)).toEqual(bashWords(text));
  });

  itBash('a seeded fuzz corpus of 300 operands matches bash word for word', () => {
    const next = rng(923);
    let compared = 0;
    const mismatches: Array<{ text: string; bash: string[]; ours: string[] }> = [];
    for (let i = 0; i < 300; i++) {
      const text = fuzzCase(next);
      const expected = bashWords(text);
      if (expected === null) continue;
      compared++;
      const ours = words(text);
      if (JSON.stringify(ours) !== JSON.stringify(expected)) mismatches.push({ text, bash: expected, ours });
    }
    expect(mismatches).toEqual([]);
    expect(compared).toBeGreaterThan(250);
  });

  it('operators end words and are reported; quoted operators are not', () => {
    const t = shellTokens(`cat a;b|c&&d "e;f" 'g|h' i\\;j`).tokens;
    expect(t.map(x => `${x.type}:${x.value}`)).toEqual([
      'word:cat', 'word:a', 'op:;', 'word:b', 'op:|', 'word:c', 'op:&&', 'word:d', 'word:e;f', 'word:g|h', 'word:i;j',
    ]);
  });

  it('an unterminated quote is incomplete but its text is still a word', () => {
    const r = shellTokens(`cp x "/h/.claude/a b/../projects/p/s.jsonl`);
    expect(r.complete).toBe(false);
    expect(r.tokens.at(-1)).toMatchObject({ type: 'word', value: '/h/.claude/a b/../projects/p/s.jsonl' });
  });

  it('bare records only unquoted, unescaped characters', () => {
    const [w] = shellTokens(String.raw`a\$"{b}"'#'c!`).tokens;
    expect(w).toMatchObject({ type: 'word', value: 'a${b}#c!', bare: 'ac!' });
  });

  it('a nested shell word is tokenised again (bash -c, "$(…)")', () => {
    expect(shellWords(String.raw`bash -c 'cp a /h/x\ y/../z'`)).toContain('/h/x y/../z');
    expect(shellWords(String.raw`echo "$(cp a /h/x\ y/../z)"`)).toContain('/h/x y/../z');
  });
});

describe('#923 r7 — lexicalPathNormalise collapses on / only', () => {
  it.each<[string, string]>([
    ['/h/.claude/./projects/p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude//projects//p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude/x y/../projects/p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude/x\\y/../projects/p/s.jsonl', '/h/.claude/projects/p/s.jsonl'],
    ['/h/.claude/x\\/../projects', '/h/.claude/projects'],
    ['a\\b', 'a\\b'],
    ['../x/../y', '../y'],
    ['/../x', '/x'],
  ])('%j -> %j', (input, expected) => {
    expect(lexicalPathNormalise(input)).toBe(expected);
    expect(guardNormalise(input)).toBe(expected);
  });

  it('the r6 Astra B1 escaped alias names the transcript; the bare fragments do not', () => {
    expect(claudeTranscriptNamed(String.raw`sudo cp /h/src.jsonl /h/.claude/x\ y/../projects/p/session.jsonl`)).toBe(true);
    expect(claudeTranscriptNamed(String.raw`cat /h/.claude/x\ y/../notes.txt`)).toBe(false);
  });
});

describe('#923 r7 — both planes import the one module (no copy to drift)', () => {
  const hook = readFileSync(join(repoRoot, 'scripts', 'pre-tool-hook.mjs'), 'utf8');
  const guard = readFileSync(join(repoRoot, 'src', 'defence', 'iron-dome', 'tool-action-guard.ts'), 'utf8');

  it('the pre-tool hook imports scripts/lib/shell-words.mjs and defines no tokenizer of its own', () => {
    expect(hook).toMatch(/from '\.\/lib\/shell-words\.mjs'/);
    expect(hook).not.toMatch(/function fallbackShellWords\b/);
    expect(hook).not.toMatch(/function fallbackLexicalPathNormalise\b/);
  });

  it('the live guard imports the same file and defines no tokenizer of its own', () => {
    expect(guard).toMatch(/from '\.\.\/\.\.\/\.\.\/scripts\/lib\/shell-words\.mjs'/);
    expect(guard).not.toMatch(/^function shellWords\b/m);
    // The guard's normaliser is the shared one, so no backslash-to-slash
    // mapping survives in it; the hook has none at all. (isShellStartupWritePath
    // and isMemoryWritePath keep theirs: basename detectors that only ever
    // match MORE paths, and never collapse `..`.)
    expect(guard).toMatch(/export function lexicalPathNormalise\(p: string\): string \{\n {2}return sharedLexicalPathNormalise\(p\);\n\}/);
    expect(hook).not.toMatch(/replace\(\/\\\\\/g, '\/'\)/);
  });

  it('the built guard resolves the import to the shipped scripts/lib file', () => {
    const distGuard = join(repoRoot, 'dist', 'defence', 'iron-dome', 'tool-action-guard.js');
    let built = '';
    try { built = readFileSync(distGuard, 'utf8'); } catch { /* no build: covered by the source check above */ }
    if (built) {
      expect(built).toMatch(/from '\.\.\/\.\.\/\.\.\/scripts\/lib\/shell-words\.mjs'/);
      expect(resolve(dirname(distGuard), '../../../scripts/lib/shell-words.mjs')).toBe(join(repoRoot, 'scripts', 'lib', 'shell-words.mjs'));
    }
  });
});

/**
 * #923 r10 (r9 Astra B1, N1) — words the shell EXPANDS before the command
 * sees them. `.claude/x$((1))y/../projects/p/s.jsonl` writes the transcript
 * once bash computes `x1y`; the typed word never matched. `expansionWords`
 * keeps each expansion INSIDE its word (as a mark) and `claudeWordExpands` is
 * the closed-set refusal both planes share. Nothing here is executed.
 */
describe('#923 r10 — expansion-aware words and the shared refusal', () => {
  const L = 'projects/p/s.jsonl';
  const M = EXPANSION_MARK;

  it.each<[string, string]>([
    ['x$((1))y', `x${M}y`],
    ['x$(printf 1)y', `x${M}y`],
    ['x`printf 1`y', `x${M}y`],
    ['x${unset:-1y}', `x${M}`],
    ['x$v/y', `x${M}/y`],
    ['"a/$(echo p q)/z"', `a/${M}/z`],
    ['a/x<(true)/b', `a/x${M}/b`],
    ['a/proj*/b', `a/proj${M}/b`],
    ['a/{x,y}', `a/${M}x,y}`],
    ["'a/$x'", 'a/$x'],
    ['a\\$x', 'a$x'],
    ["$'a\\x20b'", 'a b'],
  ])('%s is one word: %j', (text, value) => {
    expect(expansionWords(text)[0].value).toBe(value);
  });

  it.each<[string, string]>([
    ['arithmetic', `cp s /h/.claude/x$((1))y/../${L}`],
    ['arithmetic +0', `cp s /h/.claude/x$((1+0))y/../${L}`],
    ['command substitution', `cp s /h/.claude/x$(printf 1)y/../${L}`],
    ['backticks', `cp s /h/.claude/x\`printf 1\`y/../${L}`],
    ['parameter default', `cp s /h/.claude/x\${unset:-1y}/../${L}`],
    ['plain parameter', `cp s /h/.claude/$P/p/s.jsonl`],
    ['double-quoted substitution', `cp s "/h/.claude/$(echo projects)/p/s.jsonl"`],
    ['mid-word process substitution', `cp s /h/.claude/x<(true)/../../../../${L}`],
    ['glob', `cp s /h/.claude/proj*/p/s.jsonl`],
    ['brace expansion', `tee /h/.claude/{x,projects}/p/s.jsonl`],
    ['bash -c single-quoted', `bash -c 'cp s /h/.claude/x$((1))y/../${L}'`],
    ['eval double-quoted', `eval "cp s /h/.claude/x\\$((1))y/../${L}"`],
    ['glob builds .claude', `cp s /h/.cl*/${L}`],
    ['substitution builds .claude', `cp s /h/.cla$(echo ude)/${L}`],
    ['parameter builds .claude', `D=/h/.cl; cp s \${D}aude/${L}`],
    ['parameter holds the .claude dir', `cp s $C/${L}`],
    ['.. climbs out of a substitution', `cp s $(echo a/b)/../${L}`],
    ['parameter assigned .claude/projects in the command', `C=/h/.claude/projects; cp s $C/p/s.jsonl`],
    // An escaped `$` is literal HERE, but the unescaped word may be an inner
    // shell's text (`bash -c cp\ s\ …\$((1))…`, `eval`), so it is rescanned
    // and refused: an accepted over-deny of a `.claude` path spelled with `$`.
    ['escaped dollar (rescanned as possible inner-shell text)', 'cp s /h/.claude/x\\$y'],
  ])('refused: %s', (_label, text) => {
    expect(claudeWordExpands(text)).toBe(true);
    expect(claudeTranscriptNamed(text)).toBe(true);
  });

  it.each<[string, string]>([
    ['literal transcript (the path regex judges it)', `cp s /h/.claude/${L}`],
    ['expansion only before .claude', 'cp s $HOME/.claude/settings.json'],
    ['an ordinary computed .jsonl, no .claude named', 'X=/tmp; cp s $X/out.jsonl'],
    ['an ordinary computed projects dir, not a transcript leaf', 'ls $HOME/projects'],
    ['no .claude at all', 'cp s /tmp/x$((1))y'],
  ])('not refused: %s', (_label, text) => {
    expect(claudeWordExpands(text)).toBe(false);
  });
});

/**
 * #923 r11 (r10 Grok BLOCKER, r10 Astra B1) — JOIN the pieces. r10 judged the
 * marked word and each expansion body as unrelated words; the shell joins
 * them. `claudeJoinedWordMayBeTranscript` rebuilds the word from its literal
 * parts plus every value the command spells for each expansion (assignment,
 * `${v:-word}`, what an echo/printf body prints, the body text, empty) and
 * brace alternatives, and judges every cross-product with the guard's own
 * transcript regex (glob items by a segment matcher). A value or command
 * expansion in a command holding both a `.claude`-ish and a `projects`/
 * `.jsonl` fragment is refused outright. Nothing is executed.
 */
describe('#923 r11 — the joined candidate', () => {
  const H = '/home/owner';

  it('judges joins with the guard\'s own transcript regex (equal source)', () => {
    expect(CLAUDE_TRANSCRIPT_NAMED_RE.source).toBe(CLAUDE_TRANSCRIPT_PATH_RE.source);
    expect(CLAUDE_TRANSCRIPT_NAMED_RE.flags).toBe(CLAUDE_TRANSCRIPT_PATH_RE.flags);
  });

  it.each(joinedSpellings(H, '/tmp/forged.jsonl', 's.jsonl'))('refused: %s', (label, text) => {
    // The NUL row expands nothing: the tokenizer's own cut makes it the
    // literal transcript word, which the path regex names.
    if (!/NUL/.test(label)) expect(claudeWordExpands(text)).toBe(true);
    expect(claudeTranscriptNamed(text)).toBe(true);
  });

  // The precise join alone (no fragment backstop) names these: each piece is
  // assembled from values the command itself spells.
  it.each<[string, string]>([
    ['${…:-word}', `cp s ${H}/.cla\${u:-ude/projects/p/s.jsonl}`],
    ['$(printf %s …)', `cp s ${H}/.cla$(printf %s ude/projects/p/s.jsonl)`],
    ['A=…; B=…; $A$B', `A=${H}/.cla; B=ude/projects/p/s.jsonl; cp s $A$B`],
    ['A+= append', `A=${H}/.cl; A+=a; cp s \${A}ude/projects/p/s.jsonl`],
    ['composed glob', `cp s ${H}/.cl[a]ude/proj[e]cts/p/s.jsonl`],
    ['brace alternatives', `cp s ${H}/.cl{x,a}ude/projects/p/s.jsonl`],
    ['printf octal escapes', "cp s $(printf '\\056\\143laude')/projects/p/s.jsonl"],
    ['printf -v with a three-way split', `printf -v A %s%s%s ${H}/.cl au de/projects/p/s.jsonl; cp s "$A"`],
  ])('joined: %s', (_label, text) => {
    expect(claudeJoinedWordMayBeTranscript(text)).toBe(true);
  });

  it.each(joinedControls(H, '/tmp/forged.jsonl', 's.jsonl').filter(([l]) => !/\(a read\)/.test(l)))('not refused: %s', (_label, text) => {
    expect(claudeWordExpands(text)).toBe(false);
  });

  it('a glob never matches a leading dot: .c*/… is refused, */projects/… is not', () => {
    expect(claudeJoinedWordMayBeTranscript(`cp s ${H}/.c*/projects/p/s.jsonl`)).toBe(true);
    expect(claudeJoinedWordMayBeTranscript(`cp s ${H}/*/projects/p/s.jsonl`)).toBe(false);
    expect(claudeJoinedWordMayBeTranscript(`shopt -s dotglob; cp s ${H}/*/projects/p/s.jsonl`)).toBe(true);
  });

  it('bash cuts an ANSI-C string at a NUL, and so does the tokenizer', () => {
    expect(words("$'.claude\\0junk'/projects")).toEqual(['.claude/projects']);
    expect(words("$'a\\x00b'c")).toEqual(['ac']);
  });
});
