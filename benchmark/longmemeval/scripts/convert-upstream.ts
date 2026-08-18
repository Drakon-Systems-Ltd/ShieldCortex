/**
 * Convert upstream LongMemEval JSON (cleaned HF release) → harness JSONL.
 *
 * Upstream shape (per README):
 *   question_id, question, answer_session_ids,
 *   haystack_session_ids: string[],
 *   haystack_sessions: Turn[][]   // parallel to ids; each session is turns[]
 *   haystack_dates?: string[]
 *
 * Harness shape (types.ts):
 *   question_id, question, answer_session_ids,
 *   haystack_sessions: { session_id, turns: {role,content,ts?}[] }[]
 *
 * Does NOT download data (license: fetch separately). See fetch-longmemeval-s.sh.
 *
 * Usage:
 *   npx tsx benchmark/longmemeval/scripts/convert-upstream.ts \
 *     --in ~/.shieldcortex/benchmark/longmemeval/longmemeval_s_cleaned.json \
 *     --out ~/.shieldcortex/benchmark/longmemeval/longmemeval-s.jsonl \
 *     [--limit N] [--seed 42]
 */
import { createHash } from 'crypto';
import { createReadStream, createWriteStream, existsSync, readFileSync, mkdirSync, writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { createInterface } from 'readline';

interface Cli {
  inPath: string;
  outPath: string;
  limit: number | null;
  seed: number;
  statsPath: string | null;
}

function parseArgs(argv: string[]): Cli {
  const cli: Cli = {
    inPath: '',
    outPath: '',
    limit: null,
    seed: 42,
    statsPath: null,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--in' && argv[i + 1]) { cli.inPath = resolve(argv[++i]); }
    else if (a === '--out' && argv[i + 1]) { cli.outPath = resolve(argv[++i]); }
    else if (a === '--limit' && argv[i + 1]) { cli.limit = Number.parseInt(argv[++i], 10); }
    else if (a === '--seed' && argv[i + 1]) { cli.seed = Number.parseInt(argv[++i], 10); }
    else if (a === '--stats' && argv[i + 1]) { cli.statsPath = resolve(argv[++i]); }
    else if (a === '--help' || a === '-h') {
      console.log(`Usage: convert-upstream.ts --in <upstream.json|jsonl> --out <harness.jsonl> [--limit N] [--seed 42]`);
      process.exit(0);
    } else {
      throw new Error(`Unknown arg: ${a}`);
    }
  }
  if (!cli.inPath || !cli.outPath) throw new Error('--in and --out required');
  return cli;
}

/** Mulberry32 PRNG for deterministic subset sampling. */
function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6D2B79F5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r ^= r + Math.imul(r ^ (r >>> 7), 61 | r);
    return ((r ^ (r >>> 14)) >>> 0) / 4294967296;
  };
}

function loadUpstream(path: string): unknown[] {
  if (!existsSync(path)) throw new Error(`input not found: ${path}`);
  const raw = readFileSync(path, 'utf-8');
  const trimmed = raw.trim();
  if (trimmed.startsWith('[')) {
    const parsed = JSON.parse(trimmed);
    if (!Array.isArray(parsed)) throw new Error('JSON root is not an array');
    return parsed;
  }
  // JSONL
  return trimmed.split(/\r?\n/).filter(Boolean).map((line, i) => {
    try { return JSON.parse(line); }
    catch (e) { throw new Error(`JSONL line ${i + 1}: ${(e as Error).message}`); }
  });
}

function isTurn(x: unknown): x is { role: string; content: string; ts?: string; has_answer?: boolean } {
  return !!x && typeof x === 'object' && typeof (x as any).role === 'string' && typeof (x as any).content === 'string';
}

/**
 * Convert one upstream question object to harness form.
 * Accepts both already-normalised harness objects and official LongMemEval.
 */
export function convertQuestion(raw: unknown, index: number): {
  question_id: string;
  question: string;
  answer_session_ids: string[];
  haystack_sessions: { session_id: string; turns: { role: 'user' | 'assistant'; content: string; ts?: string }[] }[];
} {
  if (!raw || typeof raw !== 'object') throw new Error(`item ${index} not object`);
  const o = raw as Record<string, unknown>;
  const question_id = String(o.question_id || o.questionId || `q-${index}`);
  const question = String(o.question || '');
  if (!question) throw new Error(`${question_id}: empty question`);

  const answer_session_ids = Array.isArray(o.answer_session_ids)
    ? (o.answer_session_ids as unknown[]).map(String)
    : [];

  // Already harness-shaped?
  if (Array.isArray(o.haystack_sessions) && o.haystack_sessions[0]
    && typeof o.haystack_sessions[0] === 'object'
    && !Array.isArray(o.haystack_sessions[0])
    && 'session_id' in (o.haystack_sessions[0] as object)
    && 'turns' in (o.haystack_sessions[0] as object)) {
    return {
      question_id,
      question,
      answer_session_ids,
      haystack_sessions: (o.haystack_sessions as any[]).map((s) => ({
        session_id: String(s.session_id),
        turns: (s.turns || []).filter(isTurn).map((t: any) => ({
          role: t.role === 'assistant' ? 'assistant' as const : 'user' as const,
          content: String(t.content),
          ...(typeof t.ts === 'string' ? { ts: t.ts } : {}),
        })),
      })),
    };
  }

  // Official: parallel arrays haystack_session_ids + haystack_sessions (Turn[][])
  const ids = Array.isArray(o.haystack_session_ids)
    ? (o.haystack_session_ids as unknown[]).map(String)
    : [];
  const sessionsRaw = Array.isArray(o.haystack_sessions) ? (o.haystack_sessions as unknown[]) : [];
  const dates = Array.isArray(o.haystack_dates) ? (o.haystack_dates as unknown[]).map(String) : [];

  if (sessionsRaw.length === 0) {
    throw new Error(`${question_id}: no haystack_sessions`);
  }

  const haystack_sessions = sessionsRaw.map((sess, sIdx) => {
    const session_id = ids[sIdx] || `${question_id}-sess-${sIdx}`;
    const turnsSrc = Array.isArray(sess) ? sess : (sess && typeof sess === 'object' && Array.isArray((sess as any).turns) ? (sess as any).turns : []);
    const turns = (turnsSrc as unknown[]).filter(isTurn).map((t, tIdx) => {
      const role = t.role === 'assistant' ? 'assistant' as const : 'user' as const;
      const content = String(t.content || '');
      const ts = typeof (t as any).ts === 'string'
        ? (t as any).ts
        : (dates[sIdx] ? `${dates[sIdx]}#${tIdx}` : undefined);
      return ts ? { role, content, ts } : { role, content };
    }).filter((t) => t.content.length > 0);
    return { session_id, turns };
  }).filter((s) => s.turns.length > 0);

  if (haystack_sessions.length === 0) {
    throw new Error(`${question_id}: all sessions empty after convert`);
  }

  return { question_id, question, answer_session_ids, haystack_sessions };
}

function main(): void {
  const cli = parseArgs(process.argv.slice(2));
  const items = loadUpstream(cli.inPath);
  console.log(`[convert] loaded ${items.length} upstream item(s) from ${cli.inPath}`);

  let selected = items.map((it, i) => ({ it, i }));
  if (cli.limit != null && cli.limit > 0 && cli.limit < selected.length) {
    const rnd = mulberry32(cli.seed);
    // Fisher-Yates partial shuffle for deterministic subset
    for (let i = selected.length - 1; i > 0; i--) {
      const j = Math.floor(rnd() * (i + 1));
      [selected[i], selected[j]] = [selected[j], selected[i]];
    }
    selected = selected.slice(0, cli.limit);
    console.log(`[convert] sampled limit=${cli.limit} seed=${cli.seed}`);
  }

  mkdirSync(dirname(cli.outPath), { recursive: true });
  const out = createWriteStream(cli.outPath, { encoding: 'utf-8' });
  let ok = 0;
  let fail = 0;
  const typeCounts: Record<string, number> = {};
  for (const { it, i } of selected) {
    try {
      const q = convertQuestion(it, i);
      const qtype = typeof (it as any)?.question_type === 'string' ? (it as any).question_type : 'unknown';
      typeCounts[qtype] = (typeCounts[qtype] || 0) + 1;
      out.write(JSON.stringify(q) + '\n');
      ok++;
    } catch (e) {
      fail++;
      console.warn(`[convert] skip index=${i}: ${(e as Error).message}`);
    }
  }
  out.end();

  const stats = {
    source: cli.inPath,
    out: cli.outPath,
    source_count: items.length,
    written: ok,
    skipped: fail,
    limit: cli.limit,
    seed: cli.seed,
    question_types: typeCounts,
    sha256_note: 'hash after write via sha256sum',
  };
  console.log(`[convert] wrote ${ok} questions (${fail} skipped) → ${cli.outPath}`);
  console.log(`[convert] types`, typeCounts);
  if (cli.statsPath) {
    writeFileSync(cli.statsPath, JSON.stringify(stats, null, 2));
    console.log(`[convert] stats → ${cli.statsPath}`);
  }
}

const isDirect = typeof process.argv[1] === 'string' && /convert-upstream\.ts$/.test(process.argv[1]);
if (isDirect) {
  try {
    main();
  } catch (e) {
    console.error(`[convert] fatal: ${(e as Error).message}`);
    process.exit(1);
  }
}
