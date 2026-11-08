/**
 * #992 — interactive recall returned the same top-k for unrelated prompts.
 *
 * OpenClaw 2026.10.x hands a CLI-backend turn to the agent with the owner's
 * text wrapped in boilerplate the #717 sanitiser did not know about:
 *
 *   - a leading envelope timestamp, "[Tue 2026-11-03 11:48 UTC] ", which the
 *     #717 code only removed after a ⟦openclaw:ctx⟧ envelope;
 *   - closed `<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>` … `<<<END_…>>>` blocks;
 *   - trailing visible-reply guidance paragraphs ("You can participate in the
 *     conversation throughout your work. …", "Commentary is optional …",
 *     "`send`: `message`; …", "## UI Presentation" …);
 *   - a trailing "OpenClaw runtime context:" … "End OpenClaw runtime context."
 *     block.
 *
 * The recall query is the first six distinct terms of the sanitised prompt
 * (extractQueryTerms), so the timestamp alone took four of the six slots
 * ("tue", the date, the time, "utc") on every turn, and a short owner message
 * had the rest filled from the guidance. Every turn then OR-matched the same
 * notes. The fixtures below are the 2026.10.9 shapes, taken from the emitters
 * (buildHarnessVisibleReplyGuidance, labelRuntimeContextText and the runtime
 * context markers) with synthetic owner text.
 */
import { describe, it, expect, beforeAll, afterEach } from '@jest/globals';
import { execFileSync } from 'node:child_process';
import Database from 'better-sqlite3';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCHEMA = readFileSync(join(repoRoot, 'src', 'database', 'schema.sql'), 'utf8');
const PROJECT = 'wrap992';
const CWD = `/tmp/${PROJECT}`;

let sanitisePromptForRecall: (s: string) => string;
let extractQueryTerms: (s: string) => string[];

beforeAll(async () => {
  ({ sanitisePromptForRecall } = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'prompt-sanitiser.mjs')).href));
  ({ extractQueryTerms } = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-relevance.mjs')).href));
});

// ── 2026.10.9 wrapper text (verbatim from the OpenClaw emitters) ──────────
const PARTICIPATE =
  'You can participate in the conversation throughout your work. Use `message` when you have something worth saying; ' +
  'you don’t need to wait until you’re finished, and sending a message doesn’t end your task. OpenClaw delivers your final response automatically.';
const TARGET_DEFAULT = '`send`: `message`; current source is default target. Set `target` only elsewhere.';
const COMMENTARY_TOOL =
  'Commentary is optional progress and may be hidden. Answer user questions or status requests received during ongoing work with ' +
  '`message(action=send, final=false)`, then continue the task. Before finishing, deliver every still-pending answer through this ' +
  "turn's visible-reply route. Do not repeat answers already delivered.";
const REPLY_NORMALLY =
  'For the current source conversation, reply normally in your final assistant message; OpenClaw will deliver it through the active source conversation.';
const COMMENTARY_FINAL =
  'Commentary is optional progress and may be hidden. Include answers to every still-pending user question, including questions received during ongoing work, in your final response.';
const UI_PRESENTATION = [
  '## UI Presentation',
  '`dashboard`: layout/plugin widgets, not HTML authoring; never for opening a browser side panel. For a saved widget, use action="focus_tab" with its tabId.',
  'Inspect widgets in their chat/dashboard frame; do not open hosting URLs as browser pages. Verify the delivered interaction or say unverified.',
].join('\n');
const RUNTIME_CONTEXT = [
  'OpenClaw runtime context:',
  '## Media Generation Tasks',
  '- tool=image_generate; none',
  '- tool=music_generate; none',
  'End OpenClaw runtime context.',
].join('\n');
const BEGIN = '<<<BEGIN_OPENCLAW_INTERNAL_CONTEXT>>>';
const END = '<<<END_OPENCLAW_INTERNAL_CONTEXT>>>';

/** An owner chat turn as the CLI backend receives it (interactive lane). */
function ownerTurn(text: string, minute = 48): string {
  return [
    `[Tue 2026-11-03 11:${String(minute).padStart(2, '0')} UTC] ${text}`,
    PARTICIPATE,
    TARGET_DEFAULT,
    COMMENTARY_TOOL,
    UI_PRESENTATION,
    RUNTIME_CONTEXT,
  ].join('\n\n');
}

/** A turn whose owner text sits between internal-context blocks. */
function internalContextTurn(text: string): string {
  return [
    `[Tue 2026-11-03 11:53 UTC] ${BEGIN}\n\n[Subagent Context] You are running as a subagent (depth 1/5).\n\n${END}`,
    text,
    `${BEGIN}\n\nBegin. Execute the assigned task to completion.\n\n${END}`,
    REPLY_NORMALLY,
    COMMENTARY_FINAL,
    RUNTIME_CONTEXT,
  ].join('\n\n');
}

const QUESTIONS = [
  'fix the boiler',
  'invoice for Acme?',
  'Book the dentist',
  'renew passport',
  'Is the kayak club open on Sunday?',
];

describe('sanitisePromptForRecall — OpenClaw 2026.10.x turn boilerplate (#992)', () => {
  for (const q of QUESTIONS) {
    it(`reduces an owner turn to the owner text: ${q}`, () => {
      expect(sanitisePromptForRecall(ownerTurn(q))).toBe(q);
    });
    it(`reduces an internal-context turn to the owner text: ${q}`, () => {
      expect(sanitisePromptForRecall(internalContextTurn(q))).toBe(q);
    });
  }

  it('different questions in an identical wrapper give disjoint query terms with no wrapper words', () => {
    const termSets = QUESTIONS.map((q) => extractQueryTerms(sanitisePromptForRecall(ownerTurn(q))));
    const wrapperWords = new Set(
      extractQueryTerms(`tue 2026-11-03 11:48 utc ${PARTICIPATE}`).concat(extractQueryTerms(COMMENTARY_TOOL)),
    );
    for (const terms of termSets) {
      expect(terms.length).toBeGreaterThan(0);
      for (const t of terms) expect(wrapperWords.has(t)).toBe(false);
    }
    expect(new Set(termSets.map((t) => t.join(' '))).size).toBe(QUESTIONS.length);
  });

  it('keeps the owner text when it quotes a guidance sentence mid-paragraph', () => {
    const owner = 'Why does it say "You can participate in the conversation throughout your work." in my prompt?';
    expect(sanitisePromptForRecall(ownerTurn(owner))).toBe(owner);
  });

  it('keeps an owner paragraph that is not trailing boilerplate', () => {
    const owner = `${COMMENTARY_FINAL}\n\nWhat does that line mean?`;
    expect(sanitisePromptForRecall(owner)).toBe(owner);
  });

  it('leaves an unclosed internal-context marker and an unterminated runtime header alone', () => {
    const unclosed = `${BEGIN}\nplease explain this marker`;
    expect(sanitisePromptForRecall(unclosed)).toBe(unclosed);
    const header = 'OpenClaw runtime context:\nwhat is this header for?';
    expect(sanitisePromptForRecall(header)).toBe(header);
  });

  // ── Review of 1b6cd82b (CASE-Drakon 5754304206, TARSDrakon 6604727129) ──
  // B1: a trailing paragraph that starts with a guidance sentence but carries
  // owner text after it lost the whole paragraph. Only the known sentence(s)
  // are boilerplate; the remainder is the owner's and stays.
  it('B1: keeps owner text that follows a guidance opener in the trailing paragraph (participate)', () => {
    const input = 'The logs contain this line.\n\nYou can participate in the conversation throughout your work. Why is this injected, and fix the boiler pressure valve?';
    expect(sanitisePromptForRecall(input)).toBe('The logs contain this line.\n\nWhy is this injected, and fix the boiler pressure valve?');
  });
  it('B1: keeps owner text that follows the `send` target line in the trailing paragraph', () => {
    const input = `Read this.\n\n${TARGET_DEFAULT} Does that mean my reply goes to Telegram?`;
    expect(sanitisePromptForRecall(input)).toBe('Read this.\n\nDoes that mean my reply goes to Telegram?');
  });
  it('B1: keeps owner text that follows the UI Presentation block in the trailing paragraph', () => {
    const input = `Read this.\n\n${UI_PRESENTATION}\nWhy is this section in every prompt?`;
    expect(sanitisePromptForRecall(input)).toBe('Read this.\n\nWhy is this section in every prompt?');
  });
  it('B1: a whole owner turn whose message ends with a guidance quote plus a question keeps the question', () => {
    const owner = `Look: ${COMMENTARY_FINAL} What does it want from me?`;
    // Quoted mid-paragraph (not at the paragraph start): the paragraph is owner text and is kept whole.
    expect(sanitisePromptForRecall(ownerTurn(owner))).toBe(owner);
  });

  // B2: closed internal-context / runtime-context pairs were stripped wherever
  // they appeared, so an owner message that IS a complete pair became "" and
  // the hook exited gated:prompt-too-short. A pair is stripped only when it is
  // anchored to the 2026.10.x envelope; a whole-message or mid-text quote is
  // kept, and a step that would leave nothing falls back to its input.
  it('B2: an owner message that is itself a closed internal-context pair is kept', () => {
    const input = `${BEGIN}\nplease explain this marker\n${END}`;
    expect(sanitisePromptForRecall(input)).toBe(input);
  });
  it('B2: an owner message that is itself a closed runtime-context pair is kept', () => {
    const input = 'OpenClaw runtime context:\nhello owner\nEnd OpenClaw runtime context.';
    expect(sanitisePromptForRecall(input)).toBe(input);
  });
  it('B2: a closed pair quoted mid-text in an owner turn is kept', () => {
    const owner = `I keep seeing this:\n\n${BEGIN}\nsome framework words\n${END}\n\nwhat is it for?`;
    expect(sanitisePromptForRecall(ownerTurn(owner))).toBe(owner);
    const rt = `I keep seeing this:\n\n${RUNTIME_CONTEXT}\n\nwhat is it for?`;
    expect(sanitisePromptForRecall(ownerTurn(rt))).toBe(rt);
  });
  it('B2: the leading internal-context block is stripped only when it opens the prompt', () => {
    // Anchored: opens the prompt (after the envelope timestamp) — stripped.
    expect(sanitisePromptForRecall(`[Tue 2026-11-03 11:53 UTC] ${BEGIN}\n\n[Subagent Context] depth 1/5.\n\n${END}\n\nrenew passport`)).toBe('renew passport');
    expect(sanitisePromptForRecall(`${BEGIN}\n\n[Subagent Context] depth 1/5.\n\n${END}\n\nrenew passport`)).toBe('renew passport');
  });

  it('still strips the #717 envelope and then the 2026.10.x trailer', () => {
    const MARK = '⟦openclaw:ctx⟧';
    const wrapped = [
      `Conversation info: ${MARK}`,
      '```json',
      JSON.stringify({ chat_id: 'telegram:100000001', message_id: '90004' }),
      '```',
      '',
      `[Tue 2026-11-03 11:48 UTC] renew passport`,
      '',
      PARTICIPATE,
      '',
      RUNTIME_CONTEXT,
    ].join('\n');
    expect(sanitisePromptForRecall(wrapped)).toBe('renew passport');
  });
});

// ── End to end: the real hook, N questions, identical wrapper ─────────────

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function buildPackage(): string {
  const pkg = mkdtempSync(join(tmpdir(), 'sc-992-pkg-'));
  tmpDirs.push(pkg);
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ type: 'module' }));
  symlinkSync(join(repoRoot, 'node_modules'), join(pkg, 'node_modules'), 'dir');
  cpSync(join(repoRoot, 'scripts'), join(pkg, 'scripts'), { recursive: true });
  return pkg;
}

function makeHome(): { home: string; db: Database.Database } {
  const home = mkdtempSync(join(tmpdir(), 'sc-992-home-'));
  tmpDirs.push(home);
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ proactiveRecall: true, captureEvents: false }));
  const db = new Database(join(home, '.shieldcortex', 'memories.db'));
  db.exec(SCHEMA);
  return { home, db };
}

function insert(db: Database.Database, title: string, content: string): number {
  const info = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project, salience, trust_score, sensitivity_level, status)
     VALUES (lower(hex(randomblob(16))), 'long_term', 'note', ?, ?, ?, 0.9, 1.0, 'PUBLIC', 'active')`,
  ).run(title, content, PROJECT);
  return Number(info.lastInsertRowid);
}

function runHook(pkg: string, home: string, prompt: string): Record<string, any> {
  const env: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home };
  for (const key of Object.keys(env)) {
    if (key.startsWith('SHIELDCORTEX_') || key === 'CLAUDE_MEMORY_DB') delete env[key];
  }
  try {
    execFileSync('node', [join(pkg, 'scripts', 'prompt-recall-hook.mjs')], {
      input: JSON.stringify({ prompt, cwd: CWD, session_id: null }),
      env: env as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch { /* the recall log is the evidence */ }
  // Remove the dedup ring so each turn ranks on its own.
  rmSync(join(home, '.shieldcortex', '.recall-dedup.json'), { force: true });
  return JSON.parse(readFileSync(join(home, '.shieldcortex', 'recall-log', '0.json'), 'utf8'));
}

describe('prompt-recall hook: N owner questions in an identical wrapper (#992)', () => {
  it('does not return the same top-k for unrelated questions, and finds each topic note', () => {
    const pkg = buildPackage();
    const { home, db } = makeHome();
    // Notes that share the wrapper's words: what the regression recalled every turn.
    const wrapperNotes = [
      insert(db, 'Message delivery during ongoing work', 'Tue UTC: participate in the conversation throughout your work; message tool delivery.'),
      insert(db, 'OpenClaw message protocol', 'Tue 2026-11-03 UTC conversation message protocol for ongoing work and commentary.'),
      insert(db, 'Commentary rules', 'Commentary is optional progress; answer user questions during ongoing work. Tue UTC.'),
    ];
    const topics = [
      insert(db, 'Boiler service', 'The boiler needs a service; fix the boiler pressure valve.'),
      insert(db, 'Acme invoice', 'Invoice for Acme is due on the 30th.'),
      insert(db, 'Dentist booking', 'Book the dentist for a check-up next month.'),
      insert(db, 'Passport renewal', 'Renew passport before the summer trip.'),
    ];
    // A second note per topic, so a top-5 set is decided by the question and
    // not by the handful of rows that share a common word such as "the".
    insert(db, 'Boiler pressure', 'Boiler pressure dropped again; fix before winter.');
    insert(db, 'Acme account', 'Acme account: invoice terms are 30 days.');
    insert(db, 'Dentist reminder', 'Dentist reminder: book a hygienist slot too.');
    insert(db, 'Passport photos', 'Passport photos needed to renew online.');
    db.close();

    const topK: string[] = [];
    QUESTIONS.slice(0, 4).forEach((q, i) => {
      const log = runHook(pkg, home, ownerTurn(q, 40 + i));
      expect(log.lane).toBe('interactive');
      // The candidate list can still hold rows that share a common word with
      // the question ("the"); what matters is the ranking and what is injected.
      const cands: Array<{ id: number; injected: boolean }> = log.candidates;
      expect(cands[0].id).toBe(topics[i]);
      const injected = cands.filter((c) => c.injected).map((c) => c.id);
      expect(injected).toContain(topics[i]);
      // Before #992 a wrapper note took the first rank on every question.
      for (const w of wrapperNotes) {
        const at = cands.findIndex((c) => c.id === w);
        if (at >= 0) expect(at).toBeGreaterThan(0);
      }
      topK.push(cands.slice(0, 5).map((c) => c.id).sort((a, b) => a - b).join(','));
    });
    expect(new Set(topK).size).toBe(4);
  });
});

describe('prompt-recall hook: lane detection around the 2026.10.x wrapper (#992)', () => {
  it('a timestamped liveness probe is the automation lane, not an interactive run', () => {
    const pkg = buildPackage();
    const { home, db } = makeHome();
    insert(db, 'Liveness probe pattern', 'Automated liveness check from the watchdog timer on this box.');
    db.close();
    const probe = '[Tue 2026-11-03 11:45 UTC] Automated liveness check from a watchdog timer. Reply with one line: OK';
    const log = runHook(pkg, home, probe);
    expect(log.lane).toBe('automation');
    expect(log.candidates).toEqual([]);
  });

  it('a subagent marker inside an internal-context block still selects the subagent lane', () => {
    const pkg = buildPackage();
    const { home, db } = makeHome();
    insert(db, 'Passport renewal', 'Renew passport before the summer trip.');
    db.close();
    const log = runHook(pkg, home, internalContextTurn('renew passport'));
    expect(log.lane).toBe('subagent');
    expect(log.prompt).toBe('renew passport');
  });
});
