/**
 * #718 — recall scoped by lane, not just project; PERSONAL sensitivity tier.
 *
 * Acceptance from the issue:
 *   - replaying the watchdog prompt yields injectedCount 0 with lane automation
 *     in the recall log;
 *   - a memory-13195-shaped fixture classifies PERSONAL and is excluded from a
 *     cron-lane recall;
 *   - owner-chat recall is unaffected.
 * All fixture text is invented.
 */
import { describe, it, expect, beforeAll, afterEach } from '@jest/globals';
import { execFileSync } from 'node:child_process';
import Database from 'better-sqlite3';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { classifySensitivity } from '../defence/sensitivity/index.js';
import { isIsolatedSensitivity } from '../defence/sensitivity/isolation.js';
import { reclassifyMemories } from '../cli/reclassify.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'prompt-recall-hook.mjs');
const SCHEMA = readFileSync(join(repoRoot, 'src', 'database', 'schema.sql'), 'utf8');
const PROJECT = 'lane718';

// Shaped like the mc-watchdog probe in the issue's evidence.
const WATCHDOG_PROMPT =
  'Automated liveness check from mc-watchdog (systemd user timer on this box). Purpose: confirm the CLI backend ' +
  'is still registered. No action needed — just reply with the single line WD_OK so the script can log a healthy probe.';
const CRON_PROMPT =
  '[cron:job-1234 digest] family trip deploy errors summary for yesterday.\n\n' +
  'This is an unattended scheduled run. Nobody is present to clarify or approve.';
// Shaped like memory 13195: personal, high salience, stored PUBLIC pre-#718.
const FAMILY_TITLE = 'Surprise family trip';
const FAMILY_CONTENT = 'Booked a surprise trip to the coast for Sam\'s birthday with the kids in May; do not tell her before the weekend.';

type Lane = { lane: string; signal: string };
let laneMod: {
  detectLane: (i: { text?: string; env?: Record<string, string | undefined> }) => Lane;
  resolveLanePolicy: (lane: string, config?: Record<string, unknown>) => { recall: boolean; categories: string[] | null };
  applyLanePolicy: (
    rows: Array<Record<string, unknown>>, lane: string, policy: { recall: boolean; categories: string[] | null },
    normaliseLabel?: (level: unknown) => string | null,
  ) => {
    kept: Array<Record<string, unknown>>; withheld: Array<{ row: Record<string, unknown>; reason: string }>;
  };
  loadLabelNormaliser: (distRootOverride?: string) => Promise<(level: unknown) => string | null>;
  strictLabelNormaliser: (level: unknown) => string | null;
};

// #722 review R1: labels that Unicode toUpperCase folds onto a known tier
// (dotless i, long s) or that only look like one (script l, fullwidth). The
// isolation gate keeps every one of them unknown — isolated — and so must the
// lane filter and the backfill.
const NON_ASCII_LABELS = ['publıc', 'ınternal', 'ſecret', 'pubℓic', 'ＰＵＢＬＩＣ', 'Ｐublic'];

beforeAll(async () => {
  laneMod = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-lane.mjs')).href);
});

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

describe('detectLane (#718)', () => {
  it('recognises the watchdog liveness probe as automation', () => {
    expect(laneMod.detectLane({ text: WATCHDOG_PROMPT })).toEqual({ lane: 'automation', signal: 'marker:liveness-check' });
  });

  it('recognises OpenClaw heartbeat prompts as automation', () => {
    expect(laneMod.detectLane({ text: 'Follow the heartbeat monitor scratch context when provided. Recurring tasks are automations.' }).lane).toBe('automation');
    expect(laneMod.detectLane({ text: 'Read HEARTBEAT.md if it exists.' }).lane).toBe('automation');
  });

  it('recognises cron runs and cron events', () => {
    expect(laneMod.detectLane({ text: CRON_PROMPT }).lane).toBe('cron');
    expect(laneMod.detectLane({ text: 'A scheduled reminder has been triggered. The reminder content is: water plants' }).lane).toBe('cron');
    expect(laneMod.detectLane({ text: '[Scheduled Run] weekly report' }).lane).toBe('cron');
  });

  it('recognises subagent tasks', () => {
    expect(laneMod.detectLane({ text: '[Subagent Context] You are running as a subagent (depth 1/2).\n\n[Subagent Task]\nfix the build' }).lane).toBe('subagent');
  });

  it('defaults an ordinary owner message to interactive', () => {
    expect(laneMod.detectLane({ text: 'Is ShieldCortex any good now?' })).toEqual({ lane: 'interactive', signal: 'default' });
  });

  it('ignores a marker quoted mid-sentence', () => {
    expect(laneMod.detectLane({ text: 'why does the probe say "Automated liveness check" every 15 minutes?' }).lane).toBe('interactive');
  });

  it('honours the operator pin', () => {
    expect(laneMod.detectLane({ text: 'hello there friend', env: { SHIELDCORTEX_RECALL_LANE: 'Cron' } }).lane).toBe('cron');
    expect(laneMod.detectLane({ text: CRON_PROMPT, env: { SHIELDCORTEX_RECALL_LANE: 'interactive' } }))
      .toEqual({ lane: 'interactive', signal: 'env:SHIELDCORTEX_RECALL_LANE' });
  });

  // #722 review R4: an invalid pin used to read as "no pin", so an unmarked
  // job with a typo'd pin recalled as interactive.
  it.each(['bogus', 'nightly', 'crom', 'ınteractive', 'interactive-ish'])('an invalid pin (%s) fails safe to automation', (pin) => {
    expect(laneMod.detectLane({ text: 'hello there friend', env: { SHIELDCORTEX_RECALL_LANE: pin } }))
      .toEqual({ lane: 'automation', signal: 'env:SHIELDCORTEX_RECALL_LANE:invalid' });
    expect(laneMod.detectLane({ text: WATCHDOG_PROMPT, env: { SHIELDCORTEX_RECALL_LANE: pin } }).lane).toBe('automation');
  });

  it('an unset or blank pin is no pin', () => {
    for (const pin of [undefined, '', '   ']) {
      expect(laneMod.detectLane({ text: 'hello there friend', env: { SHIELDCORTEX_RECALL_LANE: pin } }))
        .toEqual({ lane: 'interactive', signal: 'default' });
    }
  });

  it('takes the most restrictive lane when markers from two lanes appear', () => {
    expect(laneMod.detectLane({ text: `[Subagent Task]\n${WATCHDOG_PROMPT}` }).lane).toBe('automation');
  });
});

// #722 review B1: every marker used `^\s*` with the m flag, so a long run of
// line breaks was re-scanned from every line start (quadratic — 100 KB of blank
// lines took 33 s on the reviewer's box, 189 s on the CI ARM box) and the
// unclosed cron marker backtracked over overlapping classes. The hook budget is
// 5 s (settings-hooks.ts). Each pathological input is paired with a long
// positive so the fix cannot "pass" by giving up on long prompts.
describe('detectLane stays linear on adversarial prompts (#722 B1)', () => {
  const N = 100_000;
  const BUDGET_MS = 200;
  const LS = String.fromCharCode(0x2028);
  const timed = (text: string) => {
    const t0 = performance.now();
    const result = laneMod.detectLane({ text });
    return { result, ms: performance.now() - t0 };
  };

  const cases: Array<[string, string]> = [
    ['blank lines', '\n'.repeat(N)],
    ['" \\n" lines', ' \n'.repeat(N / 2)],
    ['"[cron:" + unclosed run', '[cron:' + 'a'.repeat(N)],
    ['unclosed "[cron:aaa…" lines', ('[cron:' + 'a'.repeat(30) + '\n').repeat(Math.ceil(N / 37))],
    ['bare CR line breaks', '\r'.repeat(N)],
    ['U+2028 line separators', LS.repeat(N)],
  ];

  it.each(cases)('%s (>=100 KB) classifies within the hook budget', (_name, text) => {
    expect(text.length).toBeGreaterThanOrEqual(N);
    const { result, ms } = timed(text);
    expect(result).toEqual({ lane: 'interactive', signal: 'default' });
    expect(ms).toBeLessThan(BUDGET_MS);
  });

  it.each(cases)('a marker after %s is still detected', (_name, padding) => {
    const markers: Array<[string, string]> = [
      [WATCHDOG_PROMPT, 'automation'],
      ['  [cron:job-1234 digest] summary', 'cron'],
      ['\t[Subagent Task]', 'subagent'],
    ];
    for (const [marker, lane] of markers) {
      const { result, ms } = timed(`${padding}\n${marker}`);
      expect(result.lane).toBe(lane);
      expect(ms).toBeLessThan(BUDGET_MS);
    }
  });

  it('a cron marker still needs its closing bracket on the same line', () => {
    expect(laneMod.detectLane({ text: '[cron:job-1\n] tail' }).lane).toBe('interactive');
    expect(laneMod.detectLane({ text: '[cron:job-1 nightly digest]' }).lane).toBe('cron');
  });

  it('indentation before a marker is still allowed, a line break is just a line break', () => {
    expect(laneMod.detectLane({ text: 'hello\n \t [Scheduled Run] weekly report' }).lane).toBe('cron');
    expect(laneMod.detectLane({ text: 'hello\r\n\r\nRead HEARTBEAT.md now' }).lane).toBe('automation');
  });
});

describe('lane policy (#718)', () => {
  it('safe defaults', () => {
    expect(laneMod.resolveLanePolicy('automation')).toEqual({ recall: false, categories: ['error', 'pattern', 'decision'] });
    expect(laneMod.resolveLanePolicy('cron')).toEqual({ recall: true, categories: ['error', 'pattern', 'decision'] });
    expect(laneMod.resolveLanePolicy('interactive')).toEqual({ recall: true, categories: null });
  });

  it('config can opt automation in and change categories, ignoring junk', () => {
    const cfg = { recallLanes: { automation: { recall: true, categories: ['Error', 7, ''] }, cron: { recall: 'yes' } } };
    expect(laneMod.resolveLanePolicy('automation', cfg)).toEqual({ recall: true, categories: ['error'] });
    expect(laneMod.resolveLanePolicy('cron', cfg).recall).toBe(true);
  });

  it('a non-interactive lane only ever receives PUBLIC rows, whatever the config says', () => {
    const rows = [
      { id: 1, category: 'error', sensitivity_level: 'PUBLIC' },
      { id: 2, category: 'error', sensitivity_level: 'INTERNAL' },
      { id: 3, category: 'error', sensitivity_level: 'PERSONAL' },
      { id: 4, category: 'error', sensitivity_level: null },
      { id: 5, category: 'context', sensitivity_level: 'PUBLIC' },
    ];
    const out = laneMod.applyLanePolicy(rows, 'cron', { recall: true, categories: null });
    expect(out.kept.map((r) => r.id)).toEqual([1, 5]);
    const strict = laneMod.applyLanePolicy(rows, 'cron', laneMod.resolveLanePolicy('cron'));
    expect(strict.kept.map((r) => r.id)).toEqual([1]);
    expect(strict.withheld.find((w) => w.row.id === 5)?.reason).toBe('lane_policy:category');
    expect(strict.withheld.find((w) => w.row.id === 3)?.reason).toBe('lane_policy:sensitivity');
  });

  describe('labels are normalised exactly as the isolation gate does (#722 R1)', () => {
    it.each(NON_ASCII_LABELS)('a %s row is isolated to readers and withheld from a non-interactive lane', async (label) => {
      expect(isIsolatedSensitivity(label)).toBe(true);
      const normalise = await laneMod.loadLabelNormaliser();
      expect(normalise).not.toBe(laneMod.strictLabelNormaliser); // the shared helper, from the build
      const rows = [{ id: 1, category: 'error', sensitivity_level: label }];
      for (const n of [normalise, undefined]) {
        const out = laneMod.applyLanePolicy(rows, 'cron', { recall: true, categories: null }, n);
        expect(out.kept).toEqual([]);
        expect(out.withheld[0]?.reason).toBe('lane_policy:sensitivity');
      }
    });

    it('ASCII case and whitespace still normalise to PUBLIC; absent and blank are withheld', async () => {
      const normalise = await laneMod.loadLabelNormaliser();
      const rows = [
        { id: 1, category: 'error', sensitivity_level: ' public ' },
        { id: 2, category: 'error', sensitivity_level: 'Public' },
        { id: 3, category: 'error', sensitivity_level: null },
        { id: 4, category: 'error', sensitivity_level: '  ' },
        { id: 5, category: 'error' },
      ];
      const out = laneMod.applyLanePolicy(rows, 'cron', { recall: true, categories: null }, normalise);
      expect(out.kept.map((r) => r.id)).toEqual([1, 2]);
    });

    it('without a build the fallback admits only an exact PUBLIC label', async () => {
      const empty = mkdtempSync(join(tmpdir(), 'sc-722-nodist-'));
      tmpDirs.push(empty);
      const normalise = await laneMod.loadLabelNormaliser(empty);
      expect(normalise).toBe(laneMod.strictLabelNormaliser);
      const rows = [
        { id: 1, category: 'error', sensitivity_level: 'PUBLIC' },
        { id: 2, category: 'error', sensitivity_level: 'public' },
        { id: 3, category: 'error', sensitivity_level: 'publıc' },
      ];
      expect(laneMod.applyLanePolicy(rows, 'cron', { recall: true, categories: null }, normalise).kept.map((r) => r.id)).toEqual([1]);
    });
  });

  it('interactive keeps everything', () => {
    const rows = [{ id: 1, category: 'context', sensitivity_level: 'PERSONAL' }];
    expect(laneMod.applyLanePolicy(rows, 'interactive', laneMod.resolveLanePolicy('interactive')).kept).toHaveLength(1);
  });
});

describe('PERSONAL sensitivity tier (#718)', () => {
  it('classifies the 13195-shaped memory as PERSONAL', () => {
    const c = classifySensitivity(FAMILY_CONTENT, FAMILY_TITLE);
    expect(c.level).toBe('PERSONAL');
    expect(c.detectedPatterns).toContain('personal-life-event');
  });

  it('does not fire on engineering vocabulary', () => {
    for (const [content, title] of [
      ['The parent process forks a child process per request.', 'Process model'],
      ['Release party is on Friday; ship the trip-wire fix first.', 'Release'],
      ['Use the Inter font family for the dashboard.', 'Fonts'],
      ['Circuit breaker trips after five failures.', 'Resilience'],
    ]) {
      expect([title, classifySensitivity(content, title).level]).toEqual([title, 'PUBLIC']);
    }
  });

  // #722 review B3: each of these classified PERSONAL at 48cc8b7c. PERSONAL is
  // sensitive, so they silently left sync and unattended recall, and
  // `reclassify --execute` made that permanent. The first five are the
  // reviewer's probes verbatim.
  it.each([
    'Stripe partner API: third-party webhooks must be verified before processing',
    'React re-renders all children on every trip through the reconciler',
    'Our partner integration with the payment gateway uses OAuth',
    'Release party: tag v5.6.0 after the family of guard regexes is merged',
    'Holiday freeze: no deploys while the Christmas traffic peak is on, per partner SLA',
    'Gift card checkout: sibling nodes and their parents re-render on every round trip',
    'Our family of plugins ships a surprise fix for the Brother printer driver',
    'Baby steps: the sister project mirrors our partner SLA for the holiday release',
  ])('engineering/business text is not PERSONAL: %s', (content) => {
    expect(classifySensitivity(content, 'note').level).not.toBe('PERSONAL');
  });

  it.each([
    'Surprise birthday trip for my wife in March',
    'My kids birthday trip',
    "Dad's holiday plans",
    'Taking my partner away for our anniversary',
    'Her brother is getting married; the wedding is in June',
    'Planning a birthday party for our daughter',
    'Family trip with the in-laws over half-term',
    'Buying a gift for mum',
    'My family is on holiday next week',
  ])('private-life text is still PERSONAL: %s', (content) => {
    expect(classifySensitivity(content, 'note').level).toBe('PERSONAL');
  });

  it('never lowers a higher tier', () => {
    expect(classifySensitivity('My wife\'s birthday dinner, password: hunter2xx', 'x').level).toBe('RESTRICTED');
    expect(classifySensitivity('Dad\'s holiday plans; diagnosis pending', 'x').level).toBe('CONFIDENTIAL');
  });

  it('is readable by the owner (not isolated like RESTRICTED)', () => {
    expect(isIsolatedSensitivity('PERSONAL')).toBe(false);
  });
});

describe('memories reclassify (#718)', () => {
  function seed(): Database.Database {
    const db = new Database(':memory:');
    db.exec(SCHEMA);
    const ins = db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience, sensitivity_level)
       VALUES (lower(hex(randomblob(16))), 'long_term', 'context', ?, ?, ?, 0.9, ?)`,
    );
    ins.run(FAMILY_TITLE, FAMILY_CONTENT, PROJECT, 'PUBLIC');                       // → PERSONAL
    ins.run('Deploy note', 'Deploys go out on Tuesdays.', PROJECT, 'PUBLIC');       // unchanged
    ins.run('Redacted', 'Contact: [REDACTED:email]', PROJECT, 'CONFIDENTIAL');       // never lowered
    ins.run('Odd', 'My kids birthday trip', PROJECT, 'SECRET');                      // unknown label skipped
    ins.run('Other project', FAMILY_CONTENT, 'elsewhere', 'PUBLIC');
    return db;
  }

  it('dry-run reports raises without writing; --execute applies them', async () => {
    const db = seed();
    const dry = await reclassifyMemories({ db, project: PROJECT });
    expect(dry.dryRun).toBe(true);
    expect(dry.scanned).toBe(4);
    expect(dry.transitions).toEqual({ 'PUBLIC→PERSONAL': 1 });
    // #722 (non-blocking b): per-label counts so a false-positive storm is
    // visible before --execute.
    expect(dry.labels).toEqual({ 'personal-life-event': 1, 'personal-secret': 1 });
    expect(dry.skippedUnknown).toBe(0); // SECRET is on the ladder, above anything the classifier returns
    expect(db.prepare(`SELECT COUNT(*) n FROM memories WHERE sensitivity_level = 'PERSONAL'`).get()).toEqual({ n: 0 });

    const wet = await reclassifyMemories({ db, project: PROJECT, execute: true });
    expect(wet.updated).toBe(1);
    const rows = db.prepare('SELECT title, sensitivity_level FROM memories ORDER BY id').all();
    expect(rows).toEqual([
      { title: FAMILY_TITLE, sensitivity_level: 'PERSONAL' },
      { title: 'Deploy note', sensitivity_level: 'PUBLIC' },
      { title: 'Redacted', sensitivity_level: 'CONFIDENTIAL' },
      { title: 'Odd', sensitivity_level: 'SECRET' },
      { title: 'Other project', sensitivity_level: 'PUBLIC' },
    ]);
    db.close();
  });

  // #722 review R1: Unicode upper-casing turned `ınternal` into INTERNAL, so
  // the backfill rewrote an unknown (isolated) label as a known, shared one.
  it.each(NON_ASCII_LABELS)('leaves a %s row untouched and still isolated', async (label) => {
    const db = seed();
    db.prepare(`UPDATE memories SET sensitivity_level = ? WHERE title = 'Surprise family trip' AND project = ?`).run(label, PROJECT);
    const dry = await reclassifyMemories({ db, project: PROJECT });
    expect(dry.skippedUnknown).toBe(1);
    expect(dry.changes).toEqual([]);
    const wet = await reclassifyMemories({ db, project: PROJECT, execute: true });
    expect(wet.updated).toBe(0);
    const stored = (db.prepare(`SELECT sensitivity_level s FROM memories WHERE title = ? AND project = ?`).get(FAMILY_TITLE, PROJECT) as { s: string }).s;
    expect(stored).toBe(label);
    expect(isIsolatedSensitivity(stored)).toBe(true);
    db.close();
  });

  // #722 review R2: the plan is read and classified first, then written. A
  // writer that changes the row in between must win. The injected classifier
  // is the interleaving point — it runs after the plan's read and before the
  // write — and makes the change through a second connection to the same file.
  describe('--execute never overwrites a row that changed since the plan (#722 R2)', () => {
    function fileDb(): { path: string; db: Database.Database } {
      const dir = mkdtempSync(join(tmpdir(), 'sc-722-r2-'));
      tmpDirs.push(dir);
      const path = join(dir, 'memories.db');
      const db = new Database(path);
      db.exec(SCHEMA);
      const ins = db.prepare(
        `INSERT INTO memories (uuid, type, category, title, content, project, salience, sensitivity_level)
         VALUES (lower(hex(randomblob(16))), 'long_term', 'context', ?, ?, ?, 0.9, 'PUBLIC')`,
      );
      ins.run('Raced', FAMILY_CONTENT, PROJECT);
      ins.run('Bystander', 'My kids birthday trip', PROJECT);
      return { path, db };
    }

    const races: Array<[string, string, (other: Database.Database, id: number) => void, Record<string, unknown> | undefined]> = [
      ['relabelled CONFIDENTIAL', 'stronger label survives',
        (o, id) => { o.prepare(`UPDATE memories SET sensitivity_level = 'CONFIDENTIAL' WHERE id = ?`).run(id); },
        { sensitivity_level: 'CONFIDENTIAL', project: PROJECT }],
      ['relabelled RESTRICTED', 'stronger label survives',
        (o, id) => { o.prepare(`UPDATE memories SET sensitivity_level = 'RESTRICTED' WHERE id = ?`).run(id); },
        { sensitivity_level: 'RESTRICTED', project: PROJECT }],
      ['moved to another project', 'row outside the selection is untouched',
        (o, id) => { o.prepare(`UPDATE memories SET project = 'elsewhere' WHERE id = ?`).run(id); },
        { sensitivity_level: 'PUBLIC', project: 'elsewhere' }],
      ['content rewritten', 'the classification no longer applies',
        (o, id) => { o.prepare(`UPDATE memories SET content = 'Deploys go out on Tuesdays.' WHERE id = ?`).run(id); },
        { sensitivity_level: 'PUBLIC', project: PROJECT }],
      ['deleted', 'nothing is resurrected',
        (o, id) => { o.prepare('DELETE FROM memories WHERE id = ?').run(id); },
        undefined],
    ];

    it.each(races)('row %s between plan and write: skipped as stale (%s)', async (_name, _why, race, expected) => {
      const { path, db } = fileDb();
      const other = new Database(path);
      const racedId = (db.prepare(`SELECT id FROM memories WHERE title = 'Raced'`).get() as { id: number }).id;
      const classify = (content: string, title: string) => {
        if (title === 'Raced') race(other, racedId);
        return classifySensitivity(content, title);
      };
      const r = await reclassifyMemories({ db, project: PROJECT, execute: true, classify });
      other.close();
      expect(r.changes.map((c) => c.id)).toContain(racedId);
      expect(r.updated).toBe(1);           // the bystander
      expect(r.stale).toBe(1);
      expect(r.staleIds).toEqual([racedId]);
      const after = db.prepare('SELECT sensitivity_level, project FROM memories WHERE id = ?').get(racedId);
      expect(after).toEqual(expected);
      expect(db.prepare(`SELECT sensitivity_level s FROM memories WHERE title = 'Bystander'`).get()).toEqual({ s: 'PERSONAL' });
      db.close();
    });

    it('an unchanged plan applies with no stale rows', async () => {
      const { db } = fileDb();
      const r = await reclassifyMemories({ db, project: PROJECT, execute: true });
      expect([r.updated, r.stale, r.staleIds]).toEqual([2, 0, []]);
      db.close();
    });
  });

  it('skips labels outside the ladder', async () => {
    const db = seed();
    db.prepare(`UPDATE memories SET sensitivity_level = 'TOP-SECRET' WHERE title = 'Deploy note'`).run();
    const r = await reclassifyMemories({ db, project: PROJECT });
    expect(r.skippedUnknown).toBe(1);
    db.close();
  });
});

// ── End to end: the real hook ─────────────────────────────────────────────

function makeHome(): { home: string; dbPath: string } {
  const home = mkdtempSync(join(tmpdir(), 'sc-718-'));
  tmpDirs.push(home);
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ proactiveRecall: true, captureEvents: false }));
  const dbPath = join(home, '.shieldcortex', 'memories.db');
  const db = new Database(dbPath);
  db.exec(SCHEMA);
  const ins = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project, salience, trust_score, sensitivity_level, status)
     VALUES (lower(hex(randomblob(16))), 'long_term', ?, ?, ?, ?, 1.0, 1.0, ?, 'active')`,
  );
  // The private memory, labelled as the classifier now labels it.
  ins.run('context', FAMILY_TITLE, FAMILY_CONTENT, PROJECT, classifySensitivity(FAMILY_CONTENT, FAMILY_TITLE).level);
  ins.run('error', 'Deploy errors digest', 'Deploy errors from the nightly digest job: summarise yesterday failures and the trip plan.', PROJECT, 'PUBLIC');
  // A watchdog-vocabulary memory — the kind the probe used to pull in.
  ins.run('pattern', 'Liveness probe protocol', 'Automated liveness check probe from mc-watchdog confirms the CLI backend is registered; reply single line.', PROJECT, 'PUBLIC');
  db.close();
  return { home, dbPath };
}

function runHook(home: string, prompt: string, envExtra: Record<string, string> = {}): string {
  const env: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home };
  for (const key of Object.keys(env)) {
    if (key.startsWith('SHIELDCORTEX_')) delete env[key];
  }
  Object.assign(env, envExtra);
  try {
    return execFileSync('node', [HOOK], {
      input: JSON.stringify({ prompt, cwd: `/tmp/${PROJECT}`, session_id: null }),
      env: env as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (e) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

function lastLog(home: string): Record<string, any> {
  return JSON.parse(readFileSync(join(home, '.shieldcortex', 'recall-log', '0.json'), 'utf8'));
}

describe('prompt-recall hook lane scoping, end to end (#718)', () => {
  it('watchdog probe: lane automation, injectedCount 0, nothing injected', () => {
    const { home, dbPath } = makeHome();
    const out = runHook(home, WATCHDOG_PROMPT);
    expect(out.trim()).toBe('');
    const log = lastLog(home);
    expect(log.lane).toBe('automation');
    expect(log.laneSignal).toBe('marker:liveness-check');
    expect(log.injectedCount).toBe(0);
    expect(log.candidates).toEqual([]);
    const db = new Database(dbPath, { readonly: true });
    const notes = db.prepare(`SELECT notes FROM hook_invocations WHERE hook_name = 'prompt-recall'`).all();
    db.close();
    expect(notes).toEqual([{ notes: 'gated:lane-automation' }]);
  });

  it('cron lane: the PERSONAL memory is a candidate but is withheld; the PUBLIC error memory is injected', () => {
    const { home } = makeHome();
    const out = runHook(home, CRON_PROMPT);
    const log = lastLog(home);
    expect(log.lane).toBe('cron');
    const personal = log.candidates.find((c: { title: string }) => c.title === FAMILY_TITLE);
    expect(personal).toBeDefined();
    expect(personal.injected).toBe(false);
    expect(personal.dropReason).toBe('lane_policy:sensitivity');
    const context = JSON.parse(out).hookSpecificOutput.additionalContext as string;
    expect(context).toContain('Deploy errors digest');
    expect(context).not.toContain('surprise trip');
  });

  it('owner chat: unaffected — the PERSONAL memory is still recalled', () => {
    const { home } = makeHome();
    const out = runHook(home, 'remind me what we booked for the surprise birthday trip');
    const log = lastLog(home);
    expect(log.lane).toBe('interactive');
    expect(log.laneSignal).toBe('default');
    const personal = log.candidates.find((c: { title: string }) => c.title === FAMILY_TITLE);
    expect(personal.injected).toBe(true);
    expect(JSON.parse(out).hookSpecificOutput.additionalContext).toContain(FAMILY_TITLE);
  });

  // #722 review R4, through the real hook: an unmarked prompt that matches the
  // PERSONAL row, run with an invalid pin, must not recall it; the same prompt
  // with a valid interactive pin, or with no pin, still does.
  const OWNER_PROMPT = 'remind me what we booked for the surprise birthday trip';

  it('invalid pin, no marker: the PERSONAL row is not recalled', () => {
    const { home } = makeHome();
    const out = runHook(home, OWNER_PROMPT, { SHIELDCORTEX_RECALL_LANE: 'nightly' });
    const log = lastLog(home);
    expect(log.lane).toBe('automation');
    expect(log.laneSignal).toBe('env:SHIELDCORTEX_RECALL_LANE:invalid');
    expect(log.injectedCount).toBe(0);
    expect(out).not.toContain(FAMILY_TITLE);
    expect(out).not.toContain('surprise trip');
  });

  it('invalid pin with automation opted in: the non-interactive filter still withholds the PERSONAL row', () => {
    const { home } = makeHome();
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ proactiveRecall: true, captureEvents: false, recallLanes: { automation: { recall: true, categories: null } } }),
    );
    const out = runHook(home, OWNER_PROMPT, { SHIELDCORTEX_RECALL_LANE: 'nightly' });
    const log = lastLog(home);
    const personal = log.candidates.find((c: { title: string }) => c.title === FAMILY_TITLE);
    expect(personal).toBeDefined();
    expect(personal.injected).toBe(false);
    expect(personal.dropReason).toBe('lane_policy:sensitivity');
    expect(out).not.toContain(FAMILY_TITLE);
  });

  it.each([
    ['a valid interactive pin', { SHIELDCORTEX_RECALL_LANE: 'interactive' }, 'env:SHIELDCORTEX_RECALL_LANE'],
    ['no pin', {}, 'default'],
  ])('%s, no marker: the PERSONAL row is still recalled', (_name, env, signal) => {
    const { home } = makeHome();
    const out = runHook(home, OWNER_PROMPT, env as Record<string, string>);
    const log = lastLog(home);
    expect(log.lane).toBe('interactive');
    expect(log.laneSignal).toBe(signal);
    expect(JSON.parse(out).hookSpecificOutput.additionalContext).toContain(FAMILY_TITLE);
  });

  // #722 review R1 through the real hook: a cron turn whose only matching
  // PUBLIC-looking row is labelled `publıc` must withhold it.
  it('cron lane withholds a non-ASCII look-alike PUBLIC label', () => {
    const { home, dbPath } = makeHome();
    const db = new Database(dbPath);
    db.prepare(`UPDATE memories SET sensitivity_level = 'publıc' WHERE title = 'Deploy errors digest'`).run();
    db.close();
    const out = runHook(home, CRON_PROMPT);
    const log = lastLog(home);
    expect(log.lane).toBe('cron');
    const row = log.candidates.find((c: { title: string }) => c.title === 'Deploy errors digest');
    expect(row).toBeDefined();
    expect(row.injected).toBe(false);
    expect(row.dropReason).toBe('lane_policy:sensitivity');
    expect(out).not.toContain('Deploy errors digest');
  });

  it('automation opt-in via config still never receives non-PUBLIC rows', () => {
    const { home } = makeHome();
    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({ proactiveRecall: true, captureEvents: false, recallLanes: { automation: { recall: true, categories: null } } }),
    );
    runHook(home, WATCHDOG_PROMPT);
    const log = lastLog(home);
    expect(log.lane).toBe('automation');
    for (const c of log.candidates as Array<{ title: string; injected: boolean }>) {
      if (c.title === FAMILY_TITLE) expect(c.injected).toBe(false);
    }
    expect(existsSync(join(home, '.shieldcortex', 'recall-log', '0.json'))).toBe(true);
  });
});
