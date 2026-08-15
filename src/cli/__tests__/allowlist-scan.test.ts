/**
 * Spec for `shieldcortex allowlist scan` (#309) — batch review flow for the
 * reviewed-script allowlist. The load-bearing properties, in order:
 *
 *   1. Non-interactive runs NEVER write — they list, report, and exit 3 when
 *      human review is needed, so automation can detect the state without
 *      being able to act on it.
 *   2. The interactive review pins through the SAME canonical-path + content-
 *      hash write path as `allowlist add` — one item, one human decision.
 *   3. `--yes` is refused outright without a TTY, and even with one it demands
 *      the typed word "approve", not a keystroke.
 *
 * Discovery reads Hermes/OpenClaw cron files injected via deps/flags — tests
 * never touch a real ~/.hermes or ~/.openclaw.
 */
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  discoverScripts,
  reviewScanItems,
  runAllowlistScan,
  maybeReviewAllowlistAfterUpdate,
  classifyScripts,
} from '../allowlist-scan.js';
import { runAllowlist } from '../allowlist.js';
import { hashScriptSource } from '../../defence/iron-dome/reviewed-scripts.js';

const SOURCE = '#!/usr/bin/env python3\nprint("sentry sweep")\n';

describe('shieldcortex allowlist scan (#309)', () => {
  let dir: string; // stands in for $HOME — real ~/.hermes and ~/.openclaw are never read
  let scriptPath: string;
  let stored: unknown[];
  let logs: string[];
  let errs: string[];

  const writeHermesCron = (doc: unknown): string => {
    const cronDir = join(dir, '.hermes', 'cron');
    mkdirSync(cronDir, { recursive: true });
    const file = join(cronDir, 'jobs.json');
    writeFileSync(file, typeof doc === 'string' ? doc : JSON.stringify(doc));
    return file;
  };

  const writeOpenClawCron = (doc: unknown): string => {
    const cronDir = join(dir, '.openclaw', 'cron');
    mkdirSync(cronDir, { recursive: true });
    const file = join(cronDir, 'jobs.json');
    writeFileSync(file, typeof doc === 'string' ? doc : JSON.stringify(doc));
    return file;
  };

  const deps = (over: Record<string, unknown> = {}) => ({
    home: dir,
    cwd: dir,
    interactive: false,
    log: (m: string) => logs.push(m),
    error: (m: string) => errs.push(m),
    readEntries: () => stored,
    writeEntries: (e: Array<Record<string, unknown>>) => {
      stored = e;
    },
    ...over,
  });

  /** Scripted stdin — each prompt consumes the next answer. */
  const answers = (list: string[]) => {
    const queue = [...list];
    return async () => queue.shift() ?? '';
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-cli-309-'));
    scriptPath = join(dir, 'sentry.py');
    writeFileSync(scriptPath, SOURCE);
    stored = [];
    logs = [];
    errs = [];
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  // ── Discovery ─────────────────────────────────────────────

  test('discovery: absolute .py path inside a Hermes prompt string', () => {
    writeHermesCron({ jobs: [{ prompt: `Every morning run python3 ${scriptPath} and email the result` }] });
    const found = discoverScripts({ home: dir });
    expect(found.map((f) => f.path)).toContain(scriptPath);
  });

  test('discovery: ~/ path in a Hermes prompt expands against the injected home', () => {
    mkdirSync(join(dir, 'jobs'), { recursive: true });
    writeFileSync(join(dir, 'jobs', 'nightly.sh'), '#!/bin/sh\necho hi\n');
    writeHermesCron({ jobs: [{ prompt: 'run bash ~/jobs/nightly.sh please' }] });
    const found = discoverScripts({ home: dir });
    expect(found.map((f) => f.path)).toContain(join(dir, 'jobs', 'nightly.sh'));
  });

  test('discovery: explicit Hermes `script` field', () => {
    writeHermesCron({ jobs: [{ prompt: 'do the thing', script: scriptPath }] });
    const found = discoverScripts({ home: dir });
    expect(found.map((f) => f.path)).toContain(scriptPath);
  });

  test('discovery: OpenClaw payload.message', () => {
    writeOpenClawCron({
      version: 1,
      jobs: [{ payload: { kind: 'agentTurn', message: `node ${join(dir, 'poll.mjs')} --daily` } }],
    });
    writeFileSync(join(dir, 'poll.mjs'), 'console.log(1)\n');
    const found = discoverScripts({ home: dir });
    expect(found.map((f) => f.path)).toContain(join(dir, 'poll.mjs'));
  });

  test('discovery: mislabeled skills-subdir path in prompt text still found', () => {
    const skillScript = join(dir, '.hermes', 'skills', 'sentry', 'runner.py');
    mkdirSync(join(dir, '.hermes', 'skills', 'sentry'), { recursive: true });
    writeFileSync(skillScript, SOURCE);
    writeHermesCron({ jobs: [{ prompt: `use the memory skill: python3 ${skillScript}` }] });
    const found = discoverScripts({ home: dir });
    expect(found.map((f) => f.path)).toContain(skillScript);
  });

  test('discovery: bare-array Hermes shape, malformed JSON and absent files never throw', () => {
    writeHermesCron([{ prompt: `sh ${scriptPath}` }]);
    expect(discoverScripts({ home: dir }).map((f) => f.path)).toContain(scriptPath);
    writeHermesCron('{not json');
    expect(() => discoverScripts({ home: dir })).not.toThrow();
    rmSync(join(dir, '.hermes'), { recursive: true, force: true });
    expect(discoverScripts({ home: dir })).toEqual([]);
  });

  // ── Classification ────────────────────────────────────────

  test('classify: current / changed / new / missing / too_large', () => {
    const changed = join(dir, 'changed.sh');
    writeFileSync(changed, 'echo v2\n');
    const big = join(dir, 'big.sh');
    writeFileSync(big, 'x'.repeat(262_145));
    const entries = [
      { path: realpathSync(scriptPath), sha256: hashScriptSource(SOURCE) },
      { path: realpathSync(changed), sha256: hashScriptSource('echo v1\n') },
    ];
    const items = classifyScripts(
      [
        { path: scriptPath, sources: ['hermes-cron'] },
        { path: changed, sources: ['hermes-cron'] },
        { path: join(dir, 'fresh.py'), sources: ['openclaw-cron'] },
        { path: big, sources: ['glob'] },
      ],
      entries,
    );
    writeFileSync(join(dir, 'fresh.py'), 'print(1)\n'); // written after classify — stays missing
    const byPath = new Map(items.map((i) => [i.path, i.status]));
    expect(byPath.get(realpathSync(scriptPath))).toBe('current');
    expect(byPath.get(realpathSync(changed))).toBe('changed');
    expect(byPath.get(join(dir, 'fresh.py'))).toBe('missing');
    expect(byPath.get(realpathSync(big))).toBe('too_large');
  });

  test('classify: network sniff is advisory metadata, never a gate', () => {
    const net = join(dir, 'net.py');
    writeFileSync(net, 'import requests\nrequests.get("https://x")\n');
    const items = classifyScripts([{ path: net, sources: ['glob'] }], []);
    expect(items[0].status).toBe('new');
    expect(items[0].networkHint).toBe(true);
    const quiet = classifyScripts([{ path: scriptPath, sources: ['glob'] }], []);
    expect(quiet[0].networkHint).toBe(false);
  });

  // ── Non-interactive: report only, exit codes for automation ──

  test('non-interactive scan reports new scripts but NEVER writes (exit 3)', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    const code = await runAllowlistScan([], deps({ prompt: answers(['y', '']) }));
    expect(code).toBe(3);
    expect(stored).toEqual([]);
    expect(logs.join('\n')).toContain(realpathSync(scriptPath));
    expect(logs.join('\n')).toContain('shieldcortex allowlist scan');
  });

  test('non-interactive scan with nothing new/changed exits 0', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    stored = [{ path: realpathSync(scriptPath), sha256: hashScriptSource(SOURCE) }];
    expect(await runAllowlistScan([], deps())).toBe(0);
    expect(stored).toHaveLength(1);
  });

  test('missing file referenced in cron: reported, never pinned, not review-worthy', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${join(dir, 'gone.py')}` }] });
    const code = await runAllowlistScan([], deps({ interactive: true, prompt: answers(['y', '']) }));
    expect(code).toBe(0); // nothing pinnable → nothing needing review
    expect(stored).toEqual([]);
    expect(logs.join('\n')).toContain('missing');
  });

  test('--json emits a machine-readable, non-mutating report', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    const code = await runAllowlistScan(['--json'], deps({ interactive: true, prompt: answers(['y', '']) }));
    expect(code).toBe(3);
    expect(stored).toEqual([]);
    const report = JSON.parse(logs.join('\n')) as {
      counts: Record<string, number>;
      items: Array<{ path: string; status: string; sources: string[] }>;
    };
    expect(report.counts.new).toBe(1);
    expect(report.items[0].path).toBe(realpathSync(scriptPath));
    expect(report.items[0].status).toBe('new');
  });

  test('--glob discovers script files under an explicit pattern', async () => {
    mkdirSync(join(dir, 'scripts'), { recursive: true });
    const globbed = join(dir, 'scripts', 'task.sh');
    writeFileSync(globbed, 'echo run\n');
    writeFileSync(join(dir, 'scripts', 'notes.txt'), 'not a script\n');
    const code = await runAllowlistScan(['--glob', join(dir, 'scripts', '*.sh')], deps());
    expect(code).toBe(3);
    expect(logs.join('\n')).toContain(realpathSync(globbed));
    expect(logs.join('\n')).not.toContain('notes.txt');
  });

  test('cron path flags override the defaults', async () => {
    const elsewhere = join(dir, 'elsewhere');
    mkdirSync(elsewhere, { recursive: true });
    const hermes = join(elsewhere, 'h.json');
    writeFileSync(hermes, JSON.stringify({ jobs: [{ prompt: `sh ${scriptPath}` }] }));
    const code = await runAllowlistScan(['--hermes-cron', hermes], deps());
    expect(code).toBe(3);
    expect(logs.join('\n')).toContain(realpathSync(scriptPath));
  });

  // ── Interactive review: the only path that writes ─────────

  test('interactive review pins a new script with canonical path + hash', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    const code = await runAllowlistScan([], deps({ interactive: true, now: 4321, prompt: answers(['y', 'nightly sentry']) }));
    expect(code).toBe(0);
    expect(stored).toEqual([
      {
        path: realpathSync(scriptPath),
        sha256: hashScriptSource(SOURCE),
        note: 'nightly sentry',
        addedAt: 4321,
      },
    ]);
  });

  test('changed script is offered as changed; re-pin updates the hash', async () => {
    stored = [{ path: realpathSync(scriptPath), sha256: hashScriptSource('# old\n') }];
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    const code = await runAllowlistScan([], deps({ interactive: true, prompt: answers(['y', '']) }));
    expect(code).toBe(0);
    expect(logs.join('\n')).toContain('changed');
    expect(stored).toHaveLength(1);
    expect((stored[0] as Record<string, unknown>).sha256).toBe(hashScriptSource(SOURCE));
  });

  test('n skips, q stops the rest but keeps what was already pinned', async () => {
    const second = join(dir, 'zz-second.py');
    writeFileSync(second, 'print(2)\n');
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath} && python3 ${second}` }] });
    const code = await runAllowlistScan([], deps({ interactive: true, prompt: answers(['y', '', 'q']) }));
    expect(code).toBe(0);
    expect(stored).toHaveLength(1);
    expect((stored[0] as Record<string, unknown>).path).toBe(realpathSync(scriptPath));
  });

  // ── TTY gate ──────────────────────────────────────────────

  test('TTY gate: review helper with interactive=false never writes', async () => {
    const items = classifyScripts([{ path: scriptPath, sources: ['hermes-cron'] }], []);
    const result = await reviewScanItems(items, deps({ interactive: false, prompt: answers(['y', '']) }));
    expect(result.pinned).toBe(0);
    expect(stored).toEqual([]);
    expect(errs.join('\n')).toContain('interactive terminal');
  });

  test('--yes without a TTY is refused with exit 1 and no writes', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    const code = await runAllowlistScan(['--yes'], deps({ interactive: false, prompt: answers(['approve']) }));
    expect(code).toBe(1);
    expect(stored).toEqual([]);
    expect(errs.join('\n')).toContain('interactive terminal');
  });

  test('--yes on a TTY demands the typed word "approve"', async () => {
    const second = join(dir, 'zz-second.py');
    writeFileSync(second, 'print(2)\n');
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath} && python3 ${second}` }] });

    let code = await runAllowlistScan(['--yes'], deps({ interactive: true, prompt: answers(['y']) }));
    expect(code).toBe(0);
    expect(stored).toEqual([]); // "y" is not "approve" — nothing pinned

    code = await runAllowlistScan(['--yes'], deps({ interactive: true, prompt: answers(['approve']) }));
    expect(code).toBe(0);
    expect(stored).toHaveLength(2);
  });

  // ── Dispatch through `shieldcortex allowlist scan` ────────

  test('runAllowlist dispatches the scan subcommand', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    const code = await runAllowlist(['scan'], deps());
    expect(code).toBe(3);
    expect(stored).toEqual([]);
  });

  // ── `shieldcortex update` hook ────────────────────────────

  test('update hook: non-interactive prints one pointer line, never writes', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    await maybeReviewAllowlistAfterUpdate(deps());
    expect(stored).toEqual([]);
    const out = logs.join('\n');
    expect(out).toContain('1 new/changed');
    expect(out).toContain('shieldcortex allowlist scan');
  });

  test('update hook: silent when there is nothing new or changed', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    stored = [{ path: realpathSync(scriptPath), sha256: hashScriptSource(SOURCE) }];
    await maybeReviewAllowlistAfterUpdate(deps());
    expect(logs).toEqual([]);
  });

  test('update hook: scan errors are swallowed, never fail the update', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    await expect(
      maybeReviewAllowlistAfterUpdate(
        deps({
          readEntries: () => {
            throw new Error('config exploded');
          },
        }),
      ),
    ).resolves.toBeUndefined();
    expect(logs.join('\n')).toContain('skipped');
  });

  test('update hook: interactive runs the same per-item review', async () => {
    writeHermesCron({ jobs: [{ prompt: `python3 ${scriptPath}` }] });
    await maybeReviewAllowlistAfterUpdate(deps({ interactive: true, prompt: answers(['y', '']) }));
    expect(stored).toHaveLength(1);
    expect((stored[0] as Record<string, unknown>).path).toBe(realpathSync(scriptPath));
  });
});
