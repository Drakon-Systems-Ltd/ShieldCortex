import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { buildUpdateSummary, renderUpdateSummary, type UpdateSummaryInput } from '../cli/update-summary.js';
import { defaultColorStyle, NO_STYLE } from '../cli/term-ui.js';
import { maybeReviewAllowlistAfterUpdate, reviewScanItems, runAllowlistScan, type ScanItem } from '../cli/allowlist-scan.js';
import { renderEngineFailure } from '../cli/update.js';
import { nativeBindingRemediation } from '../setup/native-binding.js';

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const hostile = `${ESC}[2J${ESC}[31m${ESC}]0;pwned${BEL}\u009b\r\u2028\u202e\u200b\u2066`;
const forbidden = [ESC, BEL, '\u009b', '\r', '\u2028', '\u202e', '\u200b', '\u2066'];

function expectClean(output: string): void {
  for (const character of forbidden) expect(output).not.toContain(character);
}

// The update review sink emits these two fixed style codes around its text.
function withoutReviewStyle(output: string): string {
  return output.replaceAll(`${ESC}[2m`, '').replaceAll(`${ESC}[0m`, '');
}

// Strip only the exact SGR codes the renderer itself emits (defaultColorStyle),
// never a general ANSI strip: that would also erase an injected CSI/OSC and
// make the assertion vacuous. The payload carries a non-SGR CSI (ESC[2J) and an
// OSC, which survive this helper and fail expectClean if they leak.
const RENDERER_SGR = ['1m', '0m', '32m', '33m', '31m', '36m', '2m'].map((c) => `${ESC}[${c}`);
function withoutRendererStyle(output: string): string {
  let out = output;
  for (const code of RENDERER_SGR) out = out.replaceAll(code, '');
  return out;
}

function input(): UpdateSummaryInput {
  return {
    fromVersion: `1${hostile}.0`,
    toVersion: `2${hostile}.0`,
    packageState: 'failed',
    engine: { ok: false, remediation: `cd /tmp/install${hostile} && npm run build-release\nother command` },
    plugin: { status: 'warn', rerun: `openclaw ${hostile} update` },
    skill: { status: 'warn', rerun: `skill ${hostile} update` },
    guardOn: true,
    protection: {
      status: 'warn',
      pluginVersion: `3${hostile}.0`,
      expectedVersion: `4${hostile}.0`,
      nextCommand: `repair ${hostile} plugin`,
    },
  };
}

describe('update summary display sanitising (#779)', () => {
  it('cleans each native remediation line while preserving its intended line breaks', () => {
    const body = renderEngineFailure({
      remediation: nativeBindingRemediation(`/opt/x${hostile}/y`),
      packagedPrebuild: false,
    })?.body;
    expect(body).toHaveLength(3);
    expect(body?.[0]).toContain('/opt/x');
    expect(body?.[0]).toContain('/y/node_modules/better-sqlite3');
    expect(body?.[0]).toContain('npm run build-release');
    for (const line of body ?? []) expectClean(line);
  });

  it('cleans the engine command in row data and every rendered field in both modes and styles', () => {
    const facts = input();
    const summary = buildUpdateSummary(facts);
    expectClean(summary.rows.find((row) => row.label === 'Engine')?.command ?? '');
    summary.title += hostile;
    summary.rows.push({
      label: `Host${hostile}`,
      mark: 'check',
      text: `preview ${hostile}`,
      why: `error ${hostile}`,
      commandLabel: `Fix${hostile}`,
      command: `run ${hostile}`,
      commandNote: `from ${hostile} directory`,
    });

    for (const ascii of [false, true]) {
      const plain = renderUpdateSummary(summary, facts, { ascii, style: NO_STYLE }).join('\n');
      expectClean(plain);
      expect(plain).toContain('npm run build-release');
      const style = defaultColorStyle();
      const coloured = renderUpdateSummary(summary, facts, { ascii, style }).join('\n');
      expect(coloured).toContain(style.red);
      let withoutRendererStyle = coloured;
      for (const code of Object.values(style)) withoutRendererStyle = withoutRendererStyle.replaceAll(code, '');
      expectClean(withoutRendererStyle);
    }
  });

  it('cleans plugin versions used to build a row', () => {
    const facts = input();
    facts.packageState = 'updated';
    facts.engine = { ok: true };
    facts.plugin = { status: 'ok' };
    facts.protection.status = 'warn';
    facts.protection.versionOk = false;
    const summary = buildUpdateSummary(facts);
    const row = summary.rows.find((candidate) => candidate.label === 'OpenClaw');
    expect(row?.text).toContain('is behind ShieldCortex');
    expectClean(row?.text ?? '');
    expectClean(renderUpdateSummary(summary, facts, { style: NO_STYLE }).join('\n'));
  });
});

describe('allowlist scan display sanitising (#779)', () => {
  it('cleans an unknown option token before reporting it', async () => {
    const errors: string[] = [];
    expect(await runAllowlistScan([`--bad${hostile}option`], {
      error: (message) => errors.push(message),
    })).toBe(1);
    expect(errors.join('\n')).toContain('--bad');
    expect(errors.join('\n')).toContain('option');
    expectClean(errors.join('\n'));
  });

  it('cleans incomplete cron source paths in scan and verbose update diagnostics', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-779-source-'));
    try {
      const cron = join(dir, `jobs${hostile}.json`);
      writeFileSync(cron, '{invalid');
      const errors: string[] = [];
      const logs: string[] = [];
      const deps = {
        home: dir,
        env: {},
        hermesCronPath: cron,
        interactive: false,
        readEntries: () => [],
        log: (message: string) => logs.push(message),
        error: (message: string) => errors.push(message),
      };
      expect(await runAllowlistScan([], deps)).toBe(1);
      expect(errors.join('\n')).toContain('jobs');
      expect(errors.join('\n')).toContain('.json');
      expectClean(errors.join('\n'));

      logs.length = 0;
      await maybeReviewAllowlistAfterUpdate({ ...deps, updateFlow: true, verbose: true });
      const diagnostic = withoutReviewStyle(logs.join('\n'));
      expect(diagnostic).toContain('jobs');
      expect(diagnostic).toContain('.json:invalid_json');
      expectClean(diagnostic);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('cleans both absent OpenClaw cron paths in incomplete-discovery diagnostics', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-779-absent-'));
    try {
      const openclawCronPath = join(dir, `cron${hostile}.json`);
      const openclawDbPath = join(dir, `cron${hostile}.sqlite`);
      const errors: string[] = [];
      const logs: string[] = [];
      const deps = {
        home: dir,
        env: { OPENCLAW_CONFIG_PATH: join(dir, 'openclaw.json') },
        openclawCronPath,
        openclawDbPath,
        interactive: false,
        readEntries: () => [],
        log: (message: string) => logs.push(message),
        error: (message: string) => errors.push(message),
      };
      expect(await runAllowlistScan([], deps)).toBe(1);
      expect(errors.join('\n')).toContain('cron');
      expect(errors.join('\n')).toContain('.sqlite');
      expectClean(errors.join('\n'));

      logs.length = 0;
      await maybeReviewAllowlistAfterUpdate({ ...deps, updateFlow: true, verbose: true });
      const diagnostic = withoutReviewStyle(logs.join('\n'));
      expect(diagnostic).toContain('.sqlite:no readable OpenClaw cron source');
      expectClean(diagnostic);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('cleans a scheduled-script check exception in the default update flow', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-779-skipped-'));
    try {
      const logs: string[] = [];
      await maybeReviewAllowlistAfterUpdate({
        home: dir,
        env: {},
        updateFlow: true,
        verbose: false,
        interactive: false,
        readEntries: () => { throw new Error(`bad${hostile}x`); },
        log: (message) => logs.push(message),
      });
      const output = withoutReviewStyle(logs.join('\n'));
      expect(output).toContain('Scheduled-script check skipped');
      expect(output).toContain('bad');
      expect(output).toContain('x');
      expectClean(output);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('cleans the trusted basename and pin errors at the review sink', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-779-'));
    try {
      const path = join(dir, `script${hostile}.py`);
      writeFileSync(path, 'print(1)\n');
      const item: ScanItem = { path, status: 'new', networkHint: false, sources: ['test'] };
      const logs: string[] = [];
      const errs: string[] = [];
      const deps = {
        interactive: true,
        prompt: async () => 'y',
        log: (message: string) => logs.push(message),
        error: (message: string) => errs.push(message),
        readEntries: () => [],
        writeEntries: (_entries: Array<Record<string, unknown>>) => {},
      };
      await reviewScanItems([item], deps);
      expect(logs.join('\n')).toContain('Trusted');
      expectClean(withoutRendererStyle(logs.join('\n')));

      logs.length = 0;
      await reviewScanItems([item], {
        ...deps,
        writeEntries: () => { throw new Error(`write ${hostile} failed`); },
      });
      expect(errs.join('\n')).toContain('Could not write');
      expectClean(withoutRendererStyle(errs.join('\n')));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('cleans the path and source preview on the [v] view path', async () => {
    const item: ScanItem = {
      path: `/opt/script${hostile}.py`,
      status: 'new',
      networkHint: false,
      sources: [`src${hostile}`],
      preview: `print(1)${hostile}\nprint(2)`,
    };
    const answers = ['v', 'n'];
    const logs: string[] = [];
    await reviewScanItems([item], {
      interactive: true,
      prompt: async () => answers.shift() ?? 'q',
      log: (message: string) => logs.push(message),
      error: () => {},
      readEntries: () => [],
      writeEntries: () => {},
    });
    const output = withoutRendererStyle(logs.join('\n'));
    expect(output).toContain('print(1)');
    expect(output).toContain('print(2)');
    expectClean(output);
  });

  it('cleans a scan failure message from injected discovery', async () => {
    const errs: string[] = [];
    const code = await runAllowlistScan([], {
      home: tmpdir(),
      interactive: false,
      log: () => {},
      error: (message) => errs.push(message),
      readEntries: () => { throw new Error(`path ${hostile}`); },
    });
    expect(code).toBe(1);
    expect(errs.join('\n')).toContain('Scan failed:');
    expectClean(errs.join('\n'));
  });

  it('cleans a batch pin failure message', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-779-batch-'));
    try {
      const path = join(dir, 'batch.py');
      const cron = join(dir, 'jobs.json');
      writeFileSync(path, 'print(1)\n');
      writeFileSync(cron, JSON.stringify({ jobs: [{ script: path }] }));
      const errs: string[] = [];
      const code = await runAllowlistScan(['--yes'], {
        home: dir,
        interactive: true,
        hermesCronPath: cron,
        prompt: async () => 'approve',
        log: () => {},
        error: (message) => errs.push(message),
        readEntries: () => [],
        writeEntries: () => { throw new Error(`write ${hostile} failed`); },
      });
      expect(code).toBe(1);
      expect(errs.join('\n')).toContain('Could not write');
      expectClean(errs.join('\n'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
