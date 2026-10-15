import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from '@jest/globals';
import { buildUpdateSummary, renderUpdateSummary, type UpdateSummaryInput } from '../cli/update-summary.js';
import { defaultColorStyle, NO_STYLE, stripAnsi } from '../cli/term-ui.js';
import { reviewScanItems, runAllowlistScan, type ScanItem } from '../cli/allowlist-scan.js';

const ESC = String.fromCharCode(27);
const BEL = String.fromCharCode(7);
const hostile = `${ESC}[2J${ESC}]0;pwned${BEL}\u009b\r\u2028\u202e\u200b\u2066`;
const forbidden = [ESC, BEL, '\u009b', '\r', '\u2028', '\u202e', '\u200b', '\u2066'];

function expectClean(output: string): void {
  for (const character of forbidden) expect(output).not.toContain(character);
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
      expectClean(stripAnsi(logs.join('\n')));

      logs.length = 0;
      await reviewScanItems([item], {
        ...deps,
        writeEntries: () => { throw new Error(`write ${hostile} failed`); },
      });
      expect(errs.join('\n')).toContain('Could not write');
      expectClean(stripAnsi(errs.join('\n')));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
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
