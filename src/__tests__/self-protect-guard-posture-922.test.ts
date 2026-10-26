/**
 * #922 PR-B — `shieldcortex guard posture off|advisory` is a loosening
 * invocation. It lands on the self-protection floor (`disable-action-guard`)
 * on every surface BEFORE any writer exists: the core argv walk, the Claude
 * Code hook's outage table, the OpenClaw interceptor's outage table and both
 * Hermes outage lists. `guard posture enforce` (a tightening) and the bare
 * read-only form stay off it.
 *
 * Literals are assembled at runtime (#444 convention) so the live guard
 * scanning this file's own write does not gate it.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'node:child_process';
import { evaluateToolCall, GUARD_SELF_PROTECTION_SIGNALS } from '../defence/iron-dome/tool-action-guard.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const hookSrc = fs.readFileSync(path.join(repoRoot, 'scripts', 'pre-tool-hook.mjs'), 'utf-8');

const SC = 'shield' + 'cortex';
const GP = 'guard ' + 'posture';

const POSITIVES = [
  `${SC} ${GP} off`,
  `${SC} ${GP} advisory`,
  `npx ${SC} ${GP} advisory`,
  `npx -y ${SC} ${GP} off`,
  `${SC} ${GP} --dry-run off`,
  `${SC} ${GP} "off"`,
  `${SC} ${GP} OFF --json`,
  `bash -c '${SC} ${GP} off'`,
  `sh -c "${SC} ${GP} advisory"`,
  `$X ${GP} off`,
  `${SC} ${GP} $TARGET`,
  `${SC} ${GP} "$(echo off)"`,
  `echo hi && ${SC} ${GP} off`,
  `cat /etc/${SC}/policy.json; ${SC} ${GP} off`,
];
const NEGATIVES = [
  `${SC} ${GP}`,
  `${SC} ${GP} --json`,
  `${SC} ${GP} enforce`,
  `${SC} ${GP} enforce --dry-run`,
  `${SC} guard readiness`,
  'ls -la',
];

const onFloor = (signals: readonly string[] | undefined) =>
  (signals ?? []).some((s) => GUARD_SELF_PROTECTION_SIGNALS.includes(s));

type Match = (args: Record<string, unknown>, toolName?: string) => string | null;

/** The hook is a script: evaluate the SHIPPED text of its pure outage section
 *  (same technique as outage-fallback-regex-bounds-509). */
function hookMatch(): Match {
  const start = hookSrc.indexOf('const FALLBACK_DANGEROUS_PATTERNS');
  const end = hookSrc.indexOf('// ==================== AUDIT (local JSONL)');
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  return new Function(`${hookSrc.slice(start, end)}\nreturn fallbackSelfProtectionMatch;`)() as Match;
}

describe('#922 — guard posture loosening is on the self-protection floor (core argv walk)', () => {
  for (const cfg of [{ enabled: true, enforce: true }, { enabled: true, enforce: false }]) {
    it.each(POSITIVES)(`enforce=${cfg.enforce}: %s carries disable-action-guard`, (command) => {
      const v = evaluateToolCall('Bash', { command }, cfg as never);
      expect({ command, signals: v.signals ?? [] }).toEqual({ command, signals: expect.arrayContaining(['disable-action-guard']) });
      expect(v.decision).not.toBe('allow');
    });
  }

  it.each(NEGATIVES)('%s is not on the floor', (command) => {
    const v = evaluateToolCall('Bash', { command }, { enabled: true, enforce: true } as never);
    expect({ command, floor: onFloor(v.signals) }).toEqual({ command, floor: false });
  });

  it('`guard posture offline` (not a posture word) is not read as `off`', () => {
    const v = evaluateToolCall('Bash', { command: `${SC} ${GP} offline` }, { enabled: true, enforce: true } as never);
    expect(v.signals ?? []).not.toContain('disable-action-guard');
  });
});

describe('#922 — every outage fallback agrees with the core on the same table', () => {
  const table = [...POSITIVES, ...NEGATIVES];
  const core = table.map((command) => ({
    command,
    floor: onFloor(evaluateToolCall('Bash', { command }, { enabled: true, enforce: true } as never).signals),
  }));

  it('core decides the table as written (positives on, negatives off)', () => {
    expect(core.map((r) => r.floor)).toEqual(table.map((c) => POSITIVES.includes(c)));
  });

  it('Claude Code hook outage table', () => {
    const match = hookMatch();
    expect(table.map((command) => ({ command, floor: match({ command }, 'Bash') !== null }))).toEqual(core);
  });

  it('OpenClaw interceptor outage table', async () => {
    const { fallbackSelfProtectionMatch } = await import('../../plugins/openclaw/interceptor.js');
    const match = fallbackSelfProtectionMatch as Match;
    expect(table.map((command) => ({ command, floor: match({ command }, 'Bash') !== null }))).toEqual(core);
  });

  it('Hermes outage lists (_FALLBACK_SELF_PROTECTION and _FALLBACK_DANGEROUS)', () => {
    const script = [
      'import json, sys',
      `sys.path.insert(0, ${JSON.stringify(path.join(repoRoot, 'plugins', 'hermes', 'shieldcortex'))})`,
      'import sc_client as c',
      'table = json.loads(sys.stdin.read())',
      'print(json.dumps([{"command": t, "floor": bool(c.fallback_self_protection_match(t)),',
      '  "dangerous": any(p.search(t) for p in c._FALLBACK_DANGEROUS)} for t in table]))',
    ].join('\n');
    const run = spawnSync('python3', ['-W', 'error', '-c', script], { input: JSON.stringify(table), encoding: 'utf8', timeout: 60_000 });
    expect({ status: run.status, stderr: run.status === 0 ? '' : run.stderr }).toEqual({ status: 0, stderr: '' });
    const rows = JSON.parse(run.stdout.trim().split('\n').pop() as string) as Array<{ command: string; floor: boolean; dangerous: boolean }>;
    expect(rows.map(({ command, floor }) => ({ command, floor }))).toEqual(core);
    // Every floor hit is also on the dangerous list, so the outage scan sees it.
    for (const r of rows) if (r.floor) expect({ command: r.command, dangerous: r.dangerous }).toEqual({ command: r.command, dangerous: true });
  });
});
