/**
 * #922 PR-B — `shieldcortex guard posture off|advisory` is a loosening
 * invocation. It lands on the self-protection floor (`disable-action-guard`)
 * on every surface BEFORE any writer exists: the core argv walk, the Claude
 * Code hook's outage table, the OpenClaw interceptor's outage table and both
 * Hermes outage lists. `guard posture enforce` (a tightening) and the bare
 * read-only form stay off it, and so does a data-only mention of the phrase
 * (echo / grep / cat / gh --body): the outage rows need an invocation-position
 * invoker before it, as the core walk does.
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
const G = 'gu' + 'ard';
const P = 'pos' + 'ture';
const GP = `${G} ${P}`;

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
  // #922 r1: shell spellings whose argv is still the loosening.
  `$X "${G}" "${P}" off`,
  `$X ${G} "${P}" off`,
  `"$X" '${G}' '${P}' advisory`,
  `\${X} ${GP} off`,
  `$(which ${SC}) ${GP} off`,
  `${SC} "${G}" "${P}" off`,
  `${SC} ${G} "${P}" advisory`,
  `${SC} g\\uard ${P} off`,
  `${SC} ${GP} o"ff"`,
  `${SC} ${GP} o\\ff`,
  `${SC} ${GP} adv'isory'`,
  `${SC} ${GP} o*`,
  `${SC} ${GP} o\${T}`,
  `${SC} ${GP} off*`,
  `${SC} ${GP} of[f]`,
  `${SC} ${GP} \`echo off\``,
  `${SC} ${GP} "--dry-run" off`,
  `${SC} ${GP} '--dry-run' advisory`,
  `bash -lc '${SC} ${GP} off'`,
  `eval '${SC} ${GP} off'`,
  `sudo ${SC} ${GP} off`,
  `env A=1 ${SC} ${GP} off`,
  `node ./${SC}.js ${GP} off`,
  `{ ${SC} ${GP} off; }`,
  `if ${SC} ${GP} off; then :; fi`,
  `${SC}\t${G}\t${P}\toff`,
  // #922 r2: wrapper option values, path-qualified/quoted wrappers, a
  // quote-fragmented invoker and bash value options, as the core reads them.
  `env -u FOO ${SC} ${GP} off`,
  `/usr/bin/env ${SC} ${GP} advisory`,
  `"env" ${SC} ${GP} off`,
  `shield"cortex" ${GP} off`,
  `sudo -u nobody ${SC} ${GP} off`,
  `bash -O extglob -c '${SC} ${GP} off'`,
  `bash --rcfile /tmp/x -c '${SC} ${GP} off'`,
  `env -i echo ${SC} ${GP} off`,
  // The executable counterpart of the quoted filename below: the `;` is real.
  `cat notes; ${SC} "${G}" "${P}" off`,
  // #922 r3 (R3-B1): the unquoted counterparts of the composed quoted-filename
  // rows below — a real `;` before the wrapper is a real invocation.
  `cat x; env -u FOO ${SC} ${GP} off`,
  `cat 'a'; ${SC} ${GP} off`,
  `cat notes; env -u FOO ${SC} ${GP} off; touch output`,
  `cat notes# ; /usr/bin/env ${SC} ${GP} off`,
  `cat 'notes#'; shield"cortex" ${GP} off`,
  `cat "$(${SC} ${GP} off)"`,
  `cat \`${SC} ${GP} off\``,
  // #943 review B2: a redirection ends the word it is glued to, and Bash
  // deletes a backslash-newline, so the argv is still the loosening.
  `${SC} ${GP} off>/dev/null`,
  `${SC} ${GP} advisory>/dev/null`,
  `${SC} ${GP} off</dev/null`,
  `${SC} ${GP} off>>log`,
  `${SC} ${GP} off 2>/dev/null`,
  `${SC} ${GP} 2>/dev/null off`,
  `${SC} ${GP} >/dev/null advisory`,
  `${SC} ${GP} >"a b" off`,
  `${SC} ${G} \\\n${P} off`,
  `${SC} ${GP} \\\noff`,
  `${SC} ${GP} \\\nadvisory>/dev/null`,
  `${SC} \\\n${GP} off`,
  `bash -c '${SC} ${GP} off>/dev/null'`,
  `npx ${SC} ${GP} advisory>/dev/null`,
];
const NEGATIVES = [
  `${SC} ${GP}`,
  `${SC} ${GP} --json`,
  `${SC} ${GP} enforce`,
  `${SC} ${GP} enforce --dry-run`,
  `${SC} guard readiness`,
  'ls -la',
  `${SC} "${G}" "${P}" enforce`,
  `$X ${GP} enforce`,
  `${SC} ${GP} offline`,
  // #922 r1: data-only mentions of the phrase stay off the floor everywhere.
  `echo "${SC} ${GP} off"`,
  `echo ${SC} ${GP} off`,
  `echo ${GP} off`,
  `grep -F "${SC} ${GP} off" README.md`,
  `grep -c '${SC} ${GP} off' CHANGELOG.md`,
  `cat file | grep '${GP} off'`,
  `cat "${SC} ${GP} off"`,
  `gh issue create --body "${SC} ${GP} off"`,
  `gh pr comment 1 --body 'run: ${SC} ${GP} advisory'`,
  `echo "x; ${SC} ${GP} off"`,
  `git commit -m "docs: ${SC} ${GP} off"`,
  `grep -F '${GP} off' /etc/${SC}/policy.json`,
  `grep -F '${SC} ${GP} off' /etc/${SC}/policy.json`,
  `cat /etc/${SC}/policy.json`,
  // #922 r2: one single-quoted filename — its `;` and inner quotes are data.
  `cat 'notes; ${SC} "${G}" "${P}" off'`,
  `echo -u FOO ${SC} ${GP} off`,
  `sudo -u nobody echo ${SC} ${GP} off`,
  `echo bash -c '${SC} ${GP} off'`,
  // #922 r3 (R3-B1): a quoted cat filename stays data when a write sibling, a
  // redirect or a `#` (the plain split) defeats the whole-surface read exemption.
  `cat 'notes; env -u FOO ${SC} ${GP} off'; touch output`,
  `cat 'notes; env -u FOO ${SC} ${GP} off' > output`,
  `cat 'notes#; env -u FOO ${SC} ${GP} off'`,
  `cat 'notes#; /usr/bin/env ${SC} ${GP} off'`,
  `cat 'notes#; shield"cortex" ${GP} off'`,
  // #943 review B2: the same shell spellings around a tightening, the read,
  // a redirect whose TARGET is the word, and a mention stay off the floor.
  `${SC} ${GP} enforce>/dev/null`,
  `${SC} ${GP}>/dev/null`,
  `${SC} ${GP} --json>/dev/null`,
  `${SC} ${GP} \\\nenforce`,
  `${SC} ${GP} \\\n--json`,
  `${SC} ${GP} >off`,
  `${SC} ${GP} off2>/dev/null`,
  `${SC} ${GP} offline>/dev/null`,
  `echo "${SC} ${GP} off>/dev/null"`,
  `echo ${SC} ${G} \\\n${P} off`,
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

  it('a wrapper-dense command costs the same with or without the posture words (no walk cliff)', () => {
    // Differential, not a tuned absolute cap: the same `nice env nohup` corpus
    // (#500's ReDoS shape) with the trigger words and with a same-length decoy.
    // Before r1 the trigger admitted an O(tokens²) walk: ~6 s against ~10 ms.
    const pad = 'nice env nohup '.repeat(2200);
    const hot = `${pad}${GP} off`;
    const cold = `${pad}${'gu' + 'arx'} ${'pos' + 'turx'} off`;
    const cfg = { enabled: true, enforce: true } as never;
    const median = (command: string): number => {
      evaluateToolCall('Bash', { command }, cfg);   // warm up
      const runs: number[] = [];
      for (let k = 0; k < 5; k++) {
        const t0 = performance.now();
        evaluateToolCall('Bash', { command }, cfg);
        runs.push(performance.now() - t0);
      }
      return runs.sort((a, b) => a - b)[2];
    };
    const tCold = median(cold);
    const tHot = median(hot);
    expect({ hot: tHot, bounded: tHot <= tCold * 10 + 25 }).toEqual({ hot: tHot, bounded: true });
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
      '  "dangerous": bool(c.fallback_dangerous_match(t))} for t in table]))',
    ].join('\n');
    const run = spawnSync('python3', ['-W', 'error', '-c', script], { input: JSON.stringify(table), encoding: 'utf8', timeout: 60_000 });
    expect({ status: run.status, stderr: run.status === 0 ? '' : run.stderr }).toEqual({ status: 0, stderr: '' });
    const rows = JSON.parse(run.stdout.trim().split('\n').pop() as string) as Array<{ command: string; floor: boolean; dangerous: boolean }>;
    expect(rows.map(({ command, floor }) => ({ command, floor }))).toEqual(core);
    // The public dangerous matcher, on both halves of the table: every floor
    // hit is dangerous too, so the outage scan sees it; any other row is
    // dangerous exactly when the core does not allow it (an ordinary sudo row),
    // so a data mention gains no outage block.
    const expected = rows.map(({ command, floor }) => ({
      command,
      dangerous: floor || evaluateToolCall('Bash', { command }, { enabled: true, enforce: true } as never).decision !== 'allow',
    }));
    expect(rows.map(({ command, dangerous }) => ({ command, dangerous }))).toEqual(expected);
  });
});
