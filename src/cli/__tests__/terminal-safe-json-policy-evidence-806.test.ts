/**
 * #806 — `shieldcortex policy-evidence` goes through `stringifyJsonTerminalSafe`.
 *
 * `src/index.ts` prints `runPolicyEvidence(...).output` as is, so the real
 * handler is driven here, on a real self-report fixture. Every string the
 * collector copies out of a self-report is pattern-restricted today (an
 * invalid one is rejected whole), so no on-disk input reaches the output with
 * a class code point. The collector is wrapped here, in this file only, to
 * append one record note carrying them, which proves the emitter itself
 * escapes. Both spacings (`2` by default, `0` with `--compact`) are covered.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { collectPostureRecords as realCollect } from '../../posture/collect.js';
import { LIVE, H, NOW, denial, iso, reportBody, writeReport } from '../../posture/__tests__/self-report-fixture.js';

let extraNote: string | null = null;

jest.unstable_mockModule('../../posture/collect.js', () => ({
  collectPostureRecords: (...a: Parameters<typeof realCollect>) => realCollect(...a)
    .map((r) => (extraNote === null ? r : { ...r, notes: [...r.notes, extraNote] })),
}));

const { runPolicyEvidence } = await import('../policy-evidence.js');
const { stringifyJsonTerminalSafe } = await import('../term-ui.js');

// U+009B (8-bit CSI), U+202E (RLO), U+2028 (LINE SEPARATOR), U+200B (ZWSP).
const CODES = [0x9b, 0x202e, 0x2028, 0x200b];
const UNSAFE = String.fromCharCode(...CODES);
const ESCAPES = CODES.map((c) => `\\u${c.toString(16).padStart(4, '0')}`);

function literalUnsafe(raw: string): string[] {
  return [...raw].filter((ch) => {
    const cp = ch.codePointAt(0)!;
    return (cp >= 0x80 && cp <= 0x9f) || cp === 0x61c || (cp >= 0x200b && cp <= 0x200f)
      || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064)
      || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff;
  }).map((ch) => `U+${ch.codePointAt(0)!.toString(16).padStart(4, '0')}`);
}

const roots: string[] = [];

afterEach(() => {
  extraNote = null;
  for (const r of roots.splice(0)) fs.rmSync(r, { recursive: true, force: true });
});

/** A home whose Claude Code self-report records a blocked action at `testedPath`. */
function evidence(args: string[]): { code: number; output: string } {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-806-evidence-')));
  roots.push(root);
  const home = path.join(root, 'home');
  const configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(path.join(home, '.claude'), { recursive: true });
  writeReport(configDir, reportBody({
    runtime: 'claude_code',
    instance: { key: 'c0123456789abcdef01234567', pid: null, process_start: null, started_at: iso(NOW - 60_000), liveness: 'per-call' },
    plugin: { id: 'shieldcortex-pre-tool-hook', version: '5.2.1', hash: H('e') },
    policy_hash: H('d'),
    heartbeat_at: iso(NOW - 1000),
    denials: {
      blocked_action: denial({ at: iso(NOW - 500), instance: 'c0123456789abcdef01234567', plugin_hash: H('e'), policy_hash: H('d'), tested_path: 'PreToolUse:Bash' }),
      synthetic_probe: null,
      blocked_action_count: 1,
    },
  }));
  return runPolicyEvidence(args, { home, configDir, nowMs: NOW, hostDeps: { openclawBinaryPresent: () => false }, deps: LIVE });
}

function notes(output: string): string[] {
  return (JSON.parse(output) as { records: Array<{ notes: string[] }> }).records.flatMap((r) => r.notes);
}

describe('policy-evidence JSON is terminal-safe (#806)', () => {
  for (const [label, args, indent] of [['default', [], 2], ['--compact', ['--compact'], 0]] as const) {
    it(`${label}: escapes a record note and round-trips it`, () => {
      extraNote = `note${UNSAFE}`;
      const out = evidence([...args]);
      expect(out.code).toBe(0);
      expect(literalUnsafe(out.output)).toEqual([]);
      for (const esc of ESCAPES) expect(out.output).toContain(esc);
      expect(notes(out.output)).toContain(extraNote);
      expect(out.output).toBe(stringifyJsonTerminalSafe(JSON.parse(out.output), indent));
    });

    it(`${label}: clean ASCII evidence is byte-identical to plain JSON.stringify`, () => {
      extraNote = 'note-plain';
      const out = evidence([...args]);
      expect(out.code).toBe(0);
      expect(notes(out.output)).toContain('note-plain');
      expect(out.output).toContain('PreToolUse:Bash');
      expect(literalUnsafe(out.output)).toEqual([]);
      expect(out.output).toBe(JSON.stringify(JSON.parse(out.output), null, indent));
    });
  }
});
