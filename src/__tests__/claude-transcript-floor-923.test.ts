/**
 * #923 round 3, finding 2 — Claude Code's transcripts are on the guard
 * self-protection floor.
 *
 * The owner-present proof (scripts/lib/owner-tty.mjs) reads
 * `<session_id>.jsonl` to prove a call is top-level. A background process
 * that copies each new subagent tool_use into that file as a main-chain
 * record could forge the proof, so a TOOL CALL that writes a transcript is
 * floored: every `*.jsonl` beneath `.claude/projects/` and anything under a
 * `subagents/` directory there. Claude Code's auto-memory
 * (`.claude/projects/<p>/memory/`) is written by agents on purpose and is NOT
 * floored, and reading a transcript is inspection, not a write.
 *
 * Covers the live classifier and the hook's outage fallback (dist missing).
 * Same-uid writes outside the tool surface are out of scope, as for every
 * floor path.
 */
import { describe, expect, it, beforeEach, afterEach } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateToolCall, GUARD_SELF_PROTECTION_SIGNALS, isGuardSelfProtectionVerdict } from '../defence/iron-dome/tool-action-guard.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const cfg = { enabled: true, enforce: true } as any;
const P = '/home/owner/.claude/projects/-home-owner-work';
const T = `${P}/0b7c-session.jsonl`;
const SUB = `${P}/0b7c-session/subagents/agent-a1.jsonl`;
const MEM = `${P}/memory/MEMORY.md`;

/** Tool calls that WRITE a transcript. */
const WRITES: Array<[string, string, Record<string, unknown>]> = [
  ['Write', 'Write a session transcript', { file_path: T, content: '{}\n' }],
  ['Write', 'Write a subagent transcript', { file_path: SUB, content: '{}\n' }],
  ['Write', 'Write a non-jsonl file under subagents/', { file_path: `${P}/0b7c-session/subagents/agent-a1.meta.json`, content: '{}' }],
  ['Edit', 'Edit a transcript', { file_path: T, old_string: '"isSidechain":true', new_string: '"isSidechain":false' }],
  ['MultiEdit', 'MultiEdit a transcript', { file_path: T, edits: [{ old_string: 'a', new_string: 'b' }] }],
  ['NotebookEdit', 'NotebookEdit naming a transcript', { notebook_path: T, new_source: 'x' }],
  ['Bash', 'append redirect', { command: `echo '{}' >> ${T}` }],
  ['Bash', 'redirect via ~', { command: "echo '{}' > ~/.claude/projects/-home-owner-work/0b7c-session.jsonl" }],
  ['Bash', 'the race: tail a subagent transcript into the session transcript', { command: `tail -f ${SUB} >> ${T}` }],
  ['Bash', 'cp over a transcript', { command: `cp /tmp/forged.jsonl ${T}` }],
  ['Bash', 'mv over a transcript', { command: `mv /tmp/forged.jsonl ${T}` }],
  ['Bash', 'tee -a into a transcript', { command: `echo '{}' | tee -a ${T}` }],
  ['Bash', 'ln -sf at a transcript', { command: `ln -sf /tmp/forged ${T}` }],
  ['Bash', 'dd of= a transcript', { command: `dd if=/tmp/forged of=${T}` }],
  ['Bash', 'sed -i a transcript', { command: `sed -i s/true/false/ ${T}` }],
  ['Bash', 'rm a subagents directory', { command: `rm -r ${P}/0b7c-session/subagents` }],
];

/** Tool calls that must NOT reach the floor. */
const NOT_FLOORED: Array<[string, string, Record<string, unknown>]> = [
  ['Read', 'Read a transcript', { file_path: T }],
  ['Read', 'Read a subagent transcript', { file_path: SUB }],
  ['Bash', 'tail a transcript', { command: `tail -n 20 ${T}` }],
  ['Bash', 'grep | jq a transcript', { command: `grep toolu_01 ${T} | jq .isSidechain` }],
  ['Bash', 'cat via ~', { command: 'cat ~/.claude/projects/-home-owner-work/0b7c-session.jsonl' }],
  ['Bash', 'ls the project directory', { command: `ls ${P}/` }],
  ['Write', 'Write auto-memory MEMORY.md', { file_path: MEM, content: '- [note](note.md) — hook\n' }],
  ['Edit', 'Edit auto-memory MEMORY.md', { file_path: MEM, old_string: 'a', new_string: 'b' }],
  ['Write', 'Write an auto-memory note', { file_path: `${P}/memory/feedback-x.md`, content: 'x' }],
  ['Bash', 'append to auto-memory', { command: `echo '- x' >> ${MEM}` }],
  ['Write', 'a file whose CONTENT mentions a transcript path', { file_path: '/tmp/notes.md', content: `see ${T}` }],
];

describe('#923 r3 — Claude Code transcripts are on the self-protection floor (live classifier)', () => {
  it('the floor names the transcript signal', () => {
    expect(GUARD_SELF_PROTECTION_SIGNALS).toContain('touch-claude-transcript');
  });

  it.each(WRITES)('%s: %s is floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals).toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
    expect(v.decision).not.toBe('allow');
  });

  it.each(NOT_FLOORED)('%s: %s is not floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals ?? []).not.toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(false);
  });
});

describe('#923 r3 — the hook outage fallback floors transcript writes too', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-923-floor-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    // Watch-only: the outage path allows everything except the floor.
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: false } }));
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function run(tool: string, input: Record<string, unknown>): string | undefined {
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ session_id: 's', cwd: '/tmp', hook_event_name: 'PreToolUse', permission_mode: 'bypassPermissions', tool_name: tool, tool_input: input }),
      // A dist root with nothing in it: the guard module fails to load.
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(home, 'no-dist') },
      encoding: 'utf8',
      timeout: 30_000,
    });
    const out = (r.stdout ?? '').trim();
    return out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : undefined;
  }

  it.each(WRITES)('%s: %s is denied with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBe('deny');
  });

  it.each(NOT_FLOORED)('%s: %s passes with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBeUndefined();
  });
});

/**
 * #923 r5 — the floor is judged on the file targeted, not on its spelling and
 * not on the first path key alone (r4 Astra B1, Grok blocker, Astra I1).
 */
const ALIAS_DOT = '/home/owner/.claude/./projects/-home-owner-work/0b7c-session.jsonl';
const ALIAS_SLASH = '/home/owner/.claude//projects/-home-owner-work//0b7c-session.jsonl';
const ALIAS_DOTDOT = '/home/owner/.claude/x/../projects/-home-owner-work/0b7c-session.jsonl';
const DECOY = '/tmp/harmless.txt';

const R5_WRITES: Array<[string, string, Record<string, unknown>]> = [
  ...([['/./', ALIAS_DOT], ['//', ALIAS_SLASH], ['..', ALIAS_DOTDOT]] as const).flatMap(([label, a]) => [
    ['Bash', `sudo cp onto a ${label} alias`, { command: `sudo cp /tmp/forged.jsonl ${a}` }],
    ['Bash', `cp onto a ${label} alias`, { command: `cp /tmp/forged.jsonl ${a}` }],
    ['Write', `Write a ${label} alias`, { file_path: a, content: '{}\n' }],
    ['Edit', `Edit a ${label} alias`, { file_path: a, old_string: 'a', new_string: 'b' }],
    ['NotebookEdit', `NotebookEdit a ${label} alias`, { notebook_path: a, new_source: 'x' }],
  ] as Array<[string, string, Record<string, unknown>]>),
  ['Bash', 'redirect onto a ~ /./ alias', { command: "echo '{}' > ~/.claude/./projects/-home-owner-work/0b7c-session.jsonl" }],
  ['NotebookEdit', 'decoy path, then notebook_path', { path: DECOY, notebook_path: T, new_source: 'x' }],
  ['NotebookEdit', 'notebook_path, then decoy path', { notebook_path: T, path: DECOY, new_source: 'x' }],
  ['NotebookEdit', 'decoy file_path beside notebook_path', { file_path: DECOY, notebook_path: T, new_source: 'x' }],
  ['NotebookEdit', 'decoy path beside an aliased notebook_path', { path: DECOY, notebook_path: ALIAS_DOT, new_source: 'x' }],
  ['Write', 'decoy path, then file_path', { path: DECOY, file_path: T, content: '{}\n' }],
  ['Write', 'transcript path, then decoy file_path', { path: T, file_path: DECOY, content: '{}\n' }],
  ['Edit', 'decoy path, then file_path', { path: DECOY, file_path: T, old_string: 'a', new_string: 'b' }],
  ['Edit', 'transcript path, then decoy file_path', { path: T, file_path: DECOY, old_string: 'a', new_string: 'b' }],
];

const R5_NOT_FLOORED: Array<[string, string, Record<string, unknown>]> = [
  ['Write', 'an ordinary write', { file_path: '/home/owner/work/notes.txt', content: 'x' }],
  ['Write', 'an ordinary write through a /./ spelling', { file_path: '/home/owner/./work/notes.txt', content: 'x' }],
  ['Write', 'auto-memory through a /./ alias', { file_path: '/home/owner/.claude/./projects/-home-owner-work/memory/MEMORY.md', content: 'x' }],
  ['NotebookEdit', 'an ordinary notebook beside an ordinary path', { path: DECOY, notebook_path: '/home/owner/work/a.ipynb', new_source: 'x' }],
  ['Read', 'Read a /./ alias', { file_path: ALIAS_DOT }],
  ['Bash', 'cat a /./ alias', { command: `cat ${ALIAS_DOT}` }],
  ['Bash', 'tail a .. alias', { command: `tail -n 5 ${ALIAS_DOTDOT}` }],
];

describe('#923 r5 — alias spellings and every path key reach the floor (live classifier)', () => {
  it.each(R5_WRITES)('%s: %s is floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals).toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
    expect(v.decision).not.toBe('allow');
  });

  it.each(R5_NOT_FLOORED)('%s: %s is not floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals ?? []).not.toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(false);
  });

  it.each([['canonical', T], ['/./ alias', ALIAS_DOT]])(
    'a dangerous Write body into the %s transcript keeps the floor signal (I1)', (_label, target) => {
      const v = evaluateToolCall('Write', { file_path: target, content: '#!/bin/sh\nsudo systemctl stop nginx\n' }, cfg);
      expect(v.signals).toContain('write-content-dangerous');
      expect(v.signals).toContain('touch-claude-transcript');
      expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
    });

  it('a dangerous Write body to an ordinary script carries no transcript signal', () => {
    const v = evaluateToolCall('Write', { file_path: '/home/owner/work/x.sh', content: '#!/bin/sh\nsudo systemctl stop nginx\n' }, cfg);
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).not.toContain('touch-claude-transcript');
  });
});

describe('#923 r5 — the hook outage fallback floors alias and decoy spellings', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-923-r5-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: false } }));
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function run(tool: string, input: Record<string, unknown>): string | undefined {
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ session_id: 's', cwd: '/tmp', hook_event_name: 'PreToolUse', permission_mode: 'bypassPermissions', tool_name: tool, tool_input: input }),
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(home, 'no-dist') },
      encoding: 'utf8',
      timeout: 30_000,
    });
    const out = (r.stdout ?? '').trim();
    return out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : undefined;
  }

  it.each(R5_WRITES)('%s: %s is denied with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBe('deny');
  });

  it.each(R5_NOT_FLOORED)('%s: %s passes with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBeUndefined();
  });
});
