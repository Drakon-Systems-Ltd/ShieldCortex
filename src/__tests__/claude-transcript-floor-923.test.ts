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
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateToolCall, GUARD_SELF_PROTECTION_SIGNALS, isGuardSelfProtectionVerdict } from '../defence/iron-dome/tool-action-guard.js';
import { joinedControls, joinedSpellings } from './support/transcript-joins-923.js';

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

/**
 * #923 r6 — a structured path is judged whole, and a command key never reads a
 * write-family target off the floor (r5 Astra B1, Grok blocker). A comma, `=`,
 * space or paren in a directory component is part of the path; splitting
 * there before normalising lost the transcript. And `command: 'ls'` beside a
 * Write's transcript `file_path` made the joined surface parse as a read.
 */
const DELIMITED: Array<[string, string]> = [
  ['x,y/..', '/home/owner/.claude/x,y/../projects/-home-owner-work/0b7c-session.jsonl'],
  ['a=b/..', '/home/owner/.claude/a=b/../projects/-home-owner-work/0b7c-session.jsonl'],
  ['a b/..', '/home/owner/.claude/a b/../projects/-home-owner-work/0b7c-session.jsonl'],
  ['(x)/..', '/home/owner/.claude/(x)/../projects/-home-owner-work/0b7c-session.jsonl'],
];

const R6_WRITES: Array<[string, string, Record<string, unknown>]> = [
  ...DELIMITED.flatMap(([label, a]) => [
    ['Write', `Write a ${label} alias`, { file_path: a, content: '{}\n' }],
    ['Edit', `Edit a ${label} alias`, { file_path: a, old_string: 'a', new_string: 'b' }],
    ['NotebookEdit', `NotebookEdit a ${label} alias`, { notebook_path: a, new_source: 'x' }],
    ['Bash', `sudo cp onto a quoted ${label} alias`, { command: `sudo cp /tmp/forged.jsonl "${a}"` }],
  ] as Array<[string, string, Record<string, unknown>]>),
  ['Bash', 'cp onto an unquoted x,y/.. alias', { command: `cp /tmp/forged.jsonl ${DELIMITED[0][1]}` }],
  ['Bash', 'cp onto an unquoted a=b/.. alias', { command: `cp /tmp/forged.jsonl ${DELIMITED[1][1]}` }],
  ...([['canonical', T], ['/./ alias', ALIAS_DOT], ['x,y/.. alias', DELIMITED[0][1]]] as const).flatMap(([label, a]) => [
    ['Write', `command 'ls' beside a ${label} file_path`, { command: 'ls', file_path: a, content: '{}\n' }],
    ['Write', `command 'cat' beside a ${label} file_path`, { command: 'cat', file_path: a, content: '{}\n' }],
    ['Write', `cmd 'ls' beside a ${label} file_path`, { cmd: 'ls', file_path: a, content: '{}\n' }],
    ['Edit', `command 'ls' beside a ${label} file_path`, { command: 'ls', file_path: a, old_string: 'a', new_string: 'b' }],
    ['Edit', `command 'cat /tmp/x' beside a ${label} file_path`, { command: 'cat /tmp/x', file_path: a, old_string: 'a', new_string: 'b' }],
    ['MultiEdit', `command 'ls' beside a ${label} file_path`, { command: 'ls', file_path: a, edits: [{ old_string: 'a', new_string: 'b' }] }],
    ['NotebookEdit', `command 'ls' beside a ${label} notebook_path`, { command: 'ls', notebook_path: a, new_source: 'x' }],
  ] as Array<[string, string, Record<string, unknown>]>),
];

const R6_NOT_FLOORED: Array<[string, string, Record<string, unknown>]> = [
  // `(x)/..` is left out: a paren anywhere fails the closed-set read bar
  // (nested-exec veto), so that `cat` stays floored — an over-deny, never a bypass.
  ...DELIMITED.slice(0, 3).map(([label, a]) => ['Bash', `cat a quoted ${label} alias`, { command: `cat "${a}"` }] as [string, string, Record<string, unknown>]),
  ['Bash', 'ls the transcript', { command: `ls -l ${T}` }],
  ['Bash', 'ls a /./ alias', { command: `ls ${ALIAS_DOT}` }],
  ['Write', "an ordinary write beside command 'ls'", { command: 'ls', file_path: '/home/owner/work/notes.txt', content: 'x' }],
  ['Write', 'an ordinary write through a comma directory', { file_path: '/home/owner/work/x,y/../notes.txt', content: 'x' }],
  ['Write', 'auto-memory through an x,y/.. alias', { file_path: '/home/owner/.claude/x,y/../projects/-home-owner-work/memory/MEMORY.md', content: 'x' }],
];

describe('#923 r6 — whole-path normalisation and no command-key read carve-out for writes (live classifier)', () => {
  it.each(R6_WRITES)('%s: %s is floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals).toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
    expect(v.decision).not.toBe('allow');
  });

  it.each(R6_NOT_FLOORED)('%s: %s is not floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals ?? []).not.toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(false);
  });

  it('a dangerous Write body into an x,y/.. alias keeps the floor signal', () => {
    const v = evaluateToolCall('Write', { file_path: DELIMITED[0][1], content: '#!/bin/sh\nsudo systemctl stop nginx\n' }, cfg);
    expect(v.signals).toContain('write-content-dangerous');
    expect(v.signals).toContain('touch-claude-transcript');
  });
});

describe('#923 r6 — the hook outage fallback judges paths whole and keeps writes floored', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-923-r6-'));
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

  it.each(R6_WRITES)('%s: %s is denied with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBe('deny');
  });

  it.each(R6_NOT_FLOORED)('%s: %s passes with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBeUndefined();
  });
});

/**
 * #923 r7 — command text is split into the shell's own words before any `..`
 * is collapsed (r6 Astra B1, r6 Grok blocker). One tokenizer
 * (scripts/lib/shell-words.mjs) serves the live guard and the hook's outage
 * path. `x\ y` is ONE directory name, so `.claude/x\ y/../projects/…` is the
 * transcript exactly as `".claude/x y/../projects/…"` is; the r6 splitter cut
 * it at the escaped space and lexicalPathNormalise turned the backslash into a
 * slash. A backslash is no longer a separator anywhere (r6 Astra I1).
 */
const R7_HOME = '/home/owner/.claude';
const R7_LEAF = 'projects/-home-owner-work/0b7c-session.jsonl';
/** [label, escaped spelling, quoted spelling, structured (unescaped) path] of the SAME file. */
const R7_ALIASES: Array<[string, string, string, string]> = [
  ['space', String.raw`${R7_HOME}/x\ y/../${R7_LEAF}`, `"${R7_HOME}/x y/../${R7_LEAF}"`, `${R7_HOME}/x y/../${R7_LEAF}`],
  ['paren', String.raw`${R7_HOME}/x\(y\)/../${R7_LEAF}`, `"${R7_HOME}/x(y)/../${R7_LEAF}"`, `${R7_HOME}/x(y)/../${R7_LEAF}`],
  ['comma', String.raw`${R7_HOME}/x\,y/../${R7_LEAF}`, `"${R7_HOME}/x,y/../${R7_LEAF}"`, `${R7_HOME}/x,y/../${R7_LEAF}`],
  ['equals', String.raw`${R7_HOME}/a\=b/../${R7_LEAF}`, `"${R7_HOME}/a=b/../${R7_LEAF}"`, `${R7_HOME}/a=b/../${R7_LEAF}`],
  ['two escaped spaces', String.raw`${R7_HOME}/a\ b/c\ d/../../${R7_LEAF}`, `'${R7_HOME}/a b/c d/../../${R7_LEAF}'`, `${R7_HOME}/a b/c d/../../${R7_LEAF}`],
  ['escaped tab', `${R7_HOME}/x\\\ty/../${R7_LEAF}`, `"${R7_HOME}/x\ty/../${R7_LEAF}"`, `${R7_HOME}/x\ty/../${R7_LEAF}`],
];
/** Same transcript, other shell spellings of the operand. */
const R7_OTHER_SPELLINGS: Array<[string, string]> = [
  ['ANSI-C $\'…\' with \\x20', String.raw`$'${R7_HOME}/x\x20y/../${R7_LEAF}'`],
  ['line continuation inside the word', `${R7_HOME}/x\\\ny/../${R7_LEAF}`],
  ['mixed quoted and escaped halves', String.raw`${R7_HOME}/"x y"/z\ w/../../${R7_LEAF}`],
  ['escaped dot-dot segment', String.raw`${R7_HOME}/x\ y/\.\./${R7_LEAF}`],
];

const R7_WRITES: Array<[string, string, Record<string, unknown>]> = [
  ...R7_ALIASES.flatMap(([label, escaped, quoted]) => [
    ['Bash', `cp onto the escaped ${label} alias`, { command: `cp /tmp/forged.jsonl ${escaped}` }],
    ['Bash', `sudo cp onto the escaped ${label} alias`, { command: `sudo cp /tmp/forged.jsonl ${escaped}` }],
    ['Bash', `mv onto the escaped ${label} alias`, { command: `mv /tmp/forged.jsonl ${escaped}` }],
    ['Bash', `tee -a onto the escaped ${label} alias`, { command: `echo '{}' | tee -a ${escaped}` }],
    ['Bash', `redirect onto the escaped ${label} alias`, { command: `echo '{}' >> ${escaped}` }],
    ['Bash', `cp onto the quoted ${label} alias`, { command: `cp /tmp/forged.jsonl ${quoted}` }],
  ] as Array<[string, string, Record<string, unknown>]>),
  ...R7_OTHER_SPELLINGS.map(([label, op]) => ['Bash', `cp onto the ${label} alias`, { command: `cp /tmp/forged.jsonl ${op}` }] as [string, string, Record<string, unknown>]),
  ['Bash', 'bash -c with an escaped alias inside single quotes', { command: String.raw`bash -c 'cp /tmp/forged.jsonl ${R7_HOME}/x\ y/../${R7_LEAF}'` }],
  ['Bash', 'command substitution in double quotes with an escaped alias', { command: String.raw`echo "$(cp /tmp/forged.jsonl ${R7_HOME}/x\ y/../${R7_LEAF})"` }],
  // r6 Astra I1: a structured path with a LITERAL backslash in a directory name.
  ['Write', 'a literal backslash directory (x\\y/..) in file_path', { file_path: String.raw`${R7_HOME}/x\y/../${R7_LEAF}`, content: '{}\n' }],
  ['Edit', 'a literal backslash directory (x\\y/..) in file_path', { file_path: String.raw`${R7_HOME}/x\y/../${R7_LEAF}`, old_string: 'a', new_string: 'b' }],
  ['NotebookEdit', 'a literal backslash directory (x\\y/..) in notebook_path', { notebook_path: String.raw`${R7_HOME}/x\y/../${R7_LEAF}`, new_source: 'x' }],
  // r5 Grok NIT 1 (quote-split path), now pinned.
  ['Bash', 'cp onto a mid-path quoted .claude/"projects"/…', { command: `cp /tmp/forged.jsonl ${R7_HOME}/"projects"/-home-owner-work/0b7c-session.jsonl` }],
  ['Bash', 'cp onto a mid-path quoted .claude/"./projects"/…', { command: `cp /tmp/forged.jsonl ${R7_HOME}/"./projects"/-home-owner-work/0b7c-session.jsonl` }],
  // r4 Astra B1 / r4 Grok: spellings the reviewers observed matching, now asserted.
  ['Bash', 'r4: cp onto a relative .claude/projects/… spelling', { command: 'cp /tmp/forged.jsonl .claude/projects/-home-owner-work/0b7c-session.jsonl' }],
  ['Bash', 'r4: cp onto a $HOME/.claude/… spelling', { command: 'cp /tmp/forged.jsonl $HOME/.claude/projects/-home-owner-work/0b7c-session.jsonl' }],
  ['Bash', 'r4: cp onto a "${HOME}/.claude/…" spelling', { command: 'cp /tmp/forged.jsonl "${HOME}/.claude/projects/-home-owner-work/0b7c-session.jsonl"' }],
  ['Write', 'r4: a case variant (matched conservatively)', { file_path: '/home/owner/.Claude/Projects/-home-owner-work/0b7c-session.JSONL', content: '{}\n' }],
  // A read verb whose quoting the shell pairs differently from a naive scan still floors the write.
  ['Bash', 'an escaped quote cannot hide a later cp behind a cat', { command: String.raw`cat ${R7_HOME}/${R7_LEAF} a\'; cp /tmp/forged.jsonl ${R7_HOME}/${R7_LEAF}; echo \'` }],
];

const R7_NOT_FLOORED: Array<[string, string, Record<string, unknown>]> = [
  ...R7_ALIASES.flatMap(([label, escaped, quoted]) => [
    ['Bash', `cat the escaped ${label} alias`, { command: `cat ${escaped}` }],
    ['Bash', `ls the escaped ${label} alias`, { command: `ls -l ${escaped}` }],
    ['Bash', `tail the escaped ${label} alias`, { command: `tail -n 5 ${escaped}` }],
    ['Bash', `cat the quoted ${label} alias`, { command: `cat ${quoted}` }],
    ['Bash', `grep | jq the escaped ${label} alias`, { command: `grep toolu_01 ${escaped} | jq .isSidechain` }],
  ] as Array<[string, string, Record<string, unknown>]>),
  ['Bash', 'cp onto an escaped-space ordinary file', { command: String.raw`cp /tmp/a /home/owner/work/x\ y/../notes.txt` }],
  ['Bash', 'cp onto escaped-space auto-memory', { command: String.raw`cp /tmp/a ${R7_HOME}/x\ y/../projects/-home-owner-work/memory/MEMORY.md` }],
  ['Write', 'an ordinary write through a literal-backslash directory', { file_path: String.raw`/home/owner/work/x\y/../notes.txt`, content: 'x' }],
];

describe('#923 r7 — escaped shell spellings reach the floor (live classifier)', () => {
  it.each(R7_WRITES)('%s: %s is floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals).toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
    expect(v.decision).not.toBe('allow');
  });

  it.each(R7_NOT_FLOORED)('%s: %s is not floored', (tool, _label, input) => {
    const v = evaluateToolCall(tool, input, cfg);
    expect(v.signals ?? []).not.toContain('touch-claude-transcript');
    expect(isGuardSelfProtectionVerdict(v.signals)).toBe(false);
  });

  // Same inode, three spellings (escaped, quoted, structured): one verdict per verb.
  it.each(R7_ALIASES)('quoted and escaped %s spellings get identical live verdicts', (_label, escaped, quoted, structured) => {
    for (const verb of ['cp /tmp/forged.jsonl', 'sudo cp /tmp/forged.jsonl', 'mv /tmp/forged.jsonl', 'cat', 'ls -l', 'tail -n 5']) {
      const e = evaluateToolCall('Bash', { command: `${verb} ${escaped}` }, cfg);
      const q = evaluateToolCall('Bash', { command: `${verb} ${quoted}` }, cfg);
      expect({ verb, decision: e.decision, floor: (e.signals ?? []).includes('touch-claude-transcript') })
        .toEqual({ verb, decision: q.decision, floor: (q.signals ?? []).includes('touch-claude-transcript') });
    }
    const w = evaluateToolCall('Write', { file_path: structured, content: '{}\n' }, cfg);
    expect(w.signals).toContain('touch-claude-transcript');
  });
});

describe('#923 r7 — the hook outage fallback uses the same words', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-923-r7-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: false } }));
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function run(tool: string, input: Record<string, unknown>, mode = 'bypassPermissions'): string | undefined {
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ session_id: 's', cwd: '/tmp', hook_event_name: 'PreToolUse', permission_mode: mode, tool_name: tool, tool_input: input }),
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(home, 'no-dist') },
      encoding: 'utf8',
      timeout: 30_000,
    });
    const out = (r.stdout ?? '').trim();
    return out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : undefined;
  }

  it.each(R7_WRITES)('%s: %s is denied with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBe('deny');
  });

  it.each(R7_NOT_FLOORED)('%s: %s passes with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input)).toBeUndefined();
  });

  it.each(R7_ALIASES)('quoted and escaped %s spellings get identical outage verdicts', (_label, escaped, quoted) => {
    for (const verb of ['cp /tmp/forged.jsonl', 'sudo cp /tmp/forged.jsonl', 'cat', 'ls -l']) {
      expect({ verb, d: run('Bash', { command: `${verb} ${escaped}` }) }).toEqual({ verb, d: run('Bash', { command: `${verb} ${quoted}` }) });
    }
  });

  it.each(R7_ALIASES)('enforcing + dontAsk: a plain cp onto the escaped %s alias does not fail open', (_label, escaped) => {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
    expect(run('Bash', { command: `cp /tmp/forged.jsonl ${escaped}` }, 'dontAsk')).toBe('deny');
  });
});

/**
 * #923 r10 — the floor judges the command AS TYPED, through the shared
 * tokenizer, never a transformed copy of it.
 *
 * r9 Astra B1: `.claude/x$((1))y/../projects/…` (and `$((1+0))`,
 * `$(printf 1)`, backticks, `${unset:-1y}`) is the transcript once bash
 * expands it; the typed word matched nothing. A `.claude` word the shell
 * computes is now refused as a transcript (scripts/lib/shell-words.mjs
 * `claudeWordExpands`), on both planes; nothing is executed.
 * r9 Grok blocker: the live floor read `commandScanText`, whose `#` strip is
 * quote-blind, so `echo "hello #" > <t>` lost its target. The floor and its
 * read carve-out now read the raw command; a real unquoted comment naming a
 * transcript is floored too (accepted over-deny).
 */
const R10_H = '/home/owner/.claude';
const R10_LEAF = 'projects/-home-owner-work/0b7c-session.jsonl';
const R10_EXPANSIONS: Array<[string, string]> = [
  ['$((1))', `${R10_H}/x$((1))y/../${R10_LEAF}`],
  ['$((1+0))', `${R10_H}/x$((1+0))y/../${R10_LEAF}`],
  ['$(printf 1)', `${R10_H}/x$(printf 1)y/../${R10_LEAF}`],
  ['backticks', `${R10_H}/x\`printf 1\`y/../${R10_LEAF}`],
  ['${unset:-1y}', `${R10_H}/x\${unset:-1y}/../${R10_LEAF}`],
  ['$VAR component', `${R10_H}/$P/-home-owner-work/0b7c-session.jsonl`],
  ['double-quoted $(…)', `"${R10_H}/$(echo projects)/-home-owner-work/0b7c-session.jsonl"`],
  ['glob', `${R10_H}/proj*/-home-owner-work/0b7c-session.jsonl`],
  ['mid-word <(…)', `${R10_H}/x<(true)/../../../../${R10_LEAF}`],
  ['glob builds .claude', `/home/owner/.cl*/${R10_LEAF}`],
];
const R10_WRITES: Array<[string, string, Record<string, unknown>]> = [
  ...R10_EXPANSIONS.flatMap(([label, op]) => [
    ['Bash', `cp onto the ${label} alias`, { command: `cp /tmp/forged.jsonl ${op}` }],
    ['Bash', `sudo cp onto the ${label} alias`, { command: `sudo cp /tmp/forged.jsonl ${op}` }],
  ] as Array<[string, string, Record<string, unknown>]>),
  ['Bash', 'tee onto a brace-expanded alias', { command: `tee ${R10_H}/{x,projects}/-home-owner-work/0b7c-session.jsonl < /tmp/forged.jsonl` }],
  ['Bash', 'bash -c with the $((1)) alias', { command: `bash -c 'cp /tmp/forged.jsonl ${R10_H}/x$((1))y/../${R10_LEAF}'` }],
  ['Bash', 'a heredoc onto the $((1)) alias', { command: `cat <<EOF > ${R10_H}/x$((1))y/../${R10_LEAF}\n{}\nEOF` }],
  ['Bash', 'a variable assigned .claude/projects in the same command', { command: `C=${R10_H}/projects; cp /tmp/forged.jsonl $C/-home-owner-work/0b7c-session.jsonl` }],
  // r9 Grok blocker: a quoted `#` before the target.
  ['Bash', 'echo "hello #" redirect', { command: `echo "hello #" > ${R10_H}/${R10_LEAF}` }],
  ['Bash', 'cp "src #" (double quotes)', { command: `cp "/tmp/forged.jsonl #" ${R10_H}/${R10_LEAF}` }],
  ['Bash', "cp 'src #' (single quotes)", { command: `cp '/tmp/forged.jsonl #' ${R10_H}/${R10_LEAF}` }],
  ['Bash', "cp $'src #' (ANSI-C)", { command: `cp $'/tmp/forged.jsonl #' ${R10_H}/${R10_LEAF}` }],
  ['Bash', 'tee "/x #"', { command: `tee "/x #" ${R10_H}/${R10_LEAF} < /tmp/forged.jsonl` }],
  ['Bash', 'echo "a #" onto the escaped-space alias', { command: String.raw`echo "a #" > ${R10_H}/x\ y/../${R10_LEAF}` }],
  // A real unquoted comment naming a transcript: bash writes nothing, the floor over-denies (accepted).
  ['Bash', 'a real unquoted comment naming the transcript (accepted over-deny)', { command: `echo hi # > ${R10_H}/${R10_LEAF}` }],
];
const R10_NOT_FLOORED: Array<[string, string, Record<string, unknown>]> = [
  ['Bash', 'cat a glob alias of the transcript', { command: `cat ${R10_H}/proj*/-home-owner-work/0b7c-session.jsonl` }],
  ['Bash', 'ls .claude/*', { command: `ls ${R10_H}/*` }],
  ['Bash', 'echo "hello #" onto an ordinary file', { command: 'echo "hello #" > /tmp/notes.txt' }],
  ['Bash', 'cp "src #" onto an ordinary file', { command: 'cp "/tmp/forged.jsonl #" /tmp/other.jsonl' }],
  ['Bash', 'an arithmetic alias outside .claude', { command: 'cp /tmp/forged.jsonl /tmp/x$((1))y/../other.jsonl' }],
  ['Bash', 'a computed .jsonl with no .claude named', { command: 'X=/tmp; cp /tmp/forged.jsonl $X/out.jsonl' }],
  ['Bash', 'a pure print naming the transcript', { command: `echo ${R10_H}/${R10_LEAF}` }],
];

for (const enforce of [true, false]) {
  describe(`#923 r10 — expansion and quoted-# spellings reach the floor (live classifier, enforce=${enforce})`, () => {
    const c = { enabled: true, enforce } as any;
    it.each(R10_WRITES)('%s: %s is floored', (tool, _label, input) => {
      const v = evaluateToolCall(tool, input, c);
      expect(v.signals).toContain('touch-claude-transcript');
      expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
      expect(v.decision).not.toBe('allow');
    });
    it.each(R10_NOT_FLOORED)('%s: %s is not floored', (tool, _label, input) => {
      const v = evaluateToolCall(tool, input, c);
      expect(v.signals ?? []).not.toContain('touch-claude-transcript');
      expect(isGuardSelfProtectionVerdict(v.signals)).toBe(false);
    });
  });
}

describe('#923 r10 — the hook outage fallback agrees (dist missing)', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-923-r10-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function run(tool: string, input: Record<string, unknown>, enforce: boolean, mode: string): { decision?: string; reason?: string } {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce } }));
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ session_id: 's', cwd: '/tmp', hook_event_name: 'PreToolUse', permission_mode: mode, tool_name: tool, tool_input: input }),
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(home, 'no-dist') },
      encoding: 'utf8',
      timeout: 30_000,
    });
    const out = (r.stdout ?? '').trim();
    const h = out ? JSON.parse(out).hookSpecificOutput : undefined;
    return { decision: h?.permissionDecision, reason: h?.permissionDecisionReason };
  }

  for (const enforce of [true, false]) {
    it.each(R10_WRITES)(`enforce=${enforce} dontAsk: %s: %s is denied as the transcript floor`, (tool, _label, input) => {
      const r = run(tool, input, enforce, 'dontAsk');
      expect(r.decision).toBe('deny');
      expect(r.reason).toMatch(/touch-claude-transcript/);
    });
  }
  it.each(R10_NOT_FLOORED)('%s: %s passes with the guard unloaded', (tool, _label, input) => {
    expect(run(tool, input, false, 'bypassPermissions').decision).toBeUndefined();
  });
});

/**
 * #923 r10 — same inode, real effect. bash runs each spelling as an
 * UNPRIVILEGED copy of inert JSON inside a scratch home (never the real one),
 * and the canonical transcript's inode must be the one written; then both
 * planes must floor the identical command text.
 */
const itBash = process.platform === 'win32' ? it.skip : it;
describe('#923 r10 — same-inode effect oracle', () => {
  let root: string;
  let H: string;
  let T: string;
  let SRC: string;
  const CANON = '{"canonical":true}\n';
  beforeEach(() => {
    // r11 (r10 Astra): the scratch root honours TMPDIR, never a hardcoded /tmp.
    root = mkdtempSync(join(tmpdir(), 'sc-923-r10-inode-'));
    H = join(root, 'home');
    T = join(H, '.claude', 'projects', 'p', 's.jsonl');
    SRC = join(root, 'forged.jsonl');
    mkdirSync(dirname(T), { recursive: true });
    for (const d of ['x1y', 'x y']) mkdirSync(join(H, '.claude', d), { recursive: true });
    writeFileSync(T, CANON);
    writeFileSync(SRC, '{"forged":true}\n');
    writeFileSync(`${SRC} #`, '{"forged":true}\n');
    mkdirSync(join(H, '.shieldcortex'), { recursive: true });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const SPELLINGS: Array<[string, () => string]> = [
    ['x$((1))y', () => `cp ${SRC} ${H}/.claude/x$((1))y/../projects/p/s.jsonl`],
    ['x$((1+0))y', () => `cp ${SRC} ${H}/.claude/x$((1+0))y/../projects/p/s.jsonl`],
    ['x$(printf 1)y', () => `cp ${SRC} ${H}/.claude/x$(printf 1)y/../projects/p/s.jsonl`],
    ['x`printf 1`y', () => `cp ${SRC} ${H}/.claude/x\`printf 1\`y/../projects/p/s.jsonl`],
    ['x${unset:-1y}', () => `cp ${SRC} ${H}/.claude/x\${unset:-1y}/../projects/p/s.jsonl`],
    ['echo "hello #" >', () => `echo "hello #" > ${T}`],
    ['cp "src #"', () => `cp "${SRC} #" ${T}`],
    ["cp 'src #'", () => `cp '${SRC} #' ${T}`],
    ["cp $'src #'", () => `cp $'${SRC} #' ${T}`],
    ['tee "x #"', () => `tee "${root}/x #" ${T} < ${SRC}`],
    ['echo "a #" > escaped-space alias', () => String.raw`echo "a #" > ${H}/.claude/x\ y/../projects/p/s.jsonl`],
  ];

  itBash.each(SPELLINGS)('%s writes the canonical inode and both planes floor it', (_label, cmd) => {
    const command = cmd();
    const ino = statSync(T).ino;
    const r = spawnSync('bash', ['--noprofile', '--norc', '-c', command], { cwd: root, env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: H }, encoding: 'utf8', timeout: 10_000 });
    expect(r.status).toBe(0);
    expect(statSync(T).ino).toBe(ino);
    expect(readFileSync(T, 'utf8')).not.toBe(CANON);
    for (const enforce of [true, false]) {
      const v = evaluateToolCall('Bash', { command }, { enabled: true, enforce } as any);
      expect({ enforce, signals: v.signals ?? [] }).toEqual({ enforce, signals: expect.arrayContaining(['touch-claude-transcript']) });
      writeFileSync(join(H, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce } }));
      const h = spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ session_id: 's', cwd: root, hook_event_name: 'PreToolUse', permission_mode: 'dontAsk', tool_name: 'Bash', tool_input: { command } }),
        env: { ...process.env, HOME: H, SHIELDCORTEX_CONFIG_DIR: join(H, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(root, 'no-dist') },
        encoding: 'utf8',
        timeout: 30_000,
      });
      const out = JSON.parse((h.stdout ?? '').trim() || '{}').hookSpecificOutput ?? {};
      expect({ enforce, decision: out.permissionDecision }).toEqual({ enforce, decision: 'deny' });
      expect(out.permissionDecisionReason).toMatch(/touch-claude-transcript/);
    }
  });
});

/**
 * #923 r11 (r10 Grok BLOCKER, r10 Astra B1) — anchors split across an
 * expansion. `cp src /h/.cla${unset:-ude/projects/p/s.jsonl}`,
 * `.cla$(printf %s ude/…)`, `A=/h/.cla; B=ude/…; cp src $A$B` and the
 * composed glob `.cl[a]ude/proj[e]cts/…` all wrote the transcript while every
 * piece of the word, judged alone, named nothing. The shared refusal now
 * JOINS the pieces (scripts/lib/shell-words.mjs
 * `claudeJoinedWordMayBeTranscript`) on both planes; nothing is executed.
 */
const R11_WRITES = joinedSpellings('/home/owner', '/tmp/forged.jsonl', '0b7c-session.jsonl');
const R11_NOT_FLOORED = joinedControls('/home/owner', '/tmp/forged.jsonl', '0b7c-session.jsonl');

for (const enforce of [true, false]) {
  describe(`#923 r11 — joined spellings reach the floor (live classifier, enforce=${enforce})`, () => {
    const c = { enabled: true, enforce } as any;
    it.each(R11_WRITES)('%s is floored', (_label, command) => {
      for (const cmd of [command, `sudo ${command}`]) {
        const v = evaluateToolCall('Bash', { command: cmd }, c);
        expect({ cmd, signals: v.signals ?? [] }).toEqual({ cmd, signals: expect.arrayContaining(['touch-claude-transcript']) });
        expect(isGuardSelfProtectionVerdict(v.signals)).toBe(true);
        expect(v.decision).not.toBe('allow');
      }
    });
    it.each(R11_NOT_FLOORED)('%s is not floored', (_label, command) => {
      const v = evaluateToolCall('Bash', { command }, c);
      expect(v.signals ?? []).not.toContain('touch-claude-transcript');
    });
  });
}

describe('#923 r11 — the hook outage fallback agrees on joined spellings (dist missing)', () => {
  let home: string;
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-923-r11-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  function run(command: string, enforce: boolean, mode: string): { decision?: string; reason?: string } {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce } }));
    const r = spawnSync(process.execPath, [HOOK], {
      input: JSON.stringify({ session_id: 's', cwd: '/tmp', hook_event_name: 'PreToolUse', permission_mode: mode, tool_name: 'Bash', tool_input: { command } }),
      env: { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(home, 'no-dist') },
      encoding: 'utf8',
      timeout: 30_000,
    });
    const out = (r.stdout ?? '').trim();
    const h = out ? JSON.parse(out).hookSpecificOutput : undefined;
    return { decision: h?.permissionDecision, reason: h?.permissionDecisionReason };
  }

  for (const enforce of [true, false]) {
    it.each(R11_WRITES)(`enforce=${enforce} dontAsk: %s is denied as the transcript floor`, (_label, command) => {
      const r = run(command, enforce, 'dontAsk');
      expect(r.decision).toBe('deny');
      expect(r.reason).toMatch(/touch-claude-transcript/);
    });
  }
  it.each(R11_NOT_FLOORED)('%s passes with the guard unloaded', (_label, command) => {
    expect(run(command, false, 'bypassPermissions').decision).toBeUndefined();
  });
});

/**
 * #923 r11 — real effect for the joined spellings, and (r10 Astra N1) a real
 * same-inode check for the r7 escaped-vs-quoted alias pairs: the alias
 * directories are created, bash resolves each spelling (`realpath`) to the
 * canonical transcript, an unprivileged copy changes that inode's content,
 * and both planes floor the identical text. Scratch HOME under tmpdir()
 * (TMPDIR), never the real home.
 */
describe('#923 r11 — same-inode effect oracle (joined spellings, r7 alias pairs)', () => {
  let root: string;
  let H: string;
  let T: string;
  let SRC: string;
  const CANON = '{"canonical":true}\n';
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sc-923-r11-inode-'));
    H = join(root, 'home');
    T = join(H, '.claude', 'projects', 'p', 's.jsonl');
    SRC = join(root, 'forged.jsonl');
    mkdirSync(dirname(T), { recursive: true });
    mkdirSync(join(H, '.claude', 'projects', 'x1y'), { recursive: true });
    for (const d of ['x y', 'x(y)', 'x,y', 'a=b', 'a b/c d', 'x\ty']) mkdirSync(join(H, '.claude', d), { recursive: true });
    writeFileSync(T, CANON);
    writeFileSync(SRC, '{"forged":true}\n');
    writeFileSync(join(root, 's.jsonl'), '{"forged":true}\n');
    mkdirSync(join(H, '.shieldcortex'), { recursive: true });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const bash = (command: string) => spawnSync('bash', ['--noprofile', '--norc', '-c', command],
    { cwd: root, env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: H }, encoding: 'utf8', timeout: 10_000 });

  function bothPlanesFloor(command: string): void {
    for (const enforce of [true, false]) {
      const v = evaluateToolCall('Bash', { command }, { enabled: true, enforce } as any);
      expect({ enforce, signals: v.signals ?? [] }).toEqual({ enforce, signals: expect.arrayContaining(['touch-claude-transcript']) });
      writeFileSync(join(H, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce } }));
      const h = spawnSync(process.execPath, [HOOK], {
        input: JSON.stringify({ session_id: 's', cwd: root, hook_event_name: 'PreToolUse', permission_mode: 'dontAsk', tool_name: 'Bash', tool_input: { command } }),
        env: { ...process.env, HOME: H, SHIELDCORTEX_CONFIG_DIR: join(H, '.shieldcortex'), SHIELDCORTEX_DIST_ROOT: join(root, 'no-dist') },
        encoding: 'utf8',
        timeout: 30_000,
      });
      const out = JSON.parse((h.stdout ?? '').trim() || '{}').hookSpecificOutput ?? {};
      expect({ enforce, decision: out.permissionDecision }).toEqual({ enforce, decision: 'deny' });
      expect(out.permissionDecisionReason).toMatch(/touch-claude-transcript/);
    }
  }

  itBash.each(joinedSpellings('H', 'SRC', 's.jsonl').map(([label]) => [label]))('%s writes the canonical inode and both planes floor it', (label) => {
    const command = joinedSpellings(H, SRC, 's.jsonl').find(([l]) => l === label)![1];
    const ino = statSync(T).ino;
    const r = bash(command);
    expect({ status: r.status, stderr: r.stderr }).toEqual({ status: 0, stderr: '' });
    expect(statSync(T).ino).toBe(ino);
    expect(readFileSync(T, 'utf8')).toBe('{"forged":true}\n');
    bothPlanesFloor(command);
  });

  // r10 Astra N1: the r7 pairs, as REAL directories, resolve to the same inode.
  const pairs = (h: string): Array<[string, string, string]> => {
    const c = `${h}/.claude`;
    const leaf = 'projects/p/s.jsonl';
    return [
      ['space', String.raw`${c}/x\ y/../${leaf}`, `"${c}/x y/../${leaf}"`],
      ['paren', String.raw`${c}/x\(y\)/../${leaf}`, `"${c}/x(y)/../${leaf}"`],
      ['comma', String.raw`${c}/x\,y/../${leaf}`, `"${c}/x,y/../${leaf}"`],
      ['equals', String.raw`${c}/a\=b/../${leaf}`, `"${c}/a=b/../${leaf}"`],
      ['two escaped spaces', String.raw`${c}/a\ b/c\ d/../../${leaf}`, `'${c}/a b/c d/../../${leaf}'`],
      ['escaped tab', `${c}/x\\\ty/../${leaf}`, `"${c}/x\ty/../${leaf}"`],
    ];
  };
  itBash.each(pairs('H').map(([label]) => [label]))('r7 %s pair: escaped and quoted spellings are the same real inode, written, and floored', (label) => {
    const [, escaped, quoted] = pairs(H).find(([l]) => l === label)!;
    const canon = realpathSync(T);
    const ino = statSync(T).ino;
    for (const spelling of [escaped, quoted]) {
      const rp = bash(`realpath -- ${spelling}`);
      expect({ spelling, status: rp.status, path: rp.stdout.trim() }).toEqual({ spelling, status: 0, path: canon });
      const st = bash(`stat -c %i -- ${spelling}`);
      expect({ spelling, ino: Number(st.stdout.trim()) }).toEqual({ spelling, ino });
      writeFileSync(T, CANON);
      const command = `cp ${SRC} ${spelling}`;
      expect(bash(command).status).toBe(0);
      expect(statSync(T).ino).toBe(ino);
      expect(readFileSync(T, 'utf8')).toBe('{"forged":true}\n');
      bothPlanesFloor(command);
    }
  });
});

/**
 * #923 documented residuals (CHANGELOG #923; tool-action-guard.ts beside
 * CLAUDE_TRANSCRIPT_PATH_RE): the floor is lexical, so these spellings of the
 * transcript are NOT floored. Pinned here so the gap is stated in the suite,
 * and so a future fix flips these on purpose. None is a regression of r7.
 */
describe('#923 documented residuals (not resolved lexically)', () => {
  it.each<[string, string, Record<string, unknown>]>([
    ['symlink', 'Write through a symlink that does not spell .claude/projects', { file_path: '/home/owner/alias.jsonl', content: '{}\n' }],
    ['cd-relative', 'a relative leaf after an earlier cd', { command: 'cd /home/owner/.claude/projects/-home-owner-work && echo x > 0b7c-session.jsonl' }],
    ['CLAUDE_CONFIG_DIR', 'a custom Claude home', { file_path: '/srv/claude-home/projects/-home-owner-work/0b7c-session.jsonl', content: '{}\n' }],
    ['camelCase notebookPath', 'NotebookEdit with notebookPath (not a PATH_KEY)', { notebookPath: T, new_source: 'x' }],
    ['space in the project component', 'Claude Code never generates one; the regex stops at whitespace', { file_path: '/home/owner/.claude/projects/my proj/0b7c-session.jsonl', content: '{}\n' }],
    // r10: the command never spells `.claude` or a transcript tail; the value
    // comes from the environment or a file the guard does not evaluate.
    ['environment variable', 'a whole transcript path held in a variable set outside the command', { command: 'cp /tmp/forged.jsonl $SC_TRANSCRIPT' }],
    ['substitution from a file', 'a whole transcript path read from a file', { command: 'cp /tmp/forged.jsonl $(cat /tmp/path-file)' }],
  ])('residual (%s): %s is not floored', (_name, _label, input) => {
    const tool = 'command' in input ? 'Bash' : 'notebookPath' in input ? 'NotebookEdit' : 'Write';
    expect(evaluateToolCall(tool, input, cfg).signals ?? []).not.toContain('touch-claude-transcript');
  });
});
