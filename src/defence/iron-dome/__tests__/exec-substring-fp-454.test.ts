/**
 * #454 — exec-substring misclassification picked the schema.
 *
 * `classifyFamily` matches exec vocabulary as a bare SUBSTRING
 * (`/…|spawn|process|eval|script|sh|…/`) on purpose: a tool whose name merely
 * contains `sh` should still have its ARGUMENTS weighed as exec, because a
 * command string is dangerous wherever it appears. `schemaFamilyForTool` asks a
 * different question — which closed key-set is this tool's contract? — and
 * answers it at SEGMENT boundaries (`(^|_)sh(_|$)`).
 *
 * The schema gate in `evaluateToolCall` was using the substring answer, so:
 *
 *   Pu·sh·Notification              → exec → EXEC_KEYS → `status` UNKNOWN_KEYS
 *   Google_Drive__·sh·are_file      → exec → EXEC_KEYS → `fileId` UNKNOWN_KEYS
 *
 * Both hard-blocked as `invalid_tool_input` on every real call: an approval
 * card attended, a failure-policy denial unattended, on two first-party tools
 * that cannot execute anything. The fold drops `guardFam === 'exec'` from the
 * mode choice. `classifyFamily` itself is UNCHANGED — the verdict still treats
 * these names as exec-weighted, which is why the malicious half of this file
 * still blocks.
 *
 * Live host schemas, quoted so a future edit can be checked against them:
 *   PushNotification  {message: string, status: "proactive"}   required both
 *   share_file        {fileId, emailAddress, role: string}     required all
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall, classifyFamily } from '../tool-action-guard.js';
import { enforceToolInput, schemaFamilyForTool, validateToolInput } from '../tool-input-schema.js';

/** Composed, not spelled: this file must not be an evidence hit on itself. */
const BIN = String.fromCharCode(114, 109);
const RF = ['-', 'r', 'f'].join('');
const WIPE = `${BIN} ${RF} /`;
const WIPE_TOKENS = [BIN, RF, '/'];

/** The live first-party calls that were being denied, tool → exact arguments. */
const LIVE_BENIGN: Array<[string, Record<string, unknown>]> = [
  ['PushNotification', { message: 'build finished: 2 auth tests failed', status: 'proactive' }],
  ['mcp__claude_ai_Google_Drive__share_file', { fileId: '1a2B3c', emailAddress: 'colleague@example.com', role: 'reader' }],
  ['Google_Drive__share_file', { fileId: '1a2B3c', emailAddress: 'colleague@example.com', role: 'writer' }],
  ['share_file', { fileId: '1a2B3c', emailAddress: 'colleague@example.com', role: 'commenter' }],
];

/**
 * Names whose only exec evidence is a substring inside an ordinary English
 * word. None of these can run anything; every one used to fail closed.
 */
const SUBSTRING_ONLY = [
  ['PushNotification', 'sh', 'Pu(sh)Notification'],
  ['share_file', 'sh', '(sh)are_file'],
  ['publish_post', 'sh', 'publi(sh)_post'],
  ['preprocess_data', 'process', 'pre(process)_data'],
  ['filesystem_list', 'system', 'file(system)_list'],
  ['evaluate_model', 'eval', '(eval)uate_model'],
  ['transcript_fetch', 'script', 'tran(script)_fetch'],
  ['subscription_status', 'script', 'sub(script)ion_status'],
  ['runbook_lookup', 'run', '(run)book_lookup'],
] as const;

describe('#454 — a substring is not a contract', () => {
  it.each(SUBSTRING_ONLY)(
    '%s is exec-WEIGHTED but not exec-SCHEMA'.concat(' [%s in %s]'),
    (tool) => {
      // The weighting is deliberate and unchanged: args are still read as exec.
      expect(classifyFamily(tool)).toBe('exec');
      // The contract is not: a bare substring must not pick the closed key-set.
      expect(schemaFamilyForTool(tool)).not.toBe('exec');
    },
  );

  it.each(SUBSTRING_ONLY)('%s no longer denies an ordinary field', (tool) => {
    const v = evaluateToolCall(tool, { title: 'x', someHostField: 'y', another: 42 });
    expect(v.decision).toBe('allow');
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.signals).not.toContain('invalid-tool-input');
  });

  it.each(LIVE_BENIGN)('the live %s call costs nothing', (tool, args) => {
    const v = evaluateToolCall(tool, args);
    expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.signals).not.toContain('invalid-tool-input');
  });

  it('the inert host fields are stripped, never forwarded to an extractor', () => {
    const r = validateToolInput(
      'mcp__claude_ai_Google_Drive__share_file',
      { fileId: '1a2B3c', emailAddress: 'colleague@example.com', role: 'reader' },
      'annotate',
    );
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args).toEqual({});
      expect(r.strippedKeys).toEqual(['fileId', 'emailAddress', 'role']);
    }
  });
});

describe('#454 — genuine exec names still enforce', () => {
  const REAL_EXEC = [
    'Bash', 'bash', 'sh', 'zsh', 'shell_exec', 'run_command', 'execute_command',
    'powershell', 'terminal_run', 'spawn_process', 'eval_code', 'script_run',
    'code_exec',
  ] as const;

  it.each(REAL_EXEC)('%s still fails closed on an unknown key', (tool) => {
    expect(schemaFamilyForTool(tool)).toBe('exec');
    const r = enforceToolInput(tool, { command: 'ls -la', evil_payload: 'x' });
    expect(r).toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    const v = evaluateToolCall(tool, { command: 'ls -la', evil_payload: 'x' });
    expect(v).toMatchObject({ decision: 'require_approval', action: 'invalid_tool_input' });
    expect(v.signals).toContain('invalid-tool-input');
  });

  it.each(REAL_EXEC)('%s still allows its own declared shape', (tool) => {
    expect(evaluateToolCall(tool, { command: 'printf ok' }).decision).toBe('allow');
  });

  it('git and the native control plane are unaffected by the fold', () => {
    for (const tool of ['git', 'git_commit', 'BashOutput', 'TaskOutput', 'TaskStop', 'KillShell']) {
      expect(evaluateToolCall(tool, { surprise: 'x' })).toMatchObject({
        decision: 'require_approval', action: 'invalid_tool_input',
      });
    }
    // The reviewed exact-special contracts keep their own (drift-aware) path.
    expect(evaluateToolCall('sessions_spawn', { task: 'work', command: 'ls' })).toMatchObject({
      decision: 'require_approval', action: 'invalid_tool_input',
    });
  });
});

describe('#454 — the fold removes the DENY, never the SCAN', () => {
  /**
   * Annotate keeps every EXTRACTOR key regardless of the tool's family, so a
   * command/script/code payload on a substring-exec name reaches the scanners
   * exactly as it did under enforcement.
   */
  it.each(['command', 'cmd', 'script', 'code', 'input', 'shell', 'run'])(
    'a wipe in %s is still catastrophic on a substring-exec name',
    (key) => {
      for (const [tool, args] of LIVE_BENIGN) {
        expect(evaluateToolCall(tool, { ...args, [key]: WIPE })).toMatchObject({
          decision: 'block', severity: 'catastrophic',
        });
      }
    },
  );

  /**
   * `args`/`argv` are command evidence but NOT extractor keys, so annotate
   * strips them. Under the old enforcement they were unknown keys and reached
   * the scanner via the schema-rejection rescan; the fold rescans exactly what
   * annotate dropped so that guarantee survives.
   */
  it.each(['args', 'argv'])('a wipe in a STRIPPED %s is rescanned, not lost', (key) => {
    for (const payload of [WIPE, WIPE_TOKENS, { a: [BIN, RF], b: '/' }]) {
      expect(evaluateToolCall('PushNotification', { message: 'ok', [key]: payload })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
      expect(evaluateToolCall('runCommand', { [key]: payload })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it('a wipe buried mid-payload in a long stripped argv still scans', () => {
    const mid = `${'x'.repeat(140_000)} ${WIPE} ${'y'.repeat(20_000)}`;
    expect(evaluateToolCall('share_file', { fileId: 'a', argv: mid })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('camelCase exec names keep their argv teeth', () => {
    for (const tool of ['runCommand', 'runCode', 'sendCommand', 'spawnAgent', 'systemctl']) {
      expect(evaluateToolCall(tool, { argv: WIPE_TOKENS })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it('a benign stripped argv is not escalated by the rescan', () => {
    expect(evaluateToolCall('PushNotification', {
      message: 'ok', status: 'proactive', argv: ['--verbose', 'build'],
    })).toMatchObject({ decision: 'allow', severity: 'benign' });
  });

  it('secrets and egress evidence on these names are still weighed', () => {
    expect(evaluateToolCall('share_file', { fileId: 'a', command: 'cat ~/.aws/credentials' }).decision)
      .not.toBe('allow');
  });
});
