/**
 * Which closed key-set does a tool name pick?
 *
 * #454 moved that question from SUBSTRING matching to SEGMENT-ANCHORED
 * matching, which fixed `Pu(sh)Notification` and `(sh)are_file`. It left the
 * two WEAK words — `run` and `command` — anchored at segment boundaries, and
 * that is still too wide, because those words are ordinary English nouns in
 * host tool names:
 *
 *   get_workflow_run / list_workflow_runs   GitHub Actions, read-only
 *   get_command / slash_command             names a command, runs nothing
 *   command_center                          a noun
 *
 * All of them were forced into EXEC_KEYS, where every field of their live bag
 * is an UNKNOWN_KEY — `invalid_tool_input` on every real call: an approval card
 * attended, a failure-policy denial unattended. The same anchoring ALSO missed
 * `runCommand`, because the segment was lowercased before it was split, so the
 * one camelCase spelling a host actually ships fell to the unknown bag.
 *
 * The rule now: a weak word counts only when the WHOLE name is exec vocabulary
 * (`run`, `run_command`, `runCommand`, `runcommand`, `execute_command`), in any
 * separator style. Strong words (`bash`, `spawn`, `exec`, …) keep their own
 * segment-anchored rule. Nothing here removes a SCAN — see the last block.
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';
import { enforceToolInput, hasExactSpecialToolSchema, schemaFamilyForTool } from '../tool-input-schema.js';

const BIN = String.fromCharCode(114, 109);
const RF = ['-', 'r', 'f'].join('');
const WIPE_TOKENS = [BIN, RF, '/'];
const DANGER_TOKENS = [String.fromCharCode(115, 117, 100, 111), 'id'];

/** Genuine exec names. Every one keeps the closed bag. */
const EXEC_NAMES = [
  // whole name is one exec word
  'run', 'command', 'bash', 'sh', 'zsh', 'cmd', 'exec', 'shell', 'powershell',
  'terminal', 'script', 'eval', 'spawn', 'process', 'system',
  // whole name is exec words, every separator style
  'run_command', 'runCommand', 'runcommand', 'RunCommand', 'run-command',
  'run_terminal', 'runTerminal', 'execute_command', 'ExecuteCommand',
  'shell_command', 'command_run', 'exec_command', 'runShell', 'runCmd',
  // a strong word at a segment boundary, whatever the rest is
  'shell_exec', 'spawn_process', 'eval_code', 'script_run', 'code_exec',
  'terminal_run', 'vendor_bash', 'sessions_spawn_agent', 'vendor_sessions_spawn',
] as const;

/** MCP spelling is a routing boundary, never trusted identity or suffix inference. */
const MCP_FRONTED_NAMES = [
  'mcp__vendor__bash', 'mcp__web__run', 'mcp__openclaw__sessions_spawn',
  'mcp__collaboration__spawn_agent', 'mcp__evil__sessions_spawn',
  'MCP__OpenClaw__Sessions_Spawn',
] as const;

/**
 * Live first-party names whose ONLY exec evidence is a weak word used as an
 * English noun. Each row is a real host tool with a real, inert bag.
 */
const WEAK_WORD_NAMES: Array<[string, Record<string, unknown>]> = [
  ['mcp__github__get_workflow_run', { owner: 'o', repo: 'r', run_id: 42 }],
  ['mcp__github__list_workflow_runs', { owner: 'o', repo: 'r', workflow_id: 'ci.yml', per_page: 20 }],
  ['mcp__github__get_workflow_run_logs', { owner: 'o', repo: 'r', run_id: 42 }],
  ['workflow_run', { id: 42, status: 'completed', conclusion: 'success' }],
  ['WorkflowRun', { id: 42, status: 'completed' }],
  ['get_command', { name: 'deploy' }],
  ['GetCommandHistory', { limit: 20 }],
  ['slash_command', { command_name: 'review', arguments: 'src/' }],
  ['command_center', { panel: 'main', refresh: true }],
  ['CommandCenter', { panel: 'main' }],
  ['thirdparty_run', { task: 'work' }],
  ['runbook_lookup', { title: 'oncall' }],
];

describe('schema family — weak exec words need the whole name', () => {
  it.each(EXEC_NAMES)('%s is exec schema', (tool) => {
    expect(schemaFamilyForTool(tool)).toBe('exec');
  });

  it.each(WEAK_WORD_NAMES)('%s is NOT exec schema', (tool) => {
    expect(schemaFamilyForTool(tool)).not.toBe('exec');
  });

  it.each(WEAK_WORD_NAMES)('%s no longer denies its live bag', (tool, args) => {
    const v = evaluateToolCall(tool, args);
    expect(v.decision).toBe('allow');
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.signals).not.toContain('invalid-tool-input');
  });

  it.each(EXEC_NAMES)('%s still fails closed on an unknown key', (tool) => {
    const raw = { command: 'ls -la', evil_payload: 'x' };
    if (hasExactSpecialToolSchema(tool)) {
      // Reviewed native contracts drop non-evidence extras as drift, not cards.
      expect(enforceToolInput(tool, raw)).toMatchObject({ ok: true, strippedKeys: ['evil_payload'] });
      expect(evaluateToolCall(tool, raw)).toMatchObject({ decision: 'allow' });
      expect(evaluateToolCall(tool, raw).action).not.toBe('invalid_tool_input');
      return;
    }
    expect(enforceToolInput(tool, raw))
      .toMatchObject({ ok: false, code: 'UNKNOWN_KEYS' });
    expect(evaluateToolCall(tool, raw))
      .toMatchObject({ decision: 'require_approval', action: 'invalid_tool_input' });
  });

  it.each(EXEC_NAMES)('%s still allows its own declared shape', (tool) => {
    expect(evaluateToolCall(tool, { command: 'printf ok' }).decision).toBe('allow');
  });
});

describe('schema family — MCP-fronted names never infer from the final segment', () => {
  it.each(MCP_FRONTED_NAMES)('%s uses the generic unknown schema family', (tool) => {
    expect(schemaFamilyForTool(tool)).toBe('unknown');
  });

  it.each(MCP_FRONTED_NAMES)('%s allows harmless structured fields after annotation', (tool) => {
    const v = evaluateToolCall(tool, { task: 'work', structured: { nested: ['data'] } });
    expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
    expect(v.action).not.toBe('invalid_tool_input');
  });

  it.each(MCP_FRONTED_NAMES)('%s still scans raw command and argv evidence', (tool) => {
    expect(evaluateToolCall(tool, { argv: DANGER_TOKENS }).decision).not.toBe('allow');
    expect(evaluateToolCall(tool, { command: BIN, argv: [RF, '/'] }))
      .toMatchObject({ decision: 'block', severity: 'catastrophic' });
  });
});

describe('schema family — the glued and camelCase spellings are the same name', () => {
  it('every separator style of the same exec name agrees', () => {
    for (const spelling of ['run_command', 'runCommand', 'runcommand', 'RunCommand', 'run-command']) {
      expect(schemaFamilyForTool(spelling)).toBe('exec');
    }
  });

  it('a glued token that is NOT all exec words does not decompose', () => {
    for (const tool of ['runbook', 'commandcenter', 'systemctl', 'preprocess', 'evaluate',
      'subscription', 'transcript', 'publish', 'processor']) {
      expect(schemaFamilyForTool(tool)).not.toBe('exec');
    }
  });

  it('the #454 substring names are still not exec schema', () => {
    for (const tool of ['PushNotification', 'share_file', 'publish_post', 'preprocess_data',
      'filesystem_list', 'evaluate_model', 'transcript_fetch', 'subscription_status',
      'runbook_lookup']) {
      expect(schemaFamilyForTool(tool)).not.toBe('exec');
    }
  });
});

describe('schema family — the narrowing removes the DENY, never the SCAN', () => {
  it.each(WEAK_WORD_NAMES)('%s still scans a smuggled command wipe', (tool) => {
    for (const key of ['command', 'script', 'code', 'input', 'shell', 'run']) {
      expect(evaluateToolCall(tool, { [key]: WIPE_TOKENS.join(' ') })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it.each(WEAK_WORD_NAMES)('%s still scans a smuggled argv wipe', (tool) => {
    for (const key of ['args', 'argv']) {
      expect(evaluateToolCall(tool, { [key]: WIPE_TOKENS })).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it.each(WEAK_WORD_NAMES)('%s still gates a dangerous argv', (tool) => {
    expect(evaluateToolCall(tool, { argv: ['sudo', 'systemctl', 'stop', 'ssh'] }).decision)
      .not.toBe('allow');
  });

  it('git and the native control plane are untouched by the narrowing', () => {
    for (const tool of ['git', 'git_commit', 'BashOutput', 'TaskOutput', 'TaskStop', 'KillShell']) {
      expect(evaluateToolCall(tool, { surprise: 'x' })).toMatchObject({
        decision: 'require_approval', action: 'invalid_tool_input',
      });
    }
    expect(evaluateToolCall('TaskOutput', { task_id: 't', block: true, timeout: 30_000 }))
      .toMatchObject({ decision: 'allow', severity: 'benign' });
  });

  it('the reviewed native contracts still resolve to their own family', () => {
    expect(schemaFamilyForTool('sessions_spawn')).toBe('read');
    expect(schemaFamilyForTool('web.run')).toBe('network');
    expect(schemaFamilyForTool('collaboration.spawn_agent')).toBe('read');
  });
});
