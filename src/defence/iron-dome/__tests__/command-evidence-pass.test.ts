/**
 * The one shared command-evidence pass.
 *
 * Three uninstall-class holes, all in the same direction — a real root wipe or
 * a real service kill answered `allow`/`benign` — because command evidence was
 * scanned by two PARTIAL rescans bolted to two schema outcomes instead of once,
 * before the schema was consulted at all:
 *
 *   1. A VALID exec bag was never rescanned. `argv` is a DECLARED key of
 *      EXEC_KEYS, so a spawn-shaped call validated cleanly and only its
 *      first-wins `command` string was ever scanned. The host runs
 *      `command` WITH `argv`; the guard read the verb without its arguments.
 *   2. Both rescans propagated only `catastrophic`. A dangerous-tier `argv`
 *      (privilege escalation, service stop, force-push) was computed and then
 *      discarded, and the call returned `allow`.
 *   3. Neither noticed a TRUNCATED walk. Past the leaf cap the remaining
 *      elements were dropped silently, so a wipe behind 16k of padding read as
 *      a clean scan.
 *
 * Every payload here is composed at runtime, never spelled: this file must not
 * be an evidence hit on itself.
 */
import { describe, expect, it } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

const BIN = String.fromCharCode(114, 109);
const RF = ['-', 'r', 'f'].join('');
const ROOT = '/';
const WIPE_TOKENS = [BIN, RF, ROOT];
const WIPE = WIPE_TOKENS.join(' ');
const SUDO_STOP = ['sudo', 'systemctl', 'stop', 'ssh'];

/** Names whose live contract really does carry a separate argument vector. */
const EXEC_NAMES = ['spawn_process', 'runCommand', 'run_command', 'Bash', 'shell_exec'] as const;

describe('command evidence — the verb and its arguments are one call', () => {
  it.each(EXEC_NAMES)('%s: a split command/argv wipe is catastrophic, not a card', (tool) => {
    expect(evaluateToolCall(tool, { command: BIN, argv: [RF, ROOT] })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it.each(EXEC_NAMES)('%s: the same split through `args` is catastrophic', (tool) => {
    expect(evaluateToolCall(tool, { command: BIN, args: [RF, ROOT] })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('an N-way split across command + args + argv is still one wipe', () => {
    expect(evaluateToolCall('spawn_process', { command: BIN, args: [RF], argv: [ROOT] }))
      .toMatchObject({ decision: 'block', severity: 'catastrophic' });
  });

  it('the schema ACCEPTS these bags — the scan is what changed, not the contract', () => {
    // `command`/`args`/`argv` are all declared EXEC_KEYS: this call never
    // reached a rejection path, which is exactly why it went unscanned.
    const v = evaluateToolCall('spawn_process', { command: BIN, argv: [RF, ROOT] });
    expect(v.action).not.toBe('invalid_tool_input');
    expect(v.signals).not.toContain('invalid-tool-input');
  });

  it('an argv with no verb is still read as a command', () => {
    expect(evaluateToolCall('spawn_process', { argv: WIPE_TOKENS })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('each alias stays its OWN surface — a wipe is not laundered by a benign verb', () => {
    // Joined into one statement, `echo` would be the verb and the wipe its
    // data. The individual surfaces are scanned too, so it is not.
    expect(evaluateToolCall('spawn_process', { command: 'echo', args: [WIPE] })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a non-first-wins command alias is scanned, not shadowed', () => {
    // `extractCommand` is first-wins, so `script` used to be invisible whenever
    // `command` was present and benign.
    expect(evaluateToolCall('Bash', { command: 'ls', script: WIPE })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });
});

describe('command evidence — dangerous propagates, not only catastrophic', () => {
  it.each(EXEC_NAMES)('%s: a privilege-escalating argv is gated', (tool) => {
    const v = evaluateToolCall(tool, { argv: SUDO_STOP });
    expect(v.decision).not.toBe('allow');
    expect(v.severity).toBe('dangerous');
    expect(v.signals).toContain('privilege-escalation');
  });

  it('a dangerous argv on a VALID exec bag gates beside a benign command', () => {
    const v = evaluateToolCall('spawn_process', { command: 'sudo', argv: ['systemctl', 'stop', 'ssh'] });
    expect(v.decision).not.toBe('allow');
  });

  it('the evidence verdict never weakens the one from the normal path', () => {
    // Schema rejection is `require_approval`/`dangerous`; the evidence pass
    // finds `require_approval`/`dangerous` too. The merge is monotone, so the
    // schema answer — the one carrying the reason the operator has to act on —
    // stands rather than being swapped for an equal-rank evidence verdict.
    const v = evaluateToolCall('Bash', { command: 'sudo apt-get install -y curl', evil_payload: 'x' });
    expect(v.decision).toBe('require_approval');
    expect(v.severity).toBe('dangerous');
    expect(v.signals).toContain('invalid-tool-input');
  });

  it('a benign argv is never escalated by the pass', () => {
    for (const tool of ['spawn_process', 'PushNotification', 'runCommand'] as const) {
      expect(evaluateToolCall(tool, { command: 'npm', argv: ['test', '--silent'] })).toMatchObject({
        decision: 'allow', severity: 'benign',
      });
    }
  });

  it('ordinary dev work on the exec plane still costs nothing', () => {
    for (const command of ['ls -la src/', 'npm test', 'git status --short', 'node scripts/x.mjs']) {
      expect(evaluateToolCall('Bash', { command }).decision).toBe('allow');
    }
  });
});

describe('command evidence — a truncated walk is not a clean walk', () => {
  it('a wipe behind the leaf cap fails closed instead of reading clean', () => {
    const v = evaluateToolCall('runCommand', { argv: [...Array(16_384).fill('x'), ...WIPE_TOKENS] });
    expect(v.decision).toBe('block');
    expect(v.signals).toContain('command-evidence-unscannable');
  });

  it('the unscannable block is TERMINAL on every family — the tier every plane denies', () => {
    // `dangerous` would leave the Claude hook offering an `ask`: one tap and a
    // payload the guard explicitly could not read runs anyway. Catastrophic is
    // the only tier all three runtimes refuse without a door.
    for (const tool of ['PushNotification', 'share_file', 'spawn_process', 'send_message'] as const) {
      const v = evaluateToolCall(tool, { argv: [...Array(20_000).fill('x')] });
      expect(v).toMatchObject({ decision: 'block', severity: 'catastrophic' });
      expect(v.signals).toContain('command-evidence-unscannable');
    }
  });

  it('a wipe INSIDE the budget still beats the truncation card', () => {
    // Catastrophic dominance: the pass returns the wipe it actually read, not
    // the weaker "could not read it all" answer.
    const v = evaluateToolCall('runCommand', { argv: [...WIPE_TOKENS, ...Array(20_000).fill('x')] });
    expect(v).toMatchObject({ decision: 'block', severity: 'catastrophic' });
  });

  it('nesting past the depth cap fails closed on an annotate-family name', () => {
    const deep = [[[[[[[[[[WIPE_TOKENS]]]]]]]]]];
    const v = evaluateToolCall('PushNotification', { message: 'ok', argv: deep });
    expect(v.decision).toBe('block');
  });

  it('a long-but-readable argv is NOT carded — the cap is a real cap', () => {
    // 4k ordinary tokens are well inside every budget: this must stay an allow,
    // or the fail-closed rule becomes its own false-positive class.
    const v = evaluateToolCall('spawn_process', { command: 'npm', argv: Array(4_000).fill('--silent') });
    expect(v).toMatchObject({ decision: 'allow', severity: 'benign' });
  });

  it('a wipe mid-way through a very long single string still scans', () => {
    const mid = `${'x'.repeat(140_000)} ${WIPE} ${'y'.repeat(20_000)}`;
    expect(evaluateToolCall('share_file', { fileId: 'a', argv: mid })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });
});

describe('command evidence — the pass reaches every schema outcome', () => {
  it('VALID bag: scanned', () => {
    expect(evaluateToolCall('spawn_process', { command: BIN, argv: [RF, ROOT] }).severity)
      .toBe('catastrophic');
  });

  it('REJECTED bag: scanned', () => {
    // `evil_payload` is an unknown EXEC key, so the schema rejects the call.
    expect(evaluateToolCall('Bash', { command: BIN, argv: [RF, ROOT], evil_payload: 'x' }).severity)
      .toBe('catastrophic');
  });

  it('STRIPPED bag: scanned', () => {
    // `argv` is not an extractor key, so annotate throws it away.
    expect(evaluateToolCall('PushNotification', { message: 'ok', argv: WIPE_TOKENS }).severity)
      .toBe('catastrophic');
  });

  it('BOTH-MODES-INVALID bag: scanned', () => {
    // A bad-typed control field fails enforce AND annotate, so nothing
    // downstream reaches an extractor and the pass has to carry the surface.
    expect(evaluateToolCall('TaskOutput', { task_id: 't', timeout: 'x', command: WIPE }).severity)
      .toBe('catastrophic');
  });

  it('read-only and memory tools are still short-circuited, not newly gated', () => {
    for (const tool of ['Read', 'Grep', 'read_file'] as const) {
      expect(evaluateToolCall(tool, { file_path: '/tmp/a', input: WIPE })).toMatchObject({
        decision: 'allow', severity: 'benign',
      });
    }
    expect(evaluateToolCall('mcp__memory__remember', { content: WIPE })).toMatchObject({
      decision: 'allow', severity: 'benign',
    });
  });

  it('the reviewed native contracts keep their zero-card budget', () => {
    const live = {
      task: 'inspect tests', runtime: 'subagent', visible: true, worktree: true,
      outputSchema: { type: 'object', properties: { verdict: { type: 'string' } } },
    };
    expect(evaluateToolCall('sessions_spawn', live)).toMatchObject({
      decision: 'allow', severity: 'benign',
    });
    expect(evaluateToolCall('web.run', { search_query: [{ q: 'x' }] })).toMatchObject({
      decision: 'allow', severity: 'benign',
    });
  });
});
