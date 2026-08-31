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
const DASH_C = ['-', 'c'].join('');
const FORK_BOMB = [':()', '{', ' :|:& ', '};', ':'].join('');
const SHELL_OUT = ['os', '.', 'system'].join('');
const SEPARATOR = String.fromCharCode(59);
const PIPE = String.fromCharCode(124);
const BACKGROUND = String.fromCharCode(38);
const COMMAND_SUBSTITUTION = [String.fromCharCode(36), String.fromCharCode(40)].join('');
const CLOSE_PAREN = String.fromCharCode(41);
const REDIRECT = String.fromCharCode(62);
const BLOCK_DEVICE = ['/dev', 'sda'].join('/');
const GLOB_METACHAR_LITERALS = [
  String.fromCharCode(42),
  String.fromCharCode(63),
  ['[', 'a-z', ']'].join(''),
  ['{', 'one,two', '}'].join(''),
];

function singleQuotedInline(command: string, args: string[]): string {
  const quoted = args.map(arg => `'${arg.split("'").join("'\\''")}'`);
  return [command, ...quoted].join(' ');
}

/** Ordinary, entirely benign documents that nest past the walk's depth cap. */
const DEEP_JSON_SCHEMA = { type: 'object', properties: { a: { type: 'object', properties: { b: { type: 'object', properties: { c: { type: 'object', properties: { d: { type: 'object', properties: { e: { type: 'object', properties: { f: { type: 'object', properties: { g: { type: 'string' } } } } } } } } } } } } } } };
const DEEP_K8S_MANIFEST = { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'web' }, spec: { template: { spec: { containers: [{ name: 'web', image: 'nginx:1.27', livenessProbe: { httpGet: { path: '/healthz', port: 8080, httpHeaders: [{ name: 'X-Probe', value: 'kubelet' }] } } }] } } } };

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

  it('an INTERPRETER argument is a program, not data', () => {
    // The data-argument reading below must not reach a shell: `sh -c <prog>`
    // executes its argument, and a shell is not a data command, so the quoted
    // argument stays in command position exactly as it does inline.
    for (const bag of [
      { command: 'bash', args: [DASH_C, WIPE] },
      { command: 'sh', argv: [DASH_C, WIPE] },
      { command: 'sh', args: [DASH_C, FORK_BOMB] },
      { command: 'python3', args: [DASH_C, `import os; ${SHELL_OUT}('${WIPE}')`] },
      { command: 'node', args: [['-', 'e'].join(''), `require('child_process').execSync('${WIPE}')`] },
      { command: 'python3', args: [['-', 'm'].join(''), WIPE] },
    ]) {
      expect(evaluateToolCall('spawn_process', bag)).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it('a non-first-wins command alias is scanned, not shadowed', () => {
    // `extractCommand` is first-wins, so `script` used to be invisible whenever
    // `command` was present and benign.
    expect(evaluateToolCall('Bash', { command: 'ls', script: WIPE })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });
});

/**
 * The other direction of the same rule, and the one that made this pass an
 * uninstall risk on its own: a command ALIAS is a statement, but an argument
 * VECTOR is not. Execute-classifying each argv element standalone read printed,
 * formatted and searched-for text as a second command, and answered a terminal
 * DENY — no card, no retry — to calls that run nothing at all.
 *
 * The bar is PARITY with the identical inline spelling, which the `Bash` row in
 * each case pins: whatever the guard says about `echo '<wipe>'` typed into a
 * shell, it must say about `spawn('echo', ['<wipe>'])`.
 */
describe('command evidence — a data argument is not a second command', () => {
  const DATA_ARG_CALLS: Array<[string, Record<string, unknown>, string]> = [
    ['echo through args', { command: 'echo', args: [WIPE] }, `echo '${WIPE}'`],
    ['printf through args', { command: 'printf', args: ['%s', WIPE] }, `printf %s '${WIPE}'`],
    ['grep through argv', { command: 'grep', argv: [WIPE, 'incident.log'] }, `grep '${WIPE}' incident.log`],
    [
      'separator plus genuine delete tokens',
      { command: 'echo', args: [SEPARATOR, ...WIPE_TOKENS] },
      singleQuotedInline('echo', [SEPARATOR, ...WIPE_TOKENS]),
    ],
    [
      'pipe plus genuine delete tokens',
      { command: 'echo', args: [PIPE, ...WIPE_TOKENS] },
      singleQuotedInline('echo', [PIPE, ...WIPE_TOKENS]),
    ],
    [
      'background operator plus genuine delete tokens',
      { command: 'echo', args: [BACKGROUND, ...WIPE_TOKENS] },
      singleQuotedInline('echo', [BACKGROUND, ...WIPE_TOKENS]),
    ],
    [
      'command-substitution fragments',
      { command: 'echo', args: [COMMAND_SUBSTITUTION, ...WIPE_TOKENS, CLOSE_PAREN] },
      singleQuotedInline('echo', [COMMAND_SUBSTITUTION, ...WIPE_TOKENS, CLOSE_PAREN]),
    ],
    [
      'redirect to a block-device-shaped target',
      { command: 'echo', args: [REDIRECT, BLOCK_DEVICE] },
      singleQuotedInline('echo', [REDIRECT, BLOCK_DEVICE]),
    ],
    [
      'glob and metacharacter literals',
      { command: 'echo', args: GLOB_METACHAR_LITERALS },
      singleQuotedInline('echo', GLOB_METACHAR_LITERALS),
    ],
  ];

  it.each(DATA_ARG_CALLS)('%s: allowed', (_label, bag) => {
    expect(evaluateToolCall('spawn_process', bag)).toMatchObject({
      decision: 'allow', severity: 'benign',
    });
  });

  it.each(DATA_ARG_CALLS)('%s: decides exactly as the inline spelling does', (_label, bag, inline) => {
    const vector = evaluateToolCall('spawn_process', bag);
    const spelled = evaluateToolCall('Bash', { command: inline });
    expect(vector.decision).toBe(spelled.decision);
    expect(vector.severity).toBe(spelled.severity);
  });

  it('data-vector relief is limited to reviewed native exec contracts', () => {
    const bag = { command: 'echo', args: [SEPARATOR, ...WIPE_TOKENS] };
    for (const tool of ['PushNotification', 'mcp__thirdparty__spawn_process'] as const) {
      expect(evaluateToolCall(tool, bag)).toMatchObject({
        decision: 'block', severity: 'catastrophic',
      });
    }
  });

  it('a commit message quoting the command it removes is prose', () => {
    // The shape that hard-denied honest documentation work: the message is one
    // argument, and `git commit` is a data command.
    expect(evaluateToolCall('spawn_process', {
      command: 'git',
      argv: ['commit', '-m', `docs: stop recommending ${WIPE}`],
    }).decision).toBe('allow');
  });

  it('the relief is for DATA verbs only — an unknown verb still gates', () => {
    // `cat` is not a data command, so its quoted argument stays executed. Same
    // answer as `cat '<wipe>'` inline: the seam is the verb, not the vector.
    const vector = evaluateToolCall('spawn_process', { command: 'cat', args: [WIPE] });
    const spelled = evaluateToolCall('Bash', { command: `cat '${WIPE}'` });
    expect(vector).toMatchObject({ decision: 'block', severity: 'catastrophic' });
    expect(vector.decision).toBe(spelled.decision);
  });

  it('a shell-safe vector keeps its command reading', () => {
    // Shell-safe elements are left bare. A plain flag vector is still the plain
    // command line the host runs, so the wipe still spans the element seam and
    // is still terminal.
    expect(evaluateToolCall('spawn_process', { command: BIN, argv: [RF, ROOT] })).toMatchObject({
      decision: 'block', severity: 'catastrophic',
    });
  });

  it('a printed fork bomb is printed; a shelled one runs', () => {
    expect(evaluateToolCall('spawn_process', { command: 'echo', args: [FORK_BOMB] }).decision)
      .toBe('allow');
    expect(evaluateToolCall('spawn_process', { command: 'sh', args: [DASH_C, FORK_BOMB] }))
      .toMatchObject({ decision: 'block', severity: 'catastrophic' });
  });

  it('a STRING in an argv slot is still read raw — no invented boundaries', () => {
    // `args: '<wipe>'` is a spelled fragment, not a vector; quoting it would
    // manufacture a seam the caller never wrote.
    expect(evaluateToolCall('spawn_process', { command: 'ls', args: WIPE })).toMatchObject({
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
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('command-evidence-unscannable');
  });

  it('the unscannable answer is the SCHEMA-INVALID door on every family', () => {
    // Not the terminal tier. The trigger is SHAPE — a bag too deep or too big
    // to finish reading — and shape alone is not a wipe, so a benign structure
    // must get a card and a retry, not a wall. What makes it safe is the reason
    // code, not the tier: every plane derives non-widenability from
    // `invalid-tool-input` (see `isSchemaInvalid` / `unscannedBlock` in
    // `plugins/openclaw/interceptor.ts` and `scripts/pre-tool-hook.mjs`), so
    // `autoApprove`, advisory mode and broker pre-clear stay inert either way.
    for (const tool of ['PushNotification', 'share_file', 'spawn_process', 'send_message'] as const) {
      const v = evaluateToolCall(tool, { argv: [...Array(20_000).fill('x')] });
      expect(v).toMatchObject({
        decision: 'require_approval', severity: 'dangerous', action: 'invalid_tool_input',
      });
      expect(v.signals).toContain('command-evidence-unscannable');
      expect(v.signals).toContain('invalid-tool-input');
    }
  });

  it('a BENIGN over-budget shape gets a door, not a terminal block', () => {
    // The uninstall-class shape: arbitrary JSON Schema and Kubernetes manifests
    // are ordinary payloads, deeper than the walk's depth cap, and containing no
    // command at all. `sessions_spawn.outputSchema` is declared inert in this
    // very module BECAUSE arbitrary JSON Schema is too deep to validate; the
    // same document under `args`/`input` on any other tool must not be terminal.
    for (const tool of ['Workflow', 'mcp__k8s__apply', 'Task'] as const) {
      for (const bag of [
        { args: DEEP_JSON_SCHEMA },
        { script: 'build', args: DEEP_JSON_SCHEMA },
        { input: DEEP_JSON_SCHEMA },
        { args: DEEP_K8S_MANIFEST },
        { input: DEEP_K8S_MANIFEST },
      ]) {
        const v = evaluateToolCall(tool, bag);
        // The walk really did run out — these rows exercise the door, not luck.
        expect(v.signals).toContain('command-evidence-unscannable');
        expect(v).toMatchObject({ decision: 'require_approval', severity: 'dangerous' });
        // …and the door is still non-widenable: every plane keys off this code.
        expect(v.signals).toContain('invalid-tool-input');
      }
    }
  });

  it('a structured payload INSIDE the budget is not touched at all', () => {
    // The cap has to stay a cap: an ordinary manifest costs nothing.
    const podSpec = { apiVersion: 'v1', kind: 'Pod', metadata: { name: 'web' }, spec: { containers: [{ name: 'web', image: 'nginx:1.27' }] } };
    for (const bag of [{ args: podSpec }, { script: 'apply', args: podSpec }]) {
      expect(evaluateToolCall('Workflow', bag)).toMatchObject({
        decision: 'allow', severity: 'benign',
      });
    }
  });

  it('an over-budget MALICIOUS bag is still gated, and still non-widenable', () => {
    // The door is a door, not an allow: a wipe the walk DID reach keeps its own
    // verdict, and the unscannable reason codes ride along so no plane widens it.
    const v = evaluateToolCall('runCommand', {
      argv: [...SUDO_STOP, ...Array(20_000).fill('x')],
    });
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('privilege-escalation');
    expect(v.signals).toContain('invalid-tool-input');
    expect(v.signals).toContain('command-evidence-unscannable');
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
    expect(v.decision).not.toBe('allow');
    expect(v.signals).toContain('command-evidence-unscannable');
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
