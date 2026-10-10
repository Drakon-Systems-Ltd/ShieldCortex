import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * #691 — English prose containing "Look at" in written source raised
 * `modify-scheduler`.
 *
 * Field case (8 Oct 2026): a Write of an ordinary React file carrying
 * `href="/xray?tab=findings" cta="Look at` was flagged `write-content-dangerous`
 * + `modify-scheduler` on both planes. Two things let it through, and each is
 * pinned on its own below:
 *   1. the rule's `VAR=value` prefix took `href="…"` and `cta="Look` as shell
 *      assignments, which put `at` in command position;
 *   2. `at` fired on any following word, though at(1) needs an option or a
 *      timespec in that slot.
 *
 * Discipline: every allow case has a must-still-fire sibling on the same
 * surface (Bash, Write, Edit) with signal, severity and decision asserted.
 */

const TSX = '/workspace/dashboard/src/components/needs-you/NeedsYouView.tsx';
const nl = '\n';

const write = (file_path: string, content: string) =>
  evaluateToolCall('Write', { file_path, content });
const edit = (file_path: string, new_string: string) =>
  evaluateToolCall('Edit', { file_path, old_string: 'placeholder', new_string });
const bash = (command: string) => evaluateToolCall('Bash', { command });

const jsx = (attrs: string) => [
  'export function NeedsYouView() {',
  '  return (',
  '    <Row',
  `      ${attrs}`,
  '    />',
  '  );',
  '}',
  '',
].join(nl);

function expectCleanScan(v: ReturnType<typeof evaluateToolCall>): void {
  expect(v.signals).not.toContain('modify-scheduler');
  expect(v.signals).not.toContain('write-content-dangerous');
  expect(v.decision).toBe('allow');
  expect(v.severity).toBe('sensitive');
  expect(v.signals).toContain('write-content-scanned');
}

function expectScheduler(v: ReturnType<typeof evaluateToolCall>, writeSurface: boolean): void {
  expect(v.signals).toContain('modify-scheduler');
  if (writeSurface) expect(v.signals).toContain('write-content-dangerous');
  expect(v.decision).toBe('require_approval');
  expect(v.severity).toBe('dangerous');
}

describe('#691 — prose in written source is not a scheduler change', () => {
  it('Write: the field case (JSX attributes ending in "Look at") is allowed', () => {
    expectCleanScan(write(TSX, jsx('href="/xray?tab=findings" cta="Look at')));
  });

  it('Write: the full attribute `cta="Look at the findings"` is allowed', () => {
    expectCleanScan(write(TSX, jsx('href="/xray?tab=findings" cta="Look at the findings"')));
  });

  // Mechanism 1 alone: a digit after `at` IS a timespec start, so only the
  // assignment-prefix fix keeps this quiet.
  it('Write: an unclosed quoted attribute value is not a VAR=value prefix', () => {
    expectCleanScan(write(TSX, jsx('href="/xray?tab=findings" cta="Look at 3 findings"')));
  });

  // Mechanism 2 alone: no prefix involved, the line itself starts with `at`.
  it('Write: a JSX text line starting with "at" and no timespec is allowed', () => {
    expectCleanScan(write(TSX, [
      'export const Hint = () => (',
      '  <p>',
      '    Look',
      '    at the findings first',
      '  </p>',
      ');',
      '',
    ].join(nl)));
  });

  it('Write: a JS stack-trace line (`at Object.<anonymous>`) is allowed', () => {
    expectCleanScan(write('/workspace/src/fixtures/trace.js', [
      'export const TRACE = `Error: boom',
      '    at Object.<anonymous> (/app/x.js:1:1)`;',
      '',
    ].join(nl)));
  });

  it('Edit: the same JSX prose in new_string is allowed', () => {
    expectCleanScan(edit(TSX, '      href="/xray?tab=findings" cta="Look at the findings"' + nl));
  });

  it('Bash: a quoted multi-word assignment containing "at" does not signal modify-scheduler', () => {
    const v = bash('MSG="Look at the findings" true');
    expect(v.signals).not.toContain('modify-scheduler');
    expect(v.decision).toBe('allow');
  });
});

describe('#691 — real at(1) and crontab calls keep severity and decision', () => {
  const bashApprove: Array<[string, string]> = [
    ['piped job, relative time (the issue\'s own row)', 'echo cmd | at now + 1 minute'],
    ['HH:MM', 'at 22:00'],
    ['time word', 'at midnight -f /tmp/job.sh'],
    ['teatime piped', 'echo job | at teatime'],
    ['option before the timespec', 'at -f /tmp/job.sh 10:00'],
    ['mail option', 'at -m now'],
    ['-t form', 'at -t 202610101200'],
    ['day name', 'at monday < /tmp/job.sh'],
    ['month name', 'at 10am Jul 31 < /tmp/job.sh'],
    ['tomorrow', 'echo job | at tomorrow'],
    ['plus offset', 'at +5 minutes < /tmp/job.sh'],
    ['variable timespec', 'at "$WHEN" < /tmp/job.sh'],
    ['bare variable timespec', 'at $WHEN < /tmp/job.sh'],
    ['quoted timespec', "at 'now + 1 hour' < /tmp/job.sh"],
    ['heredoc input', "at now + 5 minutes <<'EOF'\n/usr/local/bin/job\nEOF"],
    ['after newline', 'echo job > /tmp/j\nat now + 1 minute < /tmp/j'],
    ['after a semicolon', 'ls; at midnight -f /tmp/job.sh'],
    ['nohup wrapper', 'nohup at 02:00 -f payload.sh'],
    ['timeout wrapper', 'timeout 60 at now + 1 hour'],
    ['sudo', 'sudo at now < /tmp/job.sh'],
    ['env assignment prefix', 'TZ=UTC at 09:00 < /tmp/job.sh'],
    ['closed quoted assignment prefix', 'LABEL="nightly" at now < /tmp/job.sh'],
    ['command substitution', 'echo $(at now < /tmp/job.sh)'],
    ['crontab -e', 'crontab -e'],
    ['crontab behind a closed quoted assignment', 'EDITOR="vi" crontab -e'],
    ['pipe into crontab -', 'echo "0 5 * * * /bin/job" | crontab -'],
  ];
  it.each(bashApprove)('Bash still requires approval: %s', (_l, command) => {
    expectScheduler(bash(command), false);
  });

  it('Write: a shell script that pipes a job into at(1) still requires approval', () => {
    expectScheduler(write('/workspace/scripts/schedule.sh', '#!/bin/bash' + nl + 'echo cmd | at now + 1 minute' + nl), true);
  });

  it('Write: at -f with a timespec in a .ts script body still requires approval', () => {
    expectScheduler(write('/workspace/scripts/schedule.ts', 'at -f /tmp/job.sh 02:00' + nl), true);
  });

  it('Write: a heredoc-fed at(1) in a .sh still requires approval', () => {
    expectScheduler(write('/workspace/scripts/later.sh', [
      '#!/bin/sh',
      "at now + 5 minutes <<'EOF'",
      '/usr/local/bin/job',
      'EOF',
      '',
    ].join(nl)), true);
  });

  it('Edit: a teatime job added to a .sh still requires approval', () => {
    expectScheduler(edit('/workspace/scripts/later.sh', 'at teatime < /tmp/job.txt' + nl), true);
  });

  const allow: Array<[string, string]> = [
    ['at -l stays read-only', 'at -l'],
    ['crontab -l stays read-only', 'crontab -l'],
    ['a variable named at (#135)', 'at=$(cat token.txt)'],
    ['gh api path containing "at"', 'gh api /repos/x/actions/runs'],
  ];
  it.each(allow)('Bash still allows: %s', (_l, command) => {
    const v = bash(command);
    expect(v.signals).not.toContain('modify-scheduler');
    expect(v.decision).toBe('allow');
  });
});

/**
 * Round 2 (GPT-6 Astra B1, Grok 1/2): the first fix whitelisted what may
 * follow `at`, and so dropped ordinary shell spellings the base row gated.
 * Every string here is an inert evaluator input; nothing runs at(1). Strings
 * are JS literals: `\\` is ONE backslash in the command, `\n` a newline, so
 * `at \\\nnow` is `at`, a backslash-newline continuation, then `now`.
 */
describe('#691 round 2 — shell spellings the base row gated still gate', () => {
  const bashApprove: Array<[string, string]> = [
    // Quoted options: the shell passes `-m` / `-f` to at(1).
    ['double-quoted option', 'echo job | at "-m" now'],
    ['single-quoted option', "echo job | at '-m' now"],
    ['quoted -f before the job file', "at '-f' /tmp/job.sh now"],
    // Redirects and heredocs before the timespec.
    ['input redirect before the timespec', 'at < /workspace/job.txt now'],
    ['no-space input redirect', 'at</workspace/job.txt now'],
    ['heredoc before the timespec', "at <<'EOF' now\n/usr/local/bin/job\nEOF"],
    ['no-space heredoc before the timespec', "at<<'EOF' now\n/usr/local/bin/job\nEOF"],
    // Escapes and backslash-newline continuations.
    ['escaped timespec', 'echo job | at \\now'],
    ['continuation before the timespec, piped', 'echo job | at \\\nnow'],
    ['continuation before the timespec, redirect', 'at \\\nnow < /tmp/job.sh'],
    ['continuation before an option', 'echo cmd | at \\\n-f /tmp/job.sh now'],
    ['continuation behind nohup', 'nohup at \\\nnow < /tmp/job.sh'],
    ['continuation behind an env assignment', 'TZ=UTC at \\\nnow < /tmp/job.sh'],
    // Backtick substitutions as the timespec, beside the `$()` sibling.
    ['backtick printf timespec', 'echo job | at `printf now`'],
    ['backtick date timespec', 'at `date +%H:%M` < /tmp/job.sh'],
    ['backtick date with options, piped', 'echo job | at `date -d tomorrow +%H:%M`'],
    ['double-quoted backtick timespec', 'at "`date +%H:%M`" < /tmp/job.sh'],
    ['$() timespec (sibling)', 'at "$(date +%H:%M)" < /tmp/job.sh'],
    // A word that carries an escape or quote is not plain prose.
    ['escape inside a day name', 'at f\\riday < /tmp/job.sh'],
    ['quote inside a day name', 'at f"ri"day < /tmp/job.sh'],
  ];
  it.each(bashApprove)('Bash still requires approval: %s', (_l, command) => {
    expectScheduler(bash(command), false);
  });

  const writeApprove: Array<[string, string]> = [
    ['quoted option', 'echo job | at "-m" now'],
    ['redirect before the timespec', 'at < /tmp/job.txt now'],
    ['continuation before the timespec', 'at \\\nnow < /tmp/job.sh'],
    ['backtick timespec', 'at `date +%H:%M` < /tmp/job.sh'],
  ];
  it.each(writeApprove)('Write .sh still requires approval: %s', (_l, line) => {
    expectScheduler(write('/workspace/scripts/schedule.sh', '#!/bin/bash' + nl + line + nl), true);
  });
  it.each(writeApprove)('Edit .sh still requires approval: %s', (_l, line) => {
    expectScheduler(edit('/workspace/scripts/schedule.sh', line + nl), true);
  });

  it.each(writeApprove)('Bash running a folded .sh still requires approval: %s', (_l, line) => {
    const v = evaluateToolCall('Bash', { command: 'bash /tmp/sched.sh' }, undefined, {
      resolveScriptSource: (p: string) => (p === '/tmp/sched.sh' ? '#!/bin/bash' + nl + line + nl : null),
    });
    expectScheduler(v, false);
  });

  it('Write: a JSX text line that is just "at" is allowed', () => {
    expectCleanScan(write(TSX, [
      'export const Hint = () => (',
      '  <p>',
      '    Look',
      '    at',
      '    the findings first',
      '  </p>',
      ');',
      '',
    ].join(nl)));
  });
});

/**
 * Round 3 (GPT-6 Astra B2): refusing a quoted value that reaches a space also
 * refused a DOUBLE-quoted value whose backtick substitution runs a scheduler.
 * Inside double quotes a backtick still executes, so these gate as at base.
 * Single quotes are literal; the single-quoted siblings are the inert control.
 * Inert evaluator inputs only; nothing runs at(1) or crontab.
 */
describe('#691 round 3 — a scheduler inside a double-quoted assignment substitution still gates', () => {
  const executing: Array<[string, string]> = [
    ['at inside a double-quoted backtick assignment', 'X="` at now < /workspace/job.txt`" true'],
    ['crontab inside a double-quoted backtick assignment', 'X="` crontab /workspace/cron.txt`" true'],
  ];
  it.each(executing)('Bash still requires approval: %s', (_l, command) => {
    expectScheduler(bash(command), false);
  });
  it.each(executing)('Write .sh still requires approval: %s', (_l, line) => {
    expectScheduler(write('/workspace/scripts/schedule.sh', '#!/bin/bash' + nl + line + nl), true);
  });
  it.each(executing)('Edit .sh still requires approval: %s', (_l, line) => {
    expectScheduler(edit('/workspace/scripts/schedule.sh', line + nl), true);
  });
  it.each(executing)('Bash running a folded .sh still requires approval: %s', (_l, line) => {
    const v = evaluateToolCall('Bash', { command: 'bash /tmp/sched.sh' }, undefined, {
      resolveScriptSource: (p: string) => (p === '/tmp/sched.sh' ? '#!/bin/bash' + nl + line + nl : null),
    });
    expectScheduler(v, false);
  });

  const literal: Array<[string, string]> = [
    ['single-quoted backtick at is literal text', "X='` at now < /workspace/job.txt`' true"],
    ['single-quoted backtick crontab is literal text', "X='` crontab /workspace/cron.txt`' true"],
  ];
  it.each(literal)('Bash does not signal modify-scheduler: %s', (_l, command) => {
    expect(bash(command).signals).not.toContain('modify-scheduler');
  });
});
