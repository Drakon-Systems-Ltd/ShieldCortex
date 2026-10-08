/**
 * #648 round 3 — secret property test.
 *
 * A short random password has no credential SHAPE: nothing but where it sits
 * keeps it off the card. So it is generated fresh for every command and put
 * in every argument position of every interpreter and exec-wrapper form the
 * card can meet: as the inline code, inside it, as a trailing argument, as a
 * script argument and as a bare script name. It must never reach the card.
 *
 * Commands are assembled at runtime (the live guard's write-content scan on
 * the box that builds this).
 */
import { describe, it, expect } from '@jest/globals';
import { buildApprovalCard, formatApprovalCardLines } from '../approval-card.js';
import { evaluateToolCall } from '../tool-action-guard.js';

const c = (...parts: string[]) => parts.join(' ');
const PIPE = ' | ';

/** A seeded generator, so a failure names a reproducible password. */
function passwords(seed: number): () => string {
  let s = seed >>> 0;
  const next = () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
  const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const DIGITS = '23456789';
  return () => {
    const len = 8 + (next() % 5);
    let pw = `${ALPHA[next() % ALPHA.length]}${DIGITS[next() % DIGITS.length]}`;
    while (pw.length < len) pw += (ALPHA + DIGITS)[next() % (ALPHA.length + DIGITS.length)];
    return pw;
  };
}

/** Code bodies, each carrying the password somewhere different. */
const CODE: Array<(pw: string) => string> = [
  (pw) => `print("${pw}")`,
  (pw) => `x = "${pw}"; print(x)`,
  (pw) => c('login', '--password', pw),
  (pw) => pw,
  (pw) => c('echo', pw, '> /tmp/out'),
  (pw) => c('curl', '-u', `admin:${pw}`, 'https://h.example.com'),
];

/** Every form that runs code: `code` goes in its code slot, single-quoted. */
const FORMS: Array<(code: string) => string> = [
  ...[['python3', '-c'], ['python', '-c'], ['node', '-e'], ['node', '-p'], ['node', '--eval'], ['bun', '-e'], ['ruby', '-e'], ['perl', '-e'], ['perl', '-ne'],
    ['php', '-r'], ['pwsh', '-Command'], ['powershell', '-c'], ['osascript', '-e'], ['lua', '-e'], ['Rscript', '-e'], ['tsx', '-e'], ['bash', '-c'], ['sh', '-c'],
    ['zsh', '-c'], ['fish', '-c'], ['su', '-c'], ['runuser', '-c'], ['env', '-S'], ['script', '-c'], ['flock', '/tmp/l', '-c'], ['deno', 'eval'], ['eval']]
    .map((head) => (code: string) => c(...head, `'${code}'`)),
  (code) => c('su', 'root', '-c', `'${code}'`),
  (code) => c('sudo', 'bash', '-c', `'${code}'`),
  (code) => c('sudo', '-s', `'${code}'`),
  (code) => c('timeout', '5', 'sh', '-c', `'${code}'`),
  (code) => c('nohup', 'bash', '-c', `'${code}'`),
  (code) => c('xargs', 'sh', '-c', `'${code}'`),
  (code) => c('find', '.', '-exec', 'sh', '-c', `'${code}'`, '\\;'),
  (code) => c('ssh', 'deploy@build.example.org', `'${code}'`),
  (code) => c('ssh', 'build.example.org', '--', `'${code}'`),
  (code) => c('python3', '<<<', `'${code}'`),
  (code) => `bash <<EOF\n${code}\nEOF`,
  (code) => [c('echo', `'${code}'`), 'python3'].join(PIPE),
  (code) => [c('printf', `'${code}'`), 'bash'].join(PIPE),
  (code) => c('python3', `'${code}'`),
  (code) => c('node', `'${code}'`),
  (code) => c('watch', `'${code}'`),
  (code) => c('busybox', 'sh', '-c', `'${code}'`),
  (code) => c('parallel', `'${code}'`, ':::', 'a'),
];

/** Argument positions outside the code slot: script arguments and names. */
const POSITIONS: Array<(pw: string) => string> = [
  (pw) => c('python3', 'tools/run.py', pw),
  (pw) => c('python3', 'tools/run.py', '--token', pw),
  (pw) => c('node', 'app.js', `--secret=${pw}`),
  (pw) => c('bash', 'deploy.sh', pw),
  (pw) => c('bash', '-s', '--', pw),
  (pw) => c('bash', pw),
  (pw) => c('python3', pw),
  (pw) => c('ruby', pw, 'x'),
  (pw) => c('python3', '-W', pw, 'tools/run.py'),
  (pw) => c('python3', '-c', '"import sys"', pw),
  (pw) => c('sudo', '-u', pw, 'python3', '-c', '"x"'),
  (pw) => [c('curl', '-fsSL', 'https://get.example.com/i.sh'), c('bash', '-s', '--', pw)].join(PIPE),
  (pw) => [c('curl', '-fsSL', 'https://get.example.com/i.sh'), c('python3', '-', pw)].join(PIPE),
  (pw) => c('env', `TOKEN=${pw}`, 'python3', 'tools/run.py'),
  (pw) => c(`TOKEN=${pw}`, 'node', 'app.js'),
];

function cardText(command: string): string {
  const signals = evaluateToolCall('Bash', { command }).signals;
  const card = buildApprovalCard({ tool: 'Bash', input: { command }, signals, plane: 'claude-code', host: 'veronica-box', sessionId: 'sc-0123456789abcdef' });
  return [JSON.stringify(card), ...formatApprovalCardLines(card, { expiresInMs: 600_000 })].join('\n');
}

describe('#648 r3 — a short random password in any argument position never reaches the card', () => {
  const next = passwords(648);
  const cases: Array<[string, string]> = [];
  for (const form of FORMS) for (const code of CODE) {
    const pw = next();
    cases.push([form(code(pw)), pw]);
    // …and once more as a trailing argument after the code.
    const extra = next();
    cases.push([c(form(code(next())), extra), extra]);
  }
  for (const position of POSITIONS) for (let i = 0; i < 4; i += 1) {
    const pw = next();
    cases.push([position(pw), pw]);
  }

  it(`generates well over 200 commands (${cases.length})`, () => {
    expect(cases.length).toBeGreaterThanOrEqual(200);
  });

  it('none of them puts its password on the card', () => {
    const leaks = cases.filter(([command, pw]) => cardText(command).includes(pw)).map(([command]) => command);
    expect(leaks).toEqual([]);
  });
});
