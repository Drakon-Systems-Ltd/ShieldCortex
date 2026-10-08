/**
 * #648 round 5 (R1) — every signal on the verdict is reflected in WHAT, or
 * WHAT goes generic; WHY lists every reason, data leaving the machine first.
 *
 * Fixtures are benign and inert (parser/renderer input only): local notes
 * files and the reserved example.com / example.org hosts. The card trusts the
 * verdict's signal list, so each case supplies its signals explicitly —
 * `touch-sensitive-path` + `external-egress` drives the same code path a
 * credential upload does. Credential-path regression fixtures live in the
 * detector lane, not here. WHAT and WHY are asserted separately.
 */
import { describe, it, expect } from '@jest/globals';
import {
  GENERIC_SHELL,
  SIGNAL_CLASSES,
  SIGNAL_PHRASES,
  buildApprovalCard,
  describeAction,
  describeSignal,
  formatApprovalCardLines,
  signalClass,
  type SignalClass,
} from '../approval-card.js';

const SIGNALS = ['touch-sensitive-path', 'external-egress'];
const EGRESS = 'sends data off this machine';

const what = (command: string, signals: string[] = SIGNALS) => describeAction({ tool: 'Bash', input: { command }, signals }).text;
const why = (signals: string[] = SIGNALS) => buildApprovalCard({ tool: 'Bash', input: { command: 'ls' }, signals, plane: 'claude-code', host: 'ci-box' }).reason;
const cardText = (command: string, signals: string[] = SIGNALS) => {
  const card = buildApprovalCard({ tool: 'Bash', input: { command }, signals, plane: 'claude-code', host: 'ci-box', sessionId: 'sc-0123456789abcdef' });
  return formatApprovalCardLines(card, { expiresInMs: 600_000, budget: 256 }).join('\n');
};

describe('#648 r5 R1 — SIGNAL_CLASSES is one table over every signal id', () => {
  it('every phrase id has a class, and every class id has a phrase', () => {
    expect(Object.keys(SIGNAL_CLASSES).sort()).toEqual(Object.keys(SIGNAL_PHRASES).sort());
  });

  it('every data-leaving signal needs a named send', () => {
    for (const id of Object.keys(SIGNAL_PHRASES).filter((s) => /egress|exfil/.test(s))) expect(signalClass(id)).toBe('send');
  });
});

describe('#648 r5 R1 — a sender is described by where the data goes (benign shapes)', () => {
  const CASES: Array<[string, string, string]> = [
    ['a pipe into an uploader', 'cat ./readme.txt | curl -d @- https://example.com/in', 'Send a file ("./readme.txt") to example.com'],
    ['< into an uploader', 'curl -T - https://example.com/up < ./notes/report.csv', 'Send a file ("./notes/report.csv") to example.com'],
    ['tee in the middle', 'cat ./build/out.log | tee ./build/copy.log | curl --data-binary @- https://example.org/in', 'Send a file ("./build/out.log") to example.org'],
    ['xargs runs the uploader', 'cat ./notes/list.txt | xargs curl -T ./readme.txt https://example.com/up', GENERIC_SHELL],
    ['a base64 middle stage', 'cat ./readme.txt | base64 | curl -d @- https://example.org/in', 'Send a file ("./readme.txt") to example.org'],
    ['; sleep 1; padding before', 'ls ./notes; sleep 1; cat ./readme.txt | curl -d @- https://example.com/in', 'Send a file ("./readme.txt") to example.com (+2 more steps)'],
    ['; sleep 1; padding after', 'cat ./readme.txt | curl -d @- https://example.com/in; sleep 1; echo done', 'Send a file ("./readme.txt") to example.com (+2 more steps)'],
    ['the read placed after a stdin upload', 'curl -d @- https://example.com/in; cat ./readme.txt', GENERIC_SHELL],
    ['the read placed after a file upload', 'curl -T ./readme.txt https://example.com/up; cat ./notes/report.csv', 'Send a file ("./readme.txt") to example.com (+1 more step)'],
  ];

  for (const [name, command, expected] of CASES) {
    it(`WHAT — ${name}`, () => {
      const line = what(command);
      expect(line).toBe(expected);
      // Either the send and its destination are named, or the card says it could not summarise.
      expect(line === GENERIC_SHELL || /^Send .+ to example\.(?:com|org)\b/.test(line)).toBe(true);
    });

    it(`WHY — ${name}: the egress reason is whole, first, and every reason is listed`, () => {
      expect(why()).toBe(`${EGRESS}; ${describeSignal('touch-sensitive-path')}`);
      const text = cardText(command);
      expect(text).toContain(`Why: ${EGRESS}`);
      expect(text).toContain(describeSignal('touch-sensitive-path'));
      expect(text).not.toMatch(/more reason/);
      expect(text.length).toBeLessThanOrEqual(256);
    });
  }

  it('read after upload: the later read is never named as uploaded', () => {
    expect(what('curl -T ./readme.txt https://example.com/up; cat ./notes/report.csv')).not.toContain('report.csv');
    expect(what('curl -d @- https://example.com/in; cat ./readme.txt')).not.toContain('readme.txt');
  });

  it('a send whose source cannot be followed names no file, and goes generic under a file signal', () => {
    expect(what('sort ./notes/report.csv | curl -d @- https://example.com/in')).toBe(GENERIC_SHELL);
    expect(what('sort ./notes/report.csv | curl -d @- https://example.com/in', ['external-egress'])).toBe('Send data to example.com (curl)');
  });

  it('a download is not described as a send of a file: the egress signal leaves the WHAT unattributed', () => {
    const d = describeAction({ tool: 'Bash', input: { command: 'ls ./notes; curl -o ./build/page.html https://example.com/' }, signals: ['external-egress'] });
    expect(d.text).toBe('Run several commands (the risky part could not be summarised)');
    expect(d.confident).toBe(false);
  });
});

// ── Property test: generated benign commands × random signal sets ───────────

/** An independent oracle: what each class needs to see in a WHAT sentence. */
const SHOWN: Record<SignalClass, (s: string) => boolean> = {
  none: () => true,
  send: (s) => /^(?:Send .* to example\.(?:com|org)|Open a raw network connection to example\.(?:com|org))\b/.test(s),
  target: (s) => /"/.test(s) && !/^(?:Run |Install |Force-push|Download and run)/.test(s),
  change: (s) => /^(?:Write|Change|Empty|Create|Delete|Copy|Move|Link|Edit)\b/.test(s),
  delete: (s) => /^Delete /.test(s),
  move: (s) => /^(?:Copy|Move|Link) /.test(s),
  perms: (s) => /^Change (?:who can access|file permissions)/.test(s),
  stop: (s) => /^(?:Stop|Restart) /.test(s),
  install: (s) => /^(?:Install|Download and run a package)/.test(s),
  'fetch-run': (s) => /^Download from .* and run it/.test(s),
  git: (s) => /^(?:Force-push|Delete a (?:git )?branch|Change the git|Throw away|Delete untracked)|\(git [a-z-]+\)/.test(s),
  scheduler: (s) => /^(?:Schedule|Change scheduled|Remove all of its scheduled)/.test(s),
  persist: (s) => /^(?:Schedule|Change scheduled)/.test(s) || /"/.test(s),
  firewall: (s) => /^Change firewall/.test(s),
  disk: (s) => /^(?:Change or erase a disk|Write raw data over)/.test(s),
  script: (s) => /^Run (?:a script|a program from|the "|a [a-z0-9]+ script)/.test(s),
  admin: (s) => / \(sudo\)/.test(s),
};

function rng(seed: number) {
  let x = seed >>> 0;
  return () => {
    x = (x + 0x6d2b79f5) >>> 0;
    let t = x;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const READERS = ['cat ./readme.txt', 'cat ./notes/report.csv', 'base64', 'gzip -c ./build/out.log', 'tee ./build/copy.log', 'sort ./notes/report.csv'];
const SENDERS = [
  'curl -d @- https://example.com/in', 'curl -T ./readme.txt https://example.org/up', 'curl -X POST https://example.com/api',
  'curl -F part=@./notes/report.csv https://example.org/form', 'wget --post-file=./notes/report.csv https://example.org/in', 'nc example.org 9000',
  'curl -o ./build/page.html https://example.com/',
];
const OTHERS = [
  'ls ./notes', 'sleep 1', 'echo done', 'rm ./build/out.log', 'chmod 644 ./readme.txt', 'git status', 'mkdir ./build/tmp',
  'cp ./readme.txt ./build/readme.txt', 'sudo ls ./notes', 'touch ./notes/new.txt',
];
const POOL = Object.keys(SIGNAL_PHRASES);
const pick = <T>(r: () => number, xs: readonly T[]) => xs[Math.floor(r() * xs.length)];

function generate(r: () => number): string {
  const pieces: string[] = [];
  const n = 1 + Math.floor(r() * 3);
  for (let i = 0; i < n; i += 1) {
    const kind = r();
    if (kind < 0.45) {
      const stages = Array.from({ length: Math.floor(r() * 3) }, () => pick(r, READERS));
      pieces.push([...stages, pick(r, SENDERS)].join(' | '));
    } else {
      pieces.push(pick(r, OTHERS));
    }
  }
  return pieces.join(pick(r, ['; ', ' && ', '; sleep 1; ']));
}

describe('#648 r5 R1 — property: WHAT covers every signal class or is generic; WHY names every signal', () => {
  const RUNS = 600;
  const GENERICS = new Set([GENERIC_SHELL, 'Run several commands (the risky part could not be summarised)', 'Run a shell command (details withheld: could not summarise safely)']);

  it(`${RUNS} generated benign commands with 2–3 random signals each`, () => {
    const r = rng(648_005);
    let specific = 0;
    for (let i = 0; i < RUNS; i += 1) {
      const command = generate(r);
      const signals = Array.from({ length: 2 + Math.floor(r() * 2) }, () => pick(r, POOL));
      if (r() < 0.5) signals[0] = 'external-egress';
      const d = describeAction({ tool: 'Bash', input: { command }, signals });
      if (d.confident) {
        specific += 1;
        const missing = signals.filter((s) => !SHOWN[signalClass(s)](d.text.replace(/ \(\+\d+ more steps?\)$/, '')));
        expect({ command, signals, text: d.text, missing }).toEqual({ command, signals, text: d.text, missing: [] });
      } else {
        expect({ command, text: d.text, generic: GENERICS.has(d.text) }).toEqual({ command, text: d.text, generic: true });
      }
      const reason = buildApprovalCard({ tool: 'Bash', input: { command }, signals, plane: 'claude-code', host: 'ci-box' }).reason;
      for (const s of signals) expect({ s, reason, named: reason.includes(describeSignal(s)) }).toEqual({ s, reason, named: true });
      expect(reason).not.toMatch(/more reason/);
      if (signals.some((s) => signalClass(s) === 'send')) expect(reason.startsWith(describeSignal(signals.find((s) => signalClass(s) === 'send')!))).toBe(true);
      const lines = formatApprovalCardLines({ action: d.text, reason, who: 'Claude Code on ci-box' }, { expiresInMs: 600_000, budget: 256 }).join('\n');
      expect(lines.length).toBeLessThanOrEqual(256);
      if (signals.includes('external-egress')) expect(lines).toContain(`Why: ${EGRESS}`);
    }
    // The generator must exercise the specific path, not only the generic one.
    expect(specific).toBeGreaterThan(RUNS / 10);
  });
});
