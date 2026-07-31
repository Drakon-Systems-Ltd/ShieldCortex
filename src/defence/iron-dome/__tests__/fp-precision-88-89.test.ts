import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * FP-precision regression pack — issues #88 and #89.
 *
 * Live audit-log analysis on production boxes (2026-07-14) showed the Action
 * Guard over-gating read-only / benign operations: read-only `npm … -g`
 * queries flagged as global installs, a greedy `[^|\n]*` bridge letting the
 * catastrophic device patterns collide across `;`-separated statements, and
 * read-only `crontab -l` (and the bare word in an echo) flagged as scheduler
 * mutation.
 *
 * Discipline: every narrowed rule keeps a must-STILL-FIRE sibling so a
 * precision fix can never quietly become a hole. Allow-cases assert the FP is
 * gone; block/approve-cases assert true-positive detection is intact.
 */

const decision = (args: Record<string, unknown>, tool = 'Bash') =>
  evaluateToolCall(tool, args).decision;
const verdict = (args: Record<string, unknown>, tool = 'Bash') =>
  evaluateToolCall(tool, args);

describe('#88 — install-package-global must not fire on read-only `npm … -g`', () => {
  const allow: Array<[string, string]> = [
    ['npm ls -g', 'npm ls -g'],
    ['npm ls -g --depth=0', 'npm ls -g --depth=0'],
    ['npm root -g', 'npm root -g'],
    ['npm list --global', 'npm list --global'],
    ['npm outdated -g', 'npm outdated -g'],
    ['npm view (no flag)', 'npm view shieldcortex version'],
    // the actual #88 compound: a read-only verification batch containing `npm ls -g`
    ['verify compound', 'echo "=== npm core ===" && npm view shieldcortex version && npm ls -g shieldcortex'],
  ];
  it.each(allow)('allows: %s', (_l, command) => {
    expect(decision({ command })).toBe('allow');
  });

  const approve: Array<[string, string]> = [
    ['npm install -g', 'npm install -g typescript'],
    ['npm i -g', 'npm i -g typescript'],
    ['npm -g install (flag first)', 'npm -g install left-pad'],
    ['npm install --global', 'npm install --global @vue/cli'],
    ['yarn global add', 'yarn global add prettier'],
    ['pnpm add -g', 'pnpm add -g eslint'],
  ];
  it.each(approve)('still requires approval: %s', (_l, command) => {
    const v = verdict({ command });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('install-package-global');
  });
});

describe('#89 — catastrophic device patterns must not bridge across statements', () => {
  // Benign commands that merely contain a wipe/shred word AND a /dev/ path in
  // SEPARATE statements — the greedy [^|\n]* bridge used to collide them.
  const allow: Array<[string, string]> = [
    ['wipe in PATH, /dev/null in echo', 'export PATH="/opt/wipe/bin:$PATH"; echo "logs at /dev/null"'],
    ['WIPE var then ls /dev/null', 'WIPE_TMP=/tmp/wipe && ls -la /dev/null'],
  ];
  it.each(allow)('allows: %s', (_l, command) => {
    expect(decision({ command })).toBe('allow');
  });

  // Issue #4475.7b (post-#89) intentionally gates ANY same-statement
  // `dd … of=<target>` to require_approval, not just a raw /dev/ target — so
  // this case is no longer a bare allow. What it still proves, unchanged, is
  // the #89 bridge fix itself: the /dev/sdX mention is in a SEPARATE statement
  // after `;`, so it must never escalate this to CATASTROPHIC.
  it('a same-statement dd of=<file> requires approval (#4475.7b), but the SEPARATE-statement /dev/ mention does not escalate it to catastrophic (#89 bridge fix holds)', () => {
    const v = verdict({ command: 'dd if=in.img of=out.img status=progress; echo "restore with of=/dev/sdX"' });
    expect(v.decision).toBe('require_approval');
    expect(v.severity).not.toBe('catastrophic');
    expect(v.signals).toContain('dd-overwrite');
  });

  // The word "shred" in a grep pattern still trips the DANGEROUS file-delete rule
  // (`\bshred\b`) — a SEPARATE use/mention over-match tracked as a follow-up, not
  // this patch's scope. What matters here: the CATASTROPHIC shred-device bridge no
  // longer hard-BLOCKS a benign command whose /dev/ path is in another statement.
  it('does not catastrophically block a grep for "shred" beside a /dev note', () => {
    const v = verdict({ command: 'grep -rn "shred" src/; echo "handles /dev/sda safely"' });
    expect(v.decision).not.toBe('block');
    expect(v.severity).not.toBe('catastrophic');
  });

  // True positives: verb and device in the SAME statement — still catastrophic.
  const block: Array<[string, string]> = [
    ['shred a device', 'shred -vfz -n 3 /dev/sda'],
    ['wipe a device', 'wipe /dev/nvme0n1'],
    ['shred single', 'shred /dev/sdb1'],
    ['dd to disk', 'dd if=/dev/zero of=/dev/sda bs=1M'],
    ['dd iso to disk', 'dd if=ubuntu.iso of=/dev/sdb'],
  ];
  it.each(block)('still blocks: %s', (_l, command) => {
    const v = verdict({ command });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });
});

describe('#89 — modify-scheduler must not fire on read-only crontab -l', () => {
  const allow: Array<[string, string]> = [
    ['crontab -l', 'crontab -l'],
    ['crontab -l piped', 'crontab -l | grep backup'],
    ['crontab word in echo', 'systemctl --user list-timers 2>/dev/null || echo "checking host crontab instead"'],
    ['systemctl list-timers', 'systemctl --user list-timers'],
  ];
  it.each(allow)('allows: %s', (_l, command) => {
    expect(decision({ command })).toBe('allow');
  });

  const approve: Array<[string, string]> = [
    ['crontab -e', 'crontab -e'],
    ['crontab -r', 'crontab -r'],
    ['crontab install file', 'crontab /tmp/my.cron'],
    ['pipe into crontab -', 'echo "0 5 * * * /bin/job" | crontab -'],
    ['at now', 'echo job | at now + 1 minute'],
  ];
  it.each(approve)('still requires approval: %s', (_l, command) => {
    const v = verdict({ command });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('modify-scheduler');
  });
});

describe('#89 (follow-up) — modify-scheduler must not fire on a variable named `at`', () => {
  // Live FP on the Jarvis box, 2026-07-29: a read-only Xero P&L pull was
  // blocked because the heredoc body assigned `at = <token>` at the start of a
  // line. The command-position anchor treats a newline as a command boundary,
  // so `\nat` matched the scheduler verb — but `at` immediately followed by
  // `=` is an assignment in every shell and in the embedded-script bodies the
  // guard also scans. The real `at` command is `at [options] TIME`; its
  // grammar has no `=` in that position, so excluding it costs no detection.
  const allow: Array<[string, string]> = [
    ['bare assignment', 'at=$(cat token.txt)'],
    ['assignment after newline', "tok=load('creds.json')\nat=tok.get('access_token')"],
    ['spaced assignment in a heredoc body', "python3 - <<'EOF'\nat = tk.get('access_token')\nEOF"],
    ['assignment then use', 'at=abc; curl -H "Authorization: Bearer $at" https://api.example.com/v1/ping'],
  ];
  it.each(allow)('allows: %s', (_l, command) => {
    expect(decision({ command })).toBe('allow');
  });

  // Must-STILL-FIRE siblings: the assignment carve-out must not rescue the verb.
  const approve: Array<[string, string]> = [
    ['at after newline', 'echo job > /tmp/j\nat now + 1 minute < /tmp/j'],
    ['at with time argument', 'at 23:30 -f /tmp/job.sh'],
    ['at after a semicolon', 'ls; at midnight -f /tmp/job.sh'],
  ];
  it.each(approve)('still requires approval: %s', (_l, command) => {
    const v = verdict({ command });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('modify-scheduler');
  });
});

describe('#90 — install-package-global must gate npm install-verb abbreviations', () => {
  // Review follow-up on #88/#89: the narrowed regex only rescued the exact `i`
  // shorthand, so npm's own alias resolver (which accepts the whole
  // i/in/ins/inst/insta/instal/install/isnt/isntall family as `install`) let
  // every abbreviation OTHER than `i` bypass the gate entirely.
  const approve: Array<[string, string]> = [
    ['npm inst -g', 'npm inst -g evil'],
    ['npm in -g', 'npm in -g evil'],
    ['npm isntall -g', 'npm isntall -g evil'],
    ['npm ins -g', 'npm ins -g evil'],
    ['npm insta -g', 'npm insta -g evil'],
    ['npm instal -g', 'npm instal -g evil'],
    ['npm isnt -g', 'npm isnt -g evil'],
    // must-still-fire siblings — the pre-existing denies this patch must not weaken.
    ['npm i -g', 'npm i -g evil'],
    ['npm install -g', 'npm install -g evil'],
    ['sudo npm install -g', 'sudo npm install -g evil'],
    ['npm -g install', 'npm -g install evil'],
    ['pnpm add -g', 'pnpm add -g evil'],
    ['bun add -g', 'bun add -g evil'],
    ['yarn global add', 'yarn global add evil'],
  ];
  it.each(approve)('still requires approval: %s', (_l, command) => {
    const v = verdict({ command });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('install-package-global');
  });

  // NOT install aliases — must not start denying just because they share the
  // `i`/`in` prefix or a hyphenated/scoped package name contains a verb word.
  const allow: Array<[string, string]> = [
    ['npm init', 'npm init'],
    ['npm info', 'npm info left-pad'],
    ['npm ls -g package name contains "ci"', 'npm ls -g some-ci-tool'],
    ['npm ls -g package name contains "add"', 'npm ls -g social-add-on'],
    ['npm outdated -g scoped package ends in "add"', 'npm outdated -g @scope/add'],
    // Fix 2: there is no global `npm ci` — dropped from the verb set entirely.
    ['npm ci -g (no such thing as global ci)', 'npm ci -g'],
  ];
  it.each(allow)('allows: %s', (_l, command) => {
    expect(decision({ command })).toBe('allow');
  });
});

describe('#89 — external-egress must not fire on read-only GET fetches', () => {
  const allow: Array<[string, Record<string, unknown>]> = [
    ['web_fetch wikipedia', { url: 'https://en.wikipedia.org/wiki/2026_FIFA_World_Cup' }],
    ['web_fetch github api', { url: 'https://api.github.com/repos/Drakon-Systems-Ltd/ShieldCortex/commits/main' }],
  ];
  it.each(allow)('allows: %s', (_l, args) => {
    expect(decision(args, 'web_fetch')).toBe('allow');
  });

  const approve: Array<[string, string]> = [
    ['curl POST with data', 'curl -X POST https://example.com/api -d @dump.json'],
    ['curl --data', 'curl --data "x=1" https://example.com/collect'],
  ];
  it.each(approve)('still requires approval: %s', (_l, command) => {
    const v = verdict({ command });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('external-egress');
  });
});
