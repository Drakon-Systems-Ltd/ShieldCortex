import { describe, it, expect } from '@jest/globals';
import {
  checkSessionLease,
  findFreeze,
  scopeForToolCall,
  type LeaseScope,
} from '../session-lease.js';

/**
 * Adversarial hardening of the #227 core (TARS review item 4): lift semantics,
 * unknown scope, blank identity, missing TTL, and verbatim untrusted-ledger
 * echo all had fail-open or trust-boundary defects under adversarial fixtures.
 * Plus the scope mapper — the piece that turns "a tool call" into "a lease
 * scope", judged on the command surface (the #183 lesson), previously absent.
 */

const NOW = Date.parse('2026-08-13T12:00:00Z');

describe('lift semantics — an operator lift cleanly cancels a freeze', () => {
  it('a record edited from FROZEN to LIFTED no longer freezes', () => {
    const ledger = '| LIFTED | npm-publish | frozen 10 Aug, lifted 11 Aug after review |';
    expect(findFreeze(ledger, 'npm-publish')).toBeNull();
  });

  it('a record carrying BOTH markers is still a freeze — a lift is an edit, not an annotation', () => {
    // An attacker (or sloppy edit) appending "LIFTED" to a live freeze must not
    // disarm it: the FROZEN marker governs unless the record was rewritten.
    const ledger = '| FROZEN | npm-publish | do not publish | LIFTED';
    expect(findFreeze(ledger, 'npm-publish')).not.toBeNull();
  });
});

describe('unknown scope — a config error must not read as "nothing frozen"', () => {
  it('an unrecognised scope refuses with unknown, never allows', () => {
    const decision = checkSessionLease({
      scope: 'not-a-real-scope' as LeaseScope,
      ledger: '',
      held: null,
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('unknown');
  });
});

describe('blank identity — re-entrancy must not be spoofable through emptiness', () => {
  it('a blank self never matches a blank holder (no accidental re-entry)', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: '', acquiredAtMs: NOW - 1000, expiresAtMs: NOW + 60_000 },
      self: '',
      nowMs: NOW,
    });
    // Neither party has an identity; treating them as "the same session" would
    // let any identity-less process re-enter any identity-less lease.
    expect(decision.verdict).not.toBe('allow');
  });
});

describe('missing TTL — a record without expiry must not wedge the fleet forever', () => {
  it('derives expiry from acquiredAt + default TTL when expiresAtMs is absent', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: 'session-b', acquiredAtMs: NOW - 60 * 60 * 1000 }, // an hour ago, no TTL
      self: 'session-a',
      nowMs: NOW,
    });
    // An hour-old record with no TTL is long past any sane default — expired.
    expect(decision.verdict).toBe('allow');
  });

  it('a record with NEITHER timestamp is malformed — treated as free, not held forever', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: 'session-b' },
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('allow');
  });

  it('a fresh record without TTL still binds within the default window', () => {
    const decision = checkSessionLease({
      scope: 'install',
      ledger: '',
      held: { holder: 'session-b', acquiredAtMs: NOW - 1000 },
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('held');
  });
});

describe('untrusted-ledger echo — freeze text is sanitised before quoting', () => {
  it('control characters in a ledger record never reach the reason string', () => {
    const ledger = '| FROZEN | npm publish is frozen \u001b[31mEVIL\u0007 until review |';
    const decision = checkSessionLease({
      scope: 'npm-publish',
      ledger,
      held: null,
      self: 'session-a',
      nowMs: NOW,
    });
    expect(decision.verdict).toBe('frozen');
    // eslint-disable-next-line no-control-regex
    const controlChars = /[\u0000-\u001F\u007F]/;
    expect(decision.reason).not.toMatch(controlChars);
    expect(decision.freeze ?? '').not.toMatch(controlChars);
  });
});

describe('scopeForToolCall — the command surface, not the tool name (#183)', () => {
  const bash = (command: string) => scopeForToolCall('Bash', { command });

  it('npm publish and tag pushes map to npm-publish', () => {
    expect(bash('npm publish')).toBe('npm-publish');
    expect(bash('cd pkg && npm publish --access public')).toBe('npm-publish');
    expect(bash('git push && git push --tags')).toBe('npm-publish');
    expect(bash('git push origin v4.50.0')).toBe('npm-publish');
  });

  it('fleet-host installs map to install; a local dev install does not', () => {
    expect(bash('npm install -g shieldcortex@latest')).toBe('install');
    expect(bash('npm i --global shieldcortex')).toBe('install');
    expect(bash('openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest')).toBe('install');
    expect(bash('npm install')).toBeNull();
    expect(bash('npm ci')).toBeNull();
  });

  it('gateway restarts map to gateway-restart', () => {
    expect(bash('openclaw gateway restart')).toBe('gateway-restart');
    expect(bash('launchctl kickstart -k gui/501/com.openclaw.gateway')).toBe('gateway-restart');
  });

  it('edits to guard-critical files map to security-config regardless of tool', () => {
    expect(scopeForToolCall('Edit', { file_path: '/Users/op/.shieldcortex/config.json' })).toBe('security-config');
    expect(scopeForToolCall('Write', { file_path: '/Users/op/.claude/settings.json' })).toBe('security-config');
    expect(bash('echo x >> ~/.shieldcortex/config.json')).toBe('security-config');
  });

  it('ordinary tool calls map to no scope at all — the lease must not tax every action', () => {
    expect(bash('ls -la')).toBeNull();
    expect(bash('git status')).toBeNull();
    expect(scopeForToolCall('Read', { file_path: '/tmp/x' })).toBeNull();
    expect(scopeForToolCall('Edit', { file_path: '/tmp/app.ts' })).toBeNull();
  });

  it('never throws on malformed input', () => {
    expect(scopeForToolCall('Bash', {})).toBeNull();
    expect(scopeForToolCall('Bash', { command: null })).toBeNull();
    expect(scopeForToolCall('', undefined as unknown as Record<string, unknown>)).toBeNull();
  });
});

describe('scopeForToolCall — evasions of its own stated coverage (review MAJOR-3 / minor-1)', () => {
  const bash = (command: string) => scopeForToolCall('Bash', { command });

  it('catches global installs with the flag in any position', () => {
    expect(bash('npm --global install shieldcortex')).toBe('install');
    expect(bash('npm --location=global install shieldcortex')).toBe('install');
    expect(bash('sudo npm install --global x')).toBe('install');
  });

  it('catches non-npm publishers', () => {
    expect(bash('yarn publish')).toBe('npm-publish');
    expect(bash('pnpm publish --access public')).toBe('npm-publish');
    expect(bash('bun publish')).toBe('npm-publish');
  });

  it('catches systemd + launchd gateway restarts', () => {
    expect(bash('systemctl restart openclaw-gateway.service')).toBe('gateway-restart');
    expect(bash('sudo systemctl stop shieldcortex-gateway')).toBe('gateway-restart');
  });

  it('does NOT false-positive on benign mentions inside quotes/args', () => {
    expect(bash('echo "how to npm publish"')).toBeNull();
    expect(bash('grep -r "npm publish steps" docs/')).toBeNull();
    expect(bash('cat notes-about-npm-publish.md')).toBeNull();
  });

  it('still leaves local dev installs and ci alone', () => {
    expect(bash('npm install')).toBeNull();
    expect(bash('npm ci')).toBeNull();
    expect(bash('npm i lodash')).toBeNull();
  });
});

describe('#550 — security-config is a WRITE SHAPE onto a protected file, not a mention', () => {
  const bash = (command: string) => scopeForToolCall('Bash', { command });

  // The issue's acceptance pair, verbatim.
  it('a commit message naming the file takes no lease; a redirect onto it does', () => {
    expect(bash('git commit -m "gate ~/.openclaw/openclaw.json writes"')).toBeNull();
    expect(bash('echo x > ~/.openclaw/openclaw.json')).toBe('security-config');
  });

  it('the refusals from the issue take no lease', () => {
    // 1. a heredoc writing a throwaway probe whose string literals name the file
    expect(bash([
      "cat > /tmp/sc517/probe505.mjs <<'EOF'",
      'const dist = process.argv[2];',
      "const target = '~/.openclaw/openclaw.json';",
      "console.log(scope('Write', { file_path: target }), scope('Bash', { command: 'cat ' + target }));",
      'EOF',
    ].join('\n'))).toBeNull();
    // 3. a commit message body naming the file, chained into push and PR creation
    expect(bash([
      "git add -A && git commit -F - <<'EOF'",
      'fix(guard): #505 treat ~/.openclaw/openclaw.json as a sensitive write target',
      '',
      'Details in the PR body.',
      'EOF',
      'git push -u origin HEAD && gh pr create --fill',
    ].join('\n'))).toBeNull();
    // the live re-trigger while fixing this: a grep whose TARGET is the file
    expect(bash('grep -rn "PreToolUse" ~/.claude/settings.json')).toBeNull();
  });

  it('reads, searches, diffs and backups of the file take no lease', () => {
    expect(bash('cat ~/.openclaw/openclaw.json')).toBeNull();
    expect(bash('jq .plugins ~/.openclaw/openclaw.json')).toBeNull();
    expect(bash('diff ~/.shieldcortex/config.json /tmp/x')).toBeNull();
    expect(bash('ls -la ~/.claude/settings.json && stat ~/.claude/settings.json')).toBeNull();
    expect(bash("sed -n '1,20p' ~/.openclaw/openclaw.json")).toBeNull();
    expect(bash('cp ~/.openclaw/openclaw.json ~/.openclaw/openclaw.json.bak')).toBeNull();
    expect(bash('cp ~/.openclaw/openclaw.json /tmp/backup.json')).toBeNull();
    expect(bash('tar czf /tmp/b.tgz ~/.openclaw/openclaw.json')).toBeNull();
    expect(bash('rsync -a ~/.shieldcortex/config.json backup:/srv/')).toBeNull();
    // A redirect written INSIDE a string is prose, not a redirect.
    expect(bash('echo "how to edit ~/.openclaw/openclaw.json > careful"')).toBeNull();
    expect(bash("git log --oneline -3 -- '~/.claude/settings.json'")).toBeNull();
  });

  it('redirects onto the file take the lease: glued, quoted, appended or via an fd', () => {
    expect(bash('echo x >~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('echo x >> ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('cat > "$HOME/.claude/settings.json" <<\'EOF\'\n{}\nEOF')).toBe('security-config');
    expect(bash('jq ".a=1" ~/.openclaw/openclaw.json > /tmp/x && cp /tmp/x ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('some-tool 2> ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('some-tool &> ~/.shieldcortex/config.json')).toBe('security-config');
    // fd dups are not files
    expect(bash('cat ~/.openclaw/openclaw.json 2>&1 | head')).toBeNull();
  });

  it('mutating verbs given the file as an operand take the lease', () => {
    expect(bash('rm -f ~/.claude/settings.json')).toBe('security-config');
    expect(bash('mv /tmp/new.json ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('mv ~/.openclaw/openclaw.json /tmp/away.json')).toBe('security-config');
    expect(bash("sed -i 's/a/b/' ~/.shieldcortex/config.json")).toBe('security-config');
    expect(bash("sed -i.bak 's/a/b/' ~/.shieldcortex/config.json")).toBe('security-config');
    expect(bash("perl -pi -e 's/a/b/' ~/.shieldcortex/config.json")).toBe('security-config');
    expect(bash('echo x | sudo tee -a ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('vim ~/.claude/settings.json')).toBe('security-config');
    expect(bash('code ~/.claude/settings.json')).toBe('security-config');
    expect(bash('truncate -s 0 ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('chmod 600 ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('dd if=/tmp/x of=$HOME/.openclaw/openclaw.json')).toBe('security-config');
  });

  it('copy-like verbs take the lease only when the file is the destination', () => {
    expect(bash('cp ~/.openclaw/openclaw.json.bak ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('install -m 600 /tmp/x ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('ln -sf /tmp/x ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('(cd /tmp && cp new.json ~/.shieldcortex/config.json)')).toBe('security-config');
    expect(bash('cp ~/.shieldcortex/config.json /tmp/copy.json')).toBeNull();
  });

  it('an interpreter or shell handed the file fails closed — the mapper does not parse programs', () => {
    expect(bash('python3 -c "import json; json.dump({}, open(\'/home/op/.openclaw/openclaw.json\',\'w\'))"')).toBe('security-config');
    expect(bash('node -e "require(\'fs\').writeFileSync(process.env.HOME+\'/.claude/settings.json\',\'{}\')"')).toBe('security-config');
    expect(bash("python3 - <<'EOF'\nopen('/home/op/.shieldcortex/config.json','w').write('{}')\nEOF")).toBe('security-config');
    expect(bash("bash -c 'echo x > ~/.openclaw/openclaw.json'")).toBe('security-config');
    expect(bash('python3 scripts/patch.py ~/.openclaw/openclaw.json')).toBe('security-config');
  });

  it('a heredoc body is data for the stage that opened it, and later statements are still read', () => {
    // body mentions the file; the writer targets /tmp — no lease
    expect(bash("cat > /tmp/x <<'EOF' && echo done\nconst p = '~/.openclaw/openclaw.json';\nEOF")).toBeNull();
    // the statement AFTER the terminator is evaluated on its own
    expect(bash("cat > /tmp/x <<'EOF'\nhello\nEOF\ncp /tmp/x ~/.openclaw/openclaw.json")).toBe('security-config');
    expect(bash("cat > /tmp/x <<'EOF'\nhello\nEOF && cp /tmp/x ~/.openclaw/openclaw.json")).toBe('security-config');
  });

  it('file-edit tools are judged on their target path exactly as before', () => {
    expect(scopeForToolCall('Edit', { file_path: '/Users/op/.shieldcortex/config.json' })).toBe('security-config');
    expect(scopeForToolCall('Write', { file_path: '/Users/op/.claude/settings.json' })).toBe('security-config');
    expect(scopeForToolCall('Read', { file_path: '/Users/op/.claude/settings.json' })).toBeNull();
  });

  it('the other scope rows are untouched', () => {
    expect(bash('npm publish')).toBe('npm-publish');
    expect(bash('npm install -g x')).toBe('install');
    expect(bash('openclaw gateway restart')).toBe('gateway-restart');
    expect(bash('git status')).toBeNull();
  });
});
