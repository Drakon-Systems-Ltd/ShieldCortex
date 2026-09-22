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

  // Review of #552 (Tars): real writes the first cut returned null for, and a
  // heredoc body it read as a redirect.
  it('a redirect glued to the word before it is still a redirect', () => {
    expect(bash('printf changed>~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('printf changed>"$HOME/.openclaw/openclaw.json"')).toBe('security-config');
    expect(bash('echo x>>~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('echo x 2>~/.claude/settings.json')).toBe('security-config');
    // still not a redirect inside a string, and fd dups are still not files
    expect(bash('echo "x>~/.openclaw/openclaw.json"')).toBeNull();
    expect(bash('cat ~/.openclaw/openclaw.json 2>&1 >/dev/null')).toBeNull();
  });

  it('sed/perl in-place flags are read quoted and in clusters', () => {
    expect(bash('sed "-i" "s/a/b/" ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash("sed -ni 's/a/b/p' ~/.shieldcortex/config.json")).toBe('security-config');
    expect(bash("sed -Ei 's/a/b/' ~/.openclaw/openclaw.json")).toBe('security-config');
    expect(bash("sed --in-place=.bak 's/a/b/' ~/.claude/settings.json")).toBe('security-config');
    expect(bash("sed --in-place 's/a/b/' '~/.claude/settings.json'")).toBe('security-config');
    expect(bash("perl -i.bak -pe 's/a/b/' ~/.shieldcortex/config.json")).toBe('security-config');
    // without an in-place flag sed is a read
    expect(bash("sed -nE '/plugins/p' ~/.openclaw/openclaw.json")).toBeNull();
  });

  it('an output option naming the file is a write whatever the verb', () => {
    expect(bash('git diff --output=$HOME/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('git diff --output ~/.openclaw/openclaw.json HEAD~1')).toBe('security-config');
    expect(bash('git diff --output "$HOME/.openclaw/openclaw.json"')).toBe('security-config');
    expect(bash('curl -o ~/.shieldcortex/config.json https://example.invalid/c.json')).toBe('security-config');
    expect(bash('git diff --output=/tmp/x -- ~/.openclaw/openclaw.json')).toBeNull();
  });

  it('a redirect written inside a heredoc body is data, not a redirect', () => {
    expect(bash([
      "cat > /tmp/notes.md <<'EOF'",
      'To change the setting run:',
      '  printf x > ~/.openclaw/openclaw.json',
      'EOF',
    ].join('\n'))).toBeNull();
    // the header's own redirect is still read
    expect(bash("cat > ~/.openclaw/openclaw.json <<'EOF'\n{}\nEOF")).toBe('security-config');
  });

  // #552 review, round 3: the mapper fails closed — an unknown verb given the
  // file is a write until proven otherwise; only proven reads and mentions
  // take nothing.
  it('ordinary write shapes the verb table did not know take the lease (fail closed)', () => {
    expect(bash('curl -s https://x/ -o ~/.claude/settings.json')).toBe('security-config');
    expect(bash('wget https://x/ -O ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash("awk -i inplace '{print}' ~/.claude/settings.json")).toBe('security-config');
    expect(bash("gawk -i inplace '{print}' ~/.claude/settings.json")).toBe('security-config');
    expect(bash("gawk '{print}' ~/.claude/settings.json")).toBeNull();
    expect(bash('patch ~/.claude/settings.json < /tmp/p.diff')).toBe('security-config');
    expect(bash('git checkout -- ~/.claude/settings.json')).toBe('security-config');
    expect(bash('git restore ~/.claude/settings.json')).toBe('security-config');
    expect(bash("yq -i '.a=1' ~/.openclaw/openclaw.json")).toBe('security-config');
    expect(bash('npx json -I -f ~/.openclaw/openclaw.json -e "this.a=1"')).toBe('security-config');
    expect(bash('some-new-tool ~/.shieldcortex/config.json')).toBe('security-config');
    expect(bash('git diff --no-index --output=$HOME/.openclaw/openclaw.json /dev/null /dev/null')).toBe('security-config');
  });

  it('compound statements, wrappers with option arguments, and xargs are seen through', () => {
    expect(bash('if true; then touch ~/.openclaw/openclaw.json; fi')).toBe('security-config');
    expect(bash('while :; do rm -f ~/.claude/settings.json; break; done')).toBe('security-config');
    expect(bash('env -u UNUSED_VAR touch ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash("sudo -u root sed -i 's/a/b/' ~/.claude/settings.json")).toBe('security-config');
    expect(bash('sudo -u root tee ~/.claude/settings.json')).toBe('security-config');
    expect(bash('nice -n 10 rm ~/.claude/settings.json')).toBe('security-config');
    expect(bash('timeout 5 tee ~/.claude/settings.json < /tmp/x')).toBe('security-config');
    expect(bash("echo ~/.claude/settings.json | xargs -I{} sh -c 'echo x > {}'")).toBe('security-config');
    expect(bash('echo ~/.claude/settings.json | xargs rm -f')).toBe('security-config');
    expect(bash('echo ~/.claude/settings.json | xargs cat')).toBeNull();
    // the wrapped command is still read as itself
    expect(bash('sudo -u root cat ~/.claude/settings.json')).toBeNull();
  });

  it('indirection and substitution fail closed', () => {
    expect(bash('T=~/.claude/settings.json; echo x > "$T"')).toBe('security-config');
    expect(bash('echo x > `echo ~/.claude/settings.json`')).toBe('security-config');
    expect(bash('echo x > $(echo ~/.claude/settings.json)')).toBe('security-config');
  });

  it('a multi-line quoted program is one statement handed to its interpreter', () => {
    expect(bash("python3 -c '\nopen(\"/home/op/.openclaw/openclaw.json\",\"w\").write(\"changed\")\n'")).toBe('security-config');
  });

  it('a sed/awk SCRIPT naming the file writes it; uniq/xxd second operand is an output (#552 r3)', () => {
    expect(bash("sed -n 'w ~/.openclaw/openclaw.json' /tmp/in")).toBe('security-config');
    expect(bash("sed 's/a/b/w ~/.claude/settings.json' /tmp/in")).toBe('security-config');
    expect(bash("sed -e w~/.openclaw/openclaw.json /tmp/in")).toBe('security-config');
    expect(bash("awk '{print > \"/home/x/.openclaw/openclaw.json\"}' /tmp/in")).toBe('security-config');
    expect(bash('uniq /tmp/in ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash('xxd -r /tmp/in.hex ~/.claude/settings.json')).toBe('security-config');
    // Plain reads through the same verbs stay reads.
    expect(bash("sed -n '1,5p' ~/.openclaw/openclaw.json")).toBeNull();
    expect(bash("awk '{print $1}' ~/.openclaw/openclaw.json")).toBeNull();
    expect(bash('uniq ~/.openclaw/openclaw.json')).toBeNull();
    expect(bash('uniq ~/.openclaw/openclaw.json /tmp/out')).toBeNull();
    expect(bash('xxd ~/.claude/settings.json')).toBeNull();
    expect(bash('xxd ~/.claude/settings.json /tmp/out.hex')).toBeNull();
  });

  it('a command substitution executes, inside double quotes and an unquoted heredoc too (#552 r3)', () => {
    expect(bash('echo "$(printf x > ~/.openclaw/openclaw.json)"')).toBe('security-config');
    expect(bash('V="$(tee ~/.claude/settings.json < /tmp/p)"; echo "$V"')).toBe('security-config');
    expect(bash('echo "`printf x > ~/.openclaw/openclaw.json`"')).toBe('security-config');
    expect(bash('echo "$(echo "$(printf x > ~/.openclaw/openclaw.json)")"')).toBe('security-config');
    expect(bash("cat <<EOF\n$(printf x > ~/.openclaw/openclaw.json)\nEOF")).toBe('security-config');
    // Single quotes and a quoted delimiter keep the text literal.
    expect(bash("echo '$(printf x > ~/.openclaw/openclaw.json)'")).toBeNull();
    expect(bash("cat <<'EOF'\n$(printf x > ~/.openclaw/openclaw.json)\nEOF")).toBeNull();
    // A substitution that only reads the file is a read.
    expect(bash('echo "$(cat ~/.openclaw/openclaw.json)"')).toBeNull();
    expect(bash('N=$((1 << 2)); cat ~/.openclaw/openclaw.json')).toBeNull();
  });

  it('quote and expansion contexts are a class: an apostrophe inside double quotes or an expanding heredoc body is text (#552 r4)', () => {
    // Tars at 0c70adc6: the substitution scanner had a single-quote toggle only.
    // Inside double quotes a `'` is literal and the `$( … )` still runs.
    expect(bash(`echo "'$(printf changed > ~/.openclaw/openclaw.json)'"`)).toBe('security-config');
    expect(bash('echo "\'`printf changed > ~/.openclaw/openclaw.json`\'"')).toBe('security-config');
    // An expanding heredoc body has NO shell quoting: quotes are text, `$( … )` runs.
    expect(bash("cat <<EOF\n'$(printf changed > ~/.openclaw/openclaw.json)'\nEOF")).toBe('security-config');
    expect(bash('cat <<EOF\n"$(printf changed > ~/.openclaw/openclaw.json)"\nEOF')).toBe('security-config');
    // Inside single quotes a backslash is literal, so `\'` CLOSES the quote.
    expect(bash("echo 'a\\'$(printf changed > ~/.openclaw/openclaw.json)")).toBe('security-config');
    // Inside double quotes `\$` and `\\` are escapes: `\$(` opens nothing.
    expect(bash('echo "\\$(printf changed > ~/.openclaw/openclaw.json)"')).toBeNull();
    expect(bash('echo "\\\\$(printf changed > ~/.openclaw/openclaw.json)"')).toBe('security-config');
    // In an expanding heredoc body only `\$`, `` \` `` and `\\` escape.
    expect(bash('cat <<EOF\n\\$(printf changed > ~/.openclaw/openclaw.json)\nEOF')).toBeNull();
    expect(bash('cat <<EOF\n\\\\$(printf changed > ~/.openclaw/openclaw.json)\nEOF')).toBe('security-config');
    // Single quotes on the shell surface still keep it literal.
    expect(bash("echo 'x\"$(printf changed > ~/.openclaw/openclaw.json)\"'")).toBeNull();
    // `$'…'` is a quote in which `\'` is an escaped apostrophe, not a close.
    expect(bash("echo $'a\\'$(printf changed > ~/.openclaw/openclaw.json)'")).toBeNull();
    expect(bash("echo $'a\\'; tee ~/.openclaw/openclaw.json < /tmp/x'")).toBeNull();
    // Every lexer shares the machine: `\"` inside double quotes does not close
    // them, so the `;` and the `>` after it are still string text.
    expect(bash('git commit -m "a\\"; tee ~/.openclaw/openclaw.json < /tmp/x"')).toBeNull();
    expect(bash('git commit -m "a\\" > ~/.openclaw/openclaw.json"')).toBeNull();
    expect(bash('git commit -m "a\\" | tee ~/.openclaw/openclaw.json"')).toBeNull();
  });

  it('a backslash-quoted or partly quoted heredoc delimiter is QUOTED: the body is literal and the terminator is the whole word (#552 r4)', () => {
    // `<<\EOF` is literal to bash (a substitution in the body is text) — no lease.
    expect(bash('cat <<\\EOF\n$(printf changed > ~/.openclaw/openclaw.json)\nEOF')).toBeNull();
    // `<<E'O'F` terminates on `EOF` and the body is literal; the write AFTER it is real.
    expect(bash("cat <<E'O'F\n$(printf changed > ~/.openclaw/openclaw.json)\nEOF\ntee ~/.openclaw/openclaw.json < /tmp/x")).toBe('security-config');
    expect(bash("cat <<E'O'F\n$(printf changed > ~/.openclaw/openclaw.json)\nEOF\necho done")).toBeNull();
    expect(bash('cat <<"EO"F\n$(printf changed > ~/.openclaw/openclaw.json)\nEOF\ncat ~/.openclaw/openclaw.json')).toBeNull();
    // `<<\EOF` swallows exactly its body: the statement after the terminator is judged.
    expect(bash('cat <<\\EOF\nbody\nEOF\ntee ~/.claude/settings.json < /tmp/x')).toBe('security-config');
    // `<<-` with a quoted delimiter is quoted too.
    expect(bash("cat <<-'EOF'\n\t$(printf changed > ~/.openclaw/openclaw.json)\n\tEOF")).toBeNull();
  });

  it('a lone `-` is stdin, an operand; grep -o is only-matching (#552 r3)', () => {
    expect(bash('xxd -r - ~/.claude/settings.json < /tmp/in.hex')).toBe('security-config');
    expect(bash('uniq - ~/.openclaw/openclaw.json < /tmp/in')).toBe('security-config');
    expect(bash('grep -o ~/.openclaw/openclaw.json /tmp/in')).toBeNull();
    expect(bash('grep -o pattern ~/.openclaw/openclaw.json')).toBeNull();
  });

  it('a `|` written inside a heredoc body is text, not a pipe — the body is never split into stages', () => {
    // #552 round 2 finding 3: pipeline splitting read the inert body and made a
    // `tee <file>` stage out of it. The body rides on the stage that opened it.
    expect(bash("cat > /tmp/note <<'EOF'\nrun: echo hi | tee ~/.openclaw/openclaw.json\nEOF")).toBeNull();
    expect(bash("cat <<'EOF' | grep -c x\nrun: echo hi | tee ~/.openclaw/openclaw.json\nEOF")).toBeNull();
    // The statements after the terminator are still judged.
    expect(bash("cat > /tmp/note <<'EOF'\necho hi | tee ~/.openclaw/openclaw.json\nEOF\nprintf x > ~/.openclaw/openclaw.json")).toBe('security-config');
    // An interpreter fed by the heredoc still reads its body, even mid-pipeline.
    expect(bash("python3 - <<'EOF' | tee /tmp/out\nopen('/home/x/.openclaw/openclaw.json','w').write('x')\nEOF")).toBe('security-config');
  });

  it('a `<<` inside quotes, a comment or arithmetic opens no heredoc — later lines are still judged', () => {
    expect(bash('echo "docs for << EOF"\ntee ~/.claude/settings.json < /tmp/x')).toBe('security-config');
    expect(bash("echo '<<EOF'\nprintf changed > ~/.openclaw/openclaw.json")).toBe('security-config');
    expect(bash('N=$((1 << WIDTH))\ntee ~/.claude/settings.json < /tmp/x')).toBe('security-config');
    expect(bash('# note: << EOF\ntee ~/.claude/settings.json < /tmp/x')).toBe('security-config');
    expect(bash('# note: << EOF\ncat ~/.claude/settings.json')).toBeNull();
  });

  it('proven reads and mentions still take nothing', () => {
    expect(bash('dd if=~/.claude/settings.json of=/tmp/x')).toBeNull();
    expect(bash('dd if=/tmp/x of=~/.claude/settings.json')).toBe('security-config');
    expect(bash('tar czf /tmp/b.tgz ~/.openclaw/openclaw.json')).toBeNull();
    expect(bash('tar cf ~/.openclaw/openclaw.json /tmp/dir')).toBe('security-config');
    expect(bash('tar xzf /tmp/b.tgz ~/.openclaw/openclaw.json')).toBe('security-config');
    expect(bash("awk '{print}' ~/.claude/settings.json")).toBeNull();
    expect(bash('git show HEAD:~/.claude/settings.json')).toBeNull();
    expect(bash('git add ~/.claude/settings.json && git commit -m x')).toBeNull();
    expect(bash('sha256sum ~/.shieldcortex/config.json')).toBeNull();
    expect(bash('echo "see ~/.shieldcortex/config.json for details" # then edit ~/.claude/settings.json')).toBeNull();
    expect(bash('cat ~/.openclaw/openclaw.json # rm ~/.openclaw/openclaw.json')).toBeNull();
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
