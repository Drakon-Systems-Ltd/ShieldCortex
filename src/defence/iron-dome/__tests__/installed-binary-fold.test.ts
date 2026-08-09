import { describe, it, expect, jest } from '@jest/globals';
import { evaluateToolCall, detectScriptInvocation } from '../tool-action-guard.js';
import type { ToolGuardVerdict } from '../tool-action-guard.js';

/**
 * Issue #199 — a wrapper shim's SOURCE was treated as the operator's command.
 *
 * `sleep 30 && /opt/homebrew/bin/openclaw gateway restart` was denied as
 * `install-package-global` because the guard folded the Homebrew shim at that
 * path, found package-manager vocabulary in the wrapper body, and scanned it as
 * live shell. Every Homebrew- and npm-installed CLI is a shim whose body
 * mentions its package manager, so the class covered essentially all of them —
 * and the denied command was the recovery action for an outage.
 *
 * The principle: spelling the full path to an installed executable must not be
 * scarier than typing its bare name. `openclaw gateway restart` never folds
 * (bare command words are not path tokens), so `/opt/homebrew/bin/openclaw
 * gateway restart` folding the shim body was pure asymmetry — the relief adds
 * zero exposure relative to the bare-name spelling of the same intent.
 *
 * The relief is deliberately narrow, and everything outside it stays folded:
 *   - only EXTENSIONLESS files count (installed CLIs are extensionless by
 *     convention; `/usr/local/bin/backup.sh` is a script someone parked in a
 *     bin dir and keeps being scanned),
 *   - only in RECOGNISED install roots (a project's own `./bin/deploy` is
 *     exactly what folding exists for),
 *   - only in COMMAND position — `bash /opt/homebrew/bin/x` executes the file
 *     AS a script and still folds it.
 */

/** A realistic npm/Homebrew launcher body — package-manager vocabulary as data. */
const SHIM_BODY = [
  '#!/bin/sh',
  'basedir=$(dirname "$(echo "$0" | sed -e \'s,\\\\,/,g\')")',
  '# installed via: npm install -g openclaw',
  'exec node "$basedir/../lib/node_modules/openclaw/dist/entry.js" "$@"',
].join('\n');

function stubResolver(files: Record<string, string>): (p: string) => string | null {
  return (p: string) => (Object.prototype.hasOwnProperty.call(files, p) ? files[p] : null);
}

function verdictOf(command: string, files: Record<string, string>): ToolGuardVerdict {
  return evaluateToolCall('Bash', { command }, undefined, { resolveScriptSource: stubResolver(files) });
}

describe('#199 — the live repro: a service restart via an installed shim', () => {
  it('allows the reported command and never reads the shim', () => {
    const resolver = jest.fn(() => SHIM_BODY);
    const v = evaluateToolCall(
      'Bash',
      { command: 'sleep 30 && /opt/homebrew/bin/openclaw gateway restart' },
      undefined,
      { resolveScriptSource: resolver },
    );
    expect(v.decision).toBe('allow');
    expect(v.signals).not.toContain('install-package-global');
    // Not folded and not opaque either — same posture as the bare-name spelling.
    expect(v.signals).not.toContain('opaque-script-invocation');
    expect(resolver).not.toHaveBeenCalled();
  });

  it('treats the path spelling exactly like the bare-name spelling', () => {
    const bare = evaluateToolCall('Bash', { command: 'openclaw gateway restart' });
    const spelt = verdictOf('/opt/homebrew/bin/openclaw gateway restart', {
      '/opt/homebrew/bin/openclaw': SHIM_BODY,
    });
    expect(spelt.decision).toBe(bare.decision);
    expect(spelt.severity).toBe(bare.severity);
    expect(spelt.signals).toEqual(bare.signals);
  });
});

describe('#199 — recognised install roots are relieved in command position', () => {
  const roots = [
    '/usr/bin/openclaw',
    '/usr/local/bin/openclaw',
    '/opt/homebrew/bin/openclaw',
    '/opt/homebrew/opt/node/bin/openclaw',
    '/usr/local/opt/node@20/bin/openclaw',
    '/opt/homebrew/Cellar/openclaw/1.0.0/bin/openclaw',
    '/snap/bin/openclaw',
    '/home/linuxbrew/.linuxbrew/bin/openclaw',
    '/home/ubuntu/.npm-global/bin/openclaw',
    '/Users/michael/.npm-global/bin/openclaw',
    '~/.npm-global/bin/openclaw',
    '~/.local/bin/openclaw',
    '~/.cargo/bin/openclaw',
    '~/.volta/bin/openclaw',
    '~/.nvm/versions/node/v22.1.0/bin/openclaw',
    '~/.asdf/shims/openclaw',
    './node_modules/.bin/jest',
    '/home/ubuntu/repo/node_modules/.bin/jest',
  ];
  for (const p of roots) {
    it(`does not fold ${p}`, () => {
      expect(detectScriptInvocation(`${p} --version`)).toEqual([]);
    });
  }
});

describe('#199 — everything outside the relief stays folded (fail-closed)', () => {
  it('still folds a project-local script whose body does a global install', () => {
    const v = verdictOf('./scripts/setup', { './scripts/setup': '#!/bin/sh\nnpm install -g something\n' });
    expect(v.decision).toBe('require_approval');
    expect(v.signals).toContain('install-package-global');
  });

  it('still folds a file WITH an extension parked in a bin dir', () => {
    expect(detectScriptInvocation('/usr/local/bin/backup.sh --now')).toEqual(['/usr/local/bin/backup.sh']);
  });

  it('still folds a bin-dir file executed BY an interpreter', () => {
    expect(detectScriptInvocation('bash /opt/homebrew/bin/openclaw')).toEqual(['/opt/homebrew/bin/openclaw']);
  });

  it('does not relieve a project bin dir that merely ends in /bin', () => {
    expect(detectScriptInvocation('./bin/deploy --prod')).toEqual(['./bin/deploy']);
    expect(detectScriptInvocation('/home/ubuntu/repo/bin/deploy')).toEqual(['/home/ubuntu/repo/bin/deploy']);
  });

  it('a catastrophic op AFTER the shim is still caught on the command surface', () => {
    const v = verdictOf('/opt/homebrew/bin/openclaw gateway stop && rm -rf ~/', {
      '/opt/homebrew/bin/openclaw': SHIM_BODY,
    });
    expect(v.decision).toBe('block');
    expect(v.severity).toBe('catastrophic');
  });
});
