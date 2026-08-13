import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it, expect, afterEach } from '@jest/globals';
import { summariseCommandOutput } from '../integrations/child-output.js';
import type { CapturedError } from '../integrations/child-output.js';
import { step, readRealtimePluginRegistration } from '../cli/update.js';
import { scanForCredentials } from '../defence/credential-leak/index.js';

/**
 * Adversarial-review regressions for #248's redaction layer (PR #261).
 *
 * The review reproduced three information-flow gaps and two smaller defects:
 *  1. `summariseCommandOutput` — the sink actual child stderr flows through —
 *     lacked the credential-fragment pass `sanitiseForReport` has, so a
 *     credential-shaped PATH SEGMENT leaked raw through the higher-volume sink
 *     while the hand-built-string sink redacted it.
 *  2. The 32KB head/tail cap ran BEFORE env-value redaction; a secret split at
 *     the cap boundary escaped the exact-match replace, and its surviving
 *     40-hex prefix was then allowlisted as a git SHA.
 *  3. `https://user:pass@host` basic-auth URLs passed every layer (the
 *     connection-string patterns covered postgres/mysql/mongo/redis only).
 *  4. `step()` printed the failure headline twice (reason + detail[0]).
 *  5. An unreadable plugins DIRECTORY still read as "not installed"
 *     (`existsSync` swallows traversal EACCES).
 */

const SECRET_TOKEN = 'X7fQ2mZp9RtL4vNc8KwB3JhD6sYgA1eU5oXiTbMr0PlWnQzVfKjSxE9uYwGdTpAaCvBn';

describe('review 1 — command-output sink redacts credential-shaped path segments', () => {
  it('a token embedded in a child-output path does not survive summariseCommandOutput', () => {
    const out = `npm error code EACCES\nnpm error open '/Users/op/.openclaw/extensions/${SECRET_TOKEN}/state.json'\n`;
    const { lines } = summariseCommandOutput(out, { home: '/Users/op', env: {} });
    expect(lines.join('\n')).not.toContain(SECRET_TOKEN);
  });
});

describe('review 2 — env-value redaction happens before the 32KB cap', () => {
  it('an env secret split by the cap boundary leaks no 40-char prefix', () => {
    // 44-char hex secret positioned so the head slice (MAX_INPUT_BYTES/2 =
    // 16384 bytes) cuts it 4 chars before its end — the exact shape the review
    // reproduced: the surviving 40-hex prefix matched the git-SHA allowlist.
    const secret = 'f3a9c1d07b5e42618ac9f0d3b7215e88fa04c6d1beef';
    const line = `npm error E401 auth failed for token ${secret}\n`;
    // Place the line so that byte 16384 falls exactly 4 chars before the
    // secret's end.
    const secretEndOffset = line.indexOf(secret) + secret.length;
    const targetLineStart = 16384 + 4 - secretEndOffset;
    let filler = '';
    while (filler.length < targetLineStart) filler += 'npm error spam line for padding purposes\n';
    filler = filler.slice(0, targetLineStart);
    const tail = 'npm error tail noise\n'.repeat(2000); // push total > 32KB
    const out = filler + line + tail;
    expect(out.length).toBeGreaterThan(32 * 1024);

    const { lines } = summariseCommandOutput(out, { env: { CLAWHUB_TOKEN: secret }, maxLines: 10 });
    const joined = lines.join('\n');
    expect(joined).not.toContain(secret);
    expect(joined).not.toContain(secret.slice(0, 40));
  });
});

describe('review 3 — HTTP basic-auth URLs are redacted like every other connection string', () => {
  it('scanForCredentials flags and redacts https://user:pass@host', () => {
    const content = 'npm error 401 GET https://ci-bot:Hunter2Passw0rd@npm.corp.example/shieldcortex';
    const result = scanForCredentials(content);
    expect(result.findings.some(f => f.type === 'connection_string')).toBe(true);
    expect(result.redactedContent ?? content).not.toContain('Hunter2Passw0rd');
  });

  it('does not flag credential-free URLs (ports, emails in query strings)', () => {
    for (const benign of [
      'GET https://registry.npmjs.org:443/shieldcortex',
      'https://mail.example.com/reset?email=a@b.com',
      'see https://example.com/path/to/x@2x.png',
    ]) {
      const r = scanForCredentials(benign);
      expect(r.findings.filter(f => f.type === 'connection_string')).toHaveLength(0);
    }
  });

  it('the password never reaches summarised child output', () => {
    const out = 'npm error 401 Unauthorized - GET https://ci-bot:Hunter2Passw0rd@npm.corp.example/shieldcortex\n';
    const { lines } = summariseCommandOutput(out, { env: {} });
    expect(lines.join('\n')).not.toContain('Hunter2Passw0rd');
  });
});

describe('review 4 — step() prints the failure headline once, not twice', () => {
  function captureWrites(stream: NodeJS.WriteStream): { calls: string[]; restore: () => void } {
    const calls: string[] = [];
    const original = stream.write.bind(stream);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (stream as any).write = (chunk: any) => {
      calls.push(typeof chunk === 'string' ? chunk : String(chunk));
      return true;
    };
    return { calls, restore: () => { (stream as any).write = original; } };
  }

  it('the first output line is not duplicated as both reason and detail', async () => {
    const stderr = captureWrites(process.stderr);
    const stdout = captureWrites(process.stdout);
    const err = Object.assign(new Error('exit 1: npm install -g shieldcortex@latest'), {
      exitCode: 1,
      command: 'npm install -g shieldcortex@latest',
      stdout: '',
      stderr: 'npm error code E401\nnpm error 401 Unauthorized - GET https://registry.npmjs.org/shieldcortex\n',
    } satisfies Partial<CapturedError>);

    try {
      await expect(step('npm package', async () => { throw err; })).rejects.toThrow();
    } finally {
      stderr.restore();
      stdout.restore();
    }
    const occurrences = stderr.calls.join('').match(/npm error code E401/g) ?? [];
    expect(occurrences).toHaveLength(1);
  });
});

describe('review 5 — an unreadable plugins DIRECTORY is not "not installed"', () => {
  let home: string;
  afterEach(() => {
    if (home) {
      try { chmodSync(join(home, '.openclaw', 'plugins'), 0o755); } catch { /* already restored */ }
      rmSync(home, { recursive: true, force: true });
    }
  });

  it('reports unreadable when the directory itself denies traversal', () => {
    home = mkdtempSync(join(tmpdir(), 'sc-review-dir-'));
    const pluginsDir = join(home, '.openclaw', 'plugins');
    mkdirSync(pluginsDir, { recursive: true });
    writeFileSync(join(pluginsDir, 'installs.json'), JSON.stringify({ installRecords: {} }));
    chmodSync(pluginsDir, 0o000);

    try {
      // Probe whether the permission actually bites for THIS process (root and
      // some CI containers can traverse a 0-mode dir). Only when it bites is
      // the unreadable verdict required — but then it is required, hard.
      let permissionBites = false;
      try {
        readFileSync(join(pluginsDir, 'installs.json'), 'utf-8');
      } catch {
        permissionBites = true;
      }

      const r = readRealtimePluginRegistration(home);
      if (permissionBites) {
        expect(r.unreadable).toBe(true);
        expect(r.registered).toBe(false);
      } else {
        expect(r.registered).toBe(false);
      }
    } finally {
      chmodSync(pluginsDir, 0o755);
    }
  });

  it('a genuinely missing registry still reads as not-installed, not unreadable', () => {
    home = mkdtempSync(join(tmpdir(), 'sc-review-dir2-'));
    const r = readRealtimePluginRegistration(home);
    expect(r.registered).toBe(false);
    expect(r.unreadable).toBe(false);
  });
});
