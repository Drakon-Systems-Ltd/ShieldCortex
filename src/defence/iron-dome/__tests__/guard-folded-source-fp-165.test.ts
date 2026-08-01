/**
 * Failing-first spec for #165 — shell rules must not fire on language APIs.
 *
 * Found by being blocked from running this repo's own test suite, minutes
 * after #160 wired script-source folding into the Claude Code hook:
 *
 *   $ node scripts/run-jest.mjs
 *   ShieldCortex Action Guard: recognised dangerous operation requires approval
 *   [rule: stop-process-or-service, touch-sensitive-path; matched: "kill"]
 *
 * What it matched, inside the runner:
 *   const env = { ...process.env, … };      → touch-sensitive-path (".env")
 *   process.kill(process.pid, signal);      → stop-process-or-service ("kill")
 *
 * Signal forwarding to its OWN pid, and a property access. #160 was right to
 * fold script contents — it closes a real write-then-exec hole — but folding
 * exposed every shell-vocabulary rule to interpreter source on the surface that
 * gates every Bash call in a Claude Code session. The blast radius is any
 * project whose build script forwards a signal or reads process.env, i.e.
 * `npm test`. A guard that blocks `npm test` is a guard people turn off.
 */
import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';
import { createScriptSourceResolver } from '../script-source-resolver.js';
import fs from 'fs';
import os from 'os';
import path from 'path';

const decide = (command: string) => evaluateToolCall('Bash', { command });

describe('#165 — a language process API is not the shell kill verb', () => {
  it('process.kill(process.pid, …) does not gate', () => {
    expect(decide('node -e "process.kill(process.pid, 0)"').signals ?? [])
      .not.toContain('stop-process-or-service');
  });

  it('a .kill() method call does not gate', () => {
    expect(decide('node -e "child.kill()"').signals ?? [])
      .not.toContain('stop-process-or-service');
  });

  // ── the shell verb must still gate, in every shape ──

  it('a bare kill still gates', () => {
    expect(decide('kill 1234').signals ?? []).toContain('stop-process-or-service');
  });

  it('sudo pkill / killall / piped and chained forms still gate', () => {
    expect(decide('sudo pkill -f node').signals ?? []).toContain('stop-process-or-service');
    expect(decide('killall -9 node').signals ?? []).toContain('stop-process-or-service');
    expect(decide('echo x; kill -9 4242').signals ?? []).toContain('stop-process-or-service');
    expect(decide('ps aux | grep node | xargs kill').signals ?? []).toContain('stop-process-or-service');
  });

  it('systemctl stop / disable / mask are untouched', () => {
    expect(decide('systemctl stop nginx').signals ?? []).toContain('stop-process-or-service');
    expect(decide('sudo systemctl disable openclaw-gateway').signals ?? []).toContain('stop-process-or-service');
  });
});

describe('#165 — `.env` means the file, not a property lookup', () => {
  it('process.env does not gate', () => {
    expect(decide('node -e "console.log(process.env.HOME)"').signals ?? [])
      .not.toContain('touch-sensitive-path');
  });

  it('import.meta.env does not gate', () => {
    expect(decide('node -e "const x = import.meta.env"').signals ?? [])
      .not.toContain('touch-sensitive-path');
  });

  // ── the FILE must still gate ──

  it('reading the .env file still gates', () => {
    expect(decide('cat .env').signals ?? []).toContain('touch-sensitive-path');
    expect(decide('cat ./.env').signals ?? []).toContain('touch-sensitive-path');
    expect(decide('cat /app/.env').signals ?? []).toContain('touch-sensitive-path');
    expect(decide('cp .env.local /tmp/x').signals ?? []).toContain('touch-sensitive-path');
  });

  it('the other sensitive paths are untouched', () => {
    expect(decide('cat /etc/shadow').signals ?? []).toContain('touch-sensitive-path');
    expect(decide('cat ~/.ssh/id_rsa').signals ?? []).toContain('touch-sensitive-path');
    expect(decide('cat ~/.aws/credentials').signals ?? []).toContain('touch-sensitive-path');
  });
});

describe('#165 — the motivating case: running the test suite', () => {
  it('a build script that forwards a signal and reads process.env does not gate when folded', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-165-'));
    try {
      const runner = path.join(dir, 'run-tests.mjs');
      // The two lines from this repo's own runner, verbatim in shape.
      fs.writeFileSync(runner, [
        "const env = { ...process.env, SKIP_EMBEDDINGS: '1' };",
        "process.on('SIGINT', (signal) => { process.kill(process.pid, signal); });",
      ].join('\n'));

      const v = evaluateToolCall(
        'Bash',
        { command: `node ${runner}` },
        undefined,
        { resolveScriptSource: createScriptSourceResolver(dir) },
      );
      expect(v.signals ?? []).not.toContain('stop-process-or-service');
      expect(v.signals ?? []).not.toContain('touch-sensitive-path');
      expect(v.decision).toBe('allow');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('but a folded script that ACTUALLY shells out to a catastrophic op still hard-blocks', () => {
    // The whole reason #160 wired folding. Precision must not cost the catch.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-165b-'));
    try {
      const payload = path.join(dir, 'payload.sh');
      fs.writeFileSync(payload, '#!/bin/sh\nrm -rf /important\n');
      const v = evaluateToolCall(
        'Bash',
        { command: `bash ${payload}` },
        undefined,
        { resolveScriptSource: createScriptSourceResolver(dir) },
      );
      expect(v.decision).toBe('block');
      expect(v.severity).toBe('catastrophic');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a folded script that stops a real service still gates', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-165c-'));
    try {
      const script = path.join(dir, 'deploy.sh');
      fs.writeFileSync(script, '#!/bin/sh\nsystemctl stop nginx\n');
      const v = evaluateToolCall(
        'Bash',
        { command: `bash ${script}` },
        undefined,
        { resolveScriptSource: createScriptSourceResolver(dir) },
      );
      expect(v.signals ?? []).toContain('stop-process-or-service');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
