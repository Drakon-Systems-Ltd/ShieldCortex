/**
 * Cross-surface parity (#160) — the test the per-surface suites cannot be.
 *
 * ShieldCortex enforces on TWO surfaces: the OpenClaw realtime plugin
 * interceptor and the Claude Code PreToolUse hook. Three times now a fix has
 * landed on one call site while the sibling kept the old behaviour, with a
 * green suite either side because each surface is tested against its own
 * wiring:
 *
 *   #146 — hooks written as a bare command name: fixed at install, but the
 *          existing boxes were left dead until upgrade-repair was added.
 *   #160 — the script-folding bypass fix (v4.47.17): the plugin passed a
 *          `resolveScriptSource`, the hook called the guard with two arguments,
 *          so a payload written in one call and executed by path in the next
 *          was blocked on one surface and ALLOWED on the other.
 *
 * The recurring root cause in this codebase is not bad logic — it is a fix
 * landing on one of two call sites. A per-surface test can never see that; only
 * a test driven from ONE fixture table across BOTH surfaces can.
 *
 * So this file asserts capability parity at the wiring level rather than
 * re-testing guard logic: whatever the guard can do, both surfaces must be able
 * to ask it to do.
 */
import { describe, it, expect } from '@jest/globals';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const hookSrc = fs.readFileSync(path.join(repoRoot, 'scripts', 'pre-tool-hook.mjs'), 'utf-8');
const pluginSrc = fs.readFileSync(path.join(repoRoot, 'plugins', 'openclaw', 'interceptor.ts'), 'utf-8');

describe('#160 — both enforcement surfaces supply the script-source resolver', () => {
  it('the OpenClaw plugin passes a resolveScriptSource', () => {
    expect(pluginSrc).toMatch(/resolveScriptSource:\s*createScriptSourceResolver\(/);
  });

  it('the Claude Code hook passes a resolveScriptSource', () => {
    // The exact gap: `evaluateToolCall(toolName, toolInput)` — two arguments,
    // no options — meant the fold could never run on this surface.
    expect(hookSrc).toMatch(/resolveScriptSource/);
    expect(hookSrc).toMatch(/evaluateToolCall\(\s*\n?\s*toolName,\s*\n?\s*toolInput,/);
    // The resolver must be the FOURTH argument — the third is the IronDome
    // config, and an options object placed there is silently ignored.
    expect(hookSrc).toMatch(/toolInput,\s*\n\s*undefined,\s*\n\s*resolveScriptSource/);
  });

  it('neither surface calls the guard with the bare two-argument form', () => {
    for (const [name, src] of [['hook', hookSrc], ['plugin', pluginSrc]] as const) {
      const bare = src.match(/evaluateToolCall\(\s*\w+\s*,\s*\w+\s*\)/g) ?? [];
      expect({ surface: name, bareCalls: bare }).toEqual({ surface: name, bareCalls: [] });
    }
  });

  it('the shared resolver carries its safety rails with the implementation', () => {
    const shared = fs.readFileSync(
      path.join(repoRoot, 'src', 'defence', 'iron-dome', 'script-source-resolver.ts'),
      'utf-8',
    );
    expect(shared).toMatch(/export function createScriptSourceResolver/);
    expect(shared).toMatch(/UNREADABLE_PATH_PREFIX/);
    expect(shared).toMatch(/MAX_SCRIPT_SOURCE_BYTES/);
    // The resolver must never throw — a guard that throws fails open.
    expect(shared).toMatch(/catch\s*{\s*\n\s*return null;/);
  });

  it('the plugin documents WHY it keeps its own copy, so the duplication is a decision not an accident', () => {
    // The plugin publishes as its own npm package and builds standalone
    // (rootDir pinned to plugins/openclaw), so it cannot import from src/ —
    // converging by import breaks its build. A real constraint; it must be
    // stated at the copy, or the next reader will "tidy" it and break the
    // published package.
    expect(pluginSrc).toMatch(/DUPLICATED here, deliberately \(#160\)/);
    expect(pluginSrc).toMatch(/drift test/i);
  });
});

describe('#160 — the two resolver copies are held together by behaviour, not by hope', () => {
  // Text comparison would fail on a reformat and pass on a semantic change —
  // exactly backwards. Both implementations are run over ONE fixture table and
  // required to answer identically.
  it('answers identically on every safety-rail case', async () => {
    const { createScriptSourceResolver: shared } = await import('../defence/iron-dome/script-source-resolver.js');
    const { createScriptSourceResolver: plugin } = await import('../../plugins/openclaw/interceptor.js');

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-drift-'));
    try {
      const good = path.join(dir, 'ok.sh');
      fs.writeFileSync(good, '#!/bin/sh\necho hi\n');
      const big = path.join(dir, 'big.sh');
      fs.writeFileSync(big, 'x'.repeat(300_000));          // over the 256KB cap
      fs.mkdirSync(path.join(dir, 'adir'));

      const fixtures = [
        good,                                   // readable regular file
        big,                                    // oversized
        path.join(dir, 'adir'),                 // a directory
        path.join(dir, 'missing.sh'),           // absent
        '/proc/self/mem',                       // pseudo-filesystem
        '/sys/kernel/notes',
        '/dev/zero',
        '',                                     // empty
        'relative.sh',                          // relative, absent
      ];

      const a = shared(dir);
      const b = plugin(dir);
      for (const f of fixtures) {
        expect({ path: f, result: a(f) }).toEqual({ path: f, result: b(f) });
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('#160 — the fold actually changes the verdict, so the wiring is load-bearing', () => {
  it('a written payload executed by path is blocked WITH a resolver and opaque without one', async () => {
    const { evaluateToolCall } = await import('../defence/iron-dome/tool-action-guard.js');
    const { createScriptSourceResolver } = await import('../defence/iron-dome/script-source-resolver.js');

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-parity-'));
    try {
      const script = path.join(dir, 'payload.sh');
      fs.writeFileSync(script, '#!/bin/sh\nrm -rf /important\n');

      // Without a resolver: the guard cannot see the payload — opaque, allowed.
      const unresolved = evaluateToolCall('Bash', { command: `bash ${script}` });
      expect(unresolved.signals ?? []).toContain('opaque-script-invocation');
      expect(unresolved.decision).toBe('allow');

      // With one: the payload is folded in and hard-blocked.
      const resolved = evaluateToolCall(
        'Bash',
        { command: `bash ${script}` },
        undefined,
        { resolveScriptSource: createScriptSourceResolver(dir) },
      );
      expect(resolved.decision).toBe('block');
      expect(resolved.severity).toBe('catastrophic');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('the resolver refuses pseudo-filesystems and oversized files rather than reading them', async () => {
    const { createScriptSourceResolver } = await import('../defence/iron-dome/script-source-resolver.js');
    const resolve = createScriptSourceResolver('/');
    expect(resolve('/proc/self/mem')).toBeNull();
    expect(resolve('/sys/kernel/notes')).toBeNull();
    expect(resolve('/dev/zero')).toBeNull();
    // A directory is not a script.
    expect(resolve('/tmp')).toBeNull();
    // A path that does not exist returns null rather than throwing.
    expect(resolve('/nonexistent/definitely/not/here.sh')).toBeNull();
  });
});

describe('#189 — the two reviewed-script-check copies are held together the same way', () => {
  // Same duplication, same reason (TS6059 build boundary), same defence: one
  // fixture table, identical answers, or this goes red.
  it('answers identically on every canonicalisation and drift case', async () => {
    const { createReviewedScriptCheck: shared } = await import('../defence/iron-dome/reviewed-scripts.js');
    const { createReviewedScriptCheck: plugin } = await import('../../plugins/openclaw/interceptor.js');
    const { hashScriptSource } = await import('../defence/iron-dome/reviewed-scripts.js');

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-189-drift-'));
    try {
      const source = '#!/bin/sh\nls -la ~/.ssh\n';
      const pinned = path.join(dir, 'sentry.sh');
      fs.writeFileSync(pinned, source);
      const twin = path.join(dir, 'twin.sh');
      fs.writeFileSync(twin, source);
      const link = path.join(dir, 'link.sh');
      fs.symlinkSync(pinned, link);

      const entries = [
        { path: pinned, sha256: hashScriptSource(source) },
        { path: path.join(dir, 'gone.sh'), sha256: hashScriptSource(source) },
        { path: 'relative.sh', sha256: hashScriptSource(source) },          // dropped: not absolute
        { path: pinned, sha256: 'nothex' },                                  // dropped: bad hash
      ];

      const fixtures: Array<[string, string]> = [
        [pinned, source],                       // exact match
        [pinned, source + '#edited'],           // content drift
        [twin, source],                          // same bytes, different file
        [link, source],                          // symlink to the pin
        ['./sentry.sh', source],                 // relative to cwd
        ['', source],                            // junk path
        [pinned, undefined as unknown as string] // junk source
      ];

      const a = shared(entries, dir);
      const b = plugin(entries, dir);
      for (const [p, s] of fixtures) {
        expect({ path: p, result: a(p, s) }).toEqual({ path: p, result: b(p, s) });
      }
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
