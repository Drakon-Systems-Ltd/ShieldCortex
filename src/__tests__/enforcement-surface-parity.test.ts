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

/**
 * Assembled, not written as literals — this file is scanned by the guard it
 * drives, and since #501's review round these exact paths carry the
 * `disable-action-guard` signal. Same convention, same reason, as
 * `SC01_CATASTROPHIC` in the dist-regression suites.
 */
const PROTECTED_ROOT_DIR = ['', 'etc', 'shieldcortex'].join('/');
const POINTER_PATH = `${PROTECTED_ROOT_DIR}.conf`;
const LOCK_PATH = `${PROTECTED_ROOT_DIR}/policy.json`;
const CLAUDE_SETTINGS = ['.claude', 'settings.json'].join('/');

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

describe('#501 — both enforcement surfaces read the OS-owned policy lock', () => {
  // The #160 lesson, applied to the lock: a lock only one surface consults is a
  // lock that protects neither, because an agent picks the surface that does
  // not. The plugin's config path lives in index.ts (loadConfig/normaliseConfig),
  // not in interceptor.ts, so this block reads that file too.
  const pluginIndexSrc = fs.readFileSync(path.join(repoRoot, 'plugins', 'openclaw', 'index.ts'), 'utf-8');

  it('the Claude Code hook reads the lock through the dist module', () => {
    expect(hookSrc).toMatch(/readPolicyLock/);
    expect(hookSrc).toMatch(/applyPolicyLock/);
    // Through the built module, not a second copy of the precedence rules.
    expect(hookSrc).toMatch(/iron-dome['"],\s*['"]policy-lock\.js['"]/);
  });

  it('the OpenClaw plugin reads the lock through the same dist module', () => {
    expect(pluginIndexSrc).toMatch(/readPolicyLock/);
    expect(pluginIndexSrc).toMatch(/applyPolicyLock/);
  });

  it('the plugin applies the lock AFTER merging the openclaw.json entry', () => {
    // Ordering is the defect: the plugin entry deep-merges OVER the shield
    // config, so a lock applied before the merge leaves an unsigned, same-UID
    // `enabled: false` as the last word — the exact bypass #501 closes.
    //
    // The two calls used to NEST, which made textual order the inverse of
    // execution order and this assertion read as the opposite of the property
    // it defends. SHOULD-FIX-4 unnested them — the merge is cached, the lock is
    // re-applied to it on every load — so source order and execution order now
    // agree. The behavioural proof is `policy-lock-chain-e2e-501`'s "the lock
    // out-ranks the openclaw.json entry" row, through the built plugin; this is
    // the cheap tripwire that names the shape.
    const merge = pluginIndexSrc.indexOf('_mergedConfig = mergeConfigs(normaliseConfig(shieldConfigRaw)');
    const apply = pluginIndexSrc.indexOf('applyPolicyLockToPluginConfig(_mergedConfig)');
    expect(merge).toBeGreaterThan(0);
    expect(apply).toBeGreaterThan(0);
    expect(merge).toBeLessThan(apply);
  });

  it('the plugin applies the lock OUTSIDE the config memo, so a new lock is seen', () => {
    // The #501 review's SHOULD-FIX-4. `policy-lock.ts` states the rule — "no
    // cache on the lock read" — and the plugin was the one surface that broke
    // it, memoising the applied result on the shield config's object identity.
    // Writing `policy.json` does not touch `config.json`, so the lock was read
    // once per gateway process and never again.
    //
    // Two halves, both required: the CACHE GATE must be on the merge, and the
    // interceptor (a second cache behind it) must be rebuilt when the posture
    // it was built with changes.
    expect(pluginIndexSrc).toMatch(/if \(!_mergedConfig \|\| shieldConfigRaw !== _lastShieldConfigRef\)/);
    expect(pluginIndexSrc).toMatch(/return applyPolicyLockToPluginConfig\(_mergedConfig\);/);
    expect(pluginIndexSrc).toMatch(/interceptorGuardPosture/);
    const init = pluginIndexSrc.slice(pluginIndexSrc.indexOf('async function initInterceptor'));
    const load = init.indexOf('await loadConfig()');
    const memo = init.indexOf('interceptorInitAttempted &&');
    expect(load).toBeGreaterThan(0);
    expect(memo).toBeGreaterThan(load);
  });

  it('both surfaces carry an INLINE probe, so a missing dist cannot fail open under a lock', () => {
    for (const [name, src] of [['hook', hookSrc], ['plugin', pluginIndexSrc]] as const) {
      expect({ surface: name, probes: /inlinePolicyLockPresent/.test(src) })
        .toEqual({ surface: name, probes: true });
      // The probe must not depend on the module it exists to survive.
      expect({ surface: name, root: src.includes("'/etc/shieldcortex'") })
        .toEqual({ surface: name, root: true });
    }
  });

  it('the inline strict posture matches STRICT_FAILCLOSED_POSTURE on both surfaces', async () => {
    const { STRICT_FAILCLOSED_POSTURE } = await import('../defence/iron-dome/policy-lock.js');
    const expected = STRICT_FAILCLOSED_POSTURE.actionGuard;
    // Text-match the four values at each copy. A drifting fail-closed posture
    // is a surface that is quietly less safe than its sibling.
    for (const [name, src] of [['hook', hookSrc], ['plugin', pluginIndexSrc]] as const) {
      const block = src.slice(src.indexOf('INLINE_STRICT'), src.indexOf('INLINE_STRICT') + 400);
      expect({ surface: name, enabled: /enabled:\s*true/.test(block) }).toEqual({ surface: name, enabled: expected.enabled });
      expect({ surface: name, enforce: /enforce:\s*true/.test(block) }).toEqual({ surface: name, enforce: expected.enforce });
      expect({ surface: name, auto: /autoApprove:\s*\[\]/.test(block) }).toEqual({ surface: name, auto: expected.autoApprove.length === 0 });
      expect({ surface: name, broker: /broker:\s*\{\s*enabled:\s*false\s*\}/.test(block) })
        .toEqual({ surface: name, broker: expected.broker.enabled === false });
    }
  });

  it('both surfaces refuse to believe a lock reader the inline probe contradicts', () => {
    // The #501 review's BLOCK-1. A reader that LOADS and answers `absent` on a
    // host where the probe can see the lock file used to be believed without a
    // second look — two files the agent owns plus one environment variable took
    // the guard off entirely with a lock on disk. The contradiction check is
    // what closes it, and it has to exist on BOTH surfaces or the agent simply
    // picks the one without it.
    for (const [name, src] of [['hook', hookSrc], ['plugin', pluginIndexSrc]] as const) {
      const cross = /'absent'[\s\S]{0,200}?inlinePolicyLockPresent\(\)|inlinePolicyLockPresent\(\)[\s\S]{0,200}?'absent'/.test(src);
      expect({ surface: name, crossChecks: cross }).toEqual({ surface: name, crossChecks: true });
      // `unsupported` is the other non-answer and must be treated the same way.
      expect({ surface: name, unsupported: src.includes("'unsupported'") })
        .toEqual({ surface: name, unsupported: true });
    }
  });

  it('both inline probes resolve the POINTER before the environment seam', () => {
    // The #501 review's BLOCK-2, second consequence: a probe that mirrors only
    // the canonical root answers `false` on a pointer host, so a broken build
    // there failed OPEN — precisely the "delete dist is the bypass" case the
    // probe exists to close. Both copies must read the pointer, and read it
    // first.
    for (const [name, src] of [['hook', hookSrc], ['plugin', pluginIndexSrc]] as const) {
      expect({ surface: name, pointer: src.includes(`'${POINTER_PATH}'`) })
        .toEqual({ surface: name, pointer: true });
      const probe = src.slice(src.indexOf('function inlinePolicyLockPresent'));
      const pointerAt = probe.indexOf('inlinePointerRoot()');
      const envAt = probe.indexOf('SHIELDCORTEX_PROTECTED_ROOT');
      expect({ surface: name, ordered: pointerAt > 0 && envAt > 0 && pointerAt < envAt })
        .toEqual({ surface: name, ordered: true });
    }
  });

  it('the shared lock reader carries its safety rails with the implementation', () => {
    const shared = fs.readFileSync(path.join(repoRoot, 'src', 'defence', 'iron-dome', 'policy-lock.ts'), 'utf-8');
    expect(shared).toMatch(/export function readPolicyLock/);
    expect(shared).toMatch(/export function applyPolicyLock/);
    expect(shared).toMatch(/STRICT_FAILCLOSED_POSTURE/);
    // Never throws — a reader that throws takes the guard down with it.
    expect(shared).toMatch(/Never throws/);
  });
});

describe('#227 — both enforcement surfaces consult the session action lease', () => {
  it('the Claude Code hook calls evaluateToolCallLease before the allow branch', () => {
    expect(hookSrc).toMatch(/evaluateToolCallLease/);
    // The refusal must precede every approval affordance: the lease CALL SITE
    // (not the loader definitions) has to appear in the main flow BEFORE the
    // one-shot approvals consumption call site.
    expect(hookSrc.indexOf('lease.evaluateToolCallLease(')).toBeGreaterThan(0);
    expect(hookSrc.indexOf('lease.evaluateToolCallLease(')).toBeLessThan(hookSrc.indexOf('approvals.consumeApproval('));
  });

  it('the OpenClaw interceptor applies checkActionLease before the allow branch', () => {
    expect(pluginSrc).toMatch(/checkActionLease/);
    expect(pluginSrc.indexOf('checkActionLease?.(')).toBeLessThan(pluginSrc.indexOf("if (v.decision === 'allow')"));
  });

  it('both surfaces protect the decisions ledger in their pattern tables', () => {
    expect(hookSrc).toMatch(/touch-decisions-ledger/);
    const guardSrc = fs.readFileSync(path.join(repoRoot, 'src', 'defence', 'iron-dome', 'tool-action-guard.ts'), 'utf-8');
    expect(guardSrc).toMatch(/touch-decisions-ledger/);
  });
});

describe("#501 — the lock's own attack surface is signalled on BOTH fallback tables", () => {
  // The review's SHOULD-FIX-7. #501 added a privileged artefact and two
  // environment seams and gave the Action Guard no signal for any of them:
  // repointing the reader scored `allow`, deleting the lock scored a generic
  // `file-delete`, and `~/.claude/settings.json` — the same-UID file whose
  // `env` stanza DELIVERS the BLOCK-1 variable — scored nothing at all.
  //
  // Defence in depth, not the boundary itself. But the parity question is
  // whether the signals exist on both outage tables and whether a drift test
  // would catch them diverging, and until now the answer to both was no.

  /** The `{ re: …, signal: … }` rows of a FALLBACK_DANGEROUS_PATTERNS table. */
  function fallbackRows(src: string): string[] {
    const start = src.indexOf('const FALLBACK_DANGEROUS_PATTERNS');
    expect(start).toBeGreaterThan(0);
    const end = src.indexOf('\n];', start);
    expect(end).toBeGreaterThan(start);
    return src.slice(start, end).split('\n').map((l) => l.trim()).filter((l) => l.startsWith('{ re:'));
  }

  it('the two outage tables are row-for-row identical', () => {
    // Same shape as the #160 resolver drift test, for the same reason: a fix
    // that lands on one copy and not the other is this repo's recurring bug.
    // Text equality is the right instrument HERE (unlike for the resolvers,
    // which are compared behaviourally) because these rows ARE their text — a
    // regex differing by one character is a surface that answers differently,
    // and there is no behaviour to run without eval.
    expect(fallbackRows(hookSrc)).toEqual(fallbackRows(pluginSrc));
  });

  it('both tables carry the #501 shapes, at the disable-action-guard tier', () => {
    const required: Array<[string, RegExp]> = [
      ['the two env seams', /SHIELDCORTEX_\(\?:DIST_ROOT\|PROTECTED_ROOT\)/],
      ['the protected root', /etc\\\/shieldcortex/],
      ['the Claude Code settings file', /\\\.claude\[/],
    ];
    for (const [name, src] of [['hook', hookSrc], ['interceptor', pluginSrc]] as const) {
      const rows = fallbackRows(src);
      for (const [what, shape] of required) {
        const row = rows.find((r) => shape.test(r));
        expect({ surface: name, what, found: row !== undefined })
          .toEqual({ surface: name, what, found: true });
        expect({ surface: name, what, tier: /signal: 'disable-action-guard'/.test(row ?? '') })
          .toEqual({ surface: name, what, tier: true });
      }
    }
  });

  it('the REAL guard answers disable-action-guard on every one of those shapes', async () => {
    // One fixture table, the shipped classifier. The fallback tables above only
    // ever run during an outage; this is the row that says the signal exists at
    // all. Every one of these scored `allow` — or, for the delete, a generic
    // `file-delete` — before this fix round.
    const { evaluateToolCall } = await import('../defence/iron-dome/tool-action-guard.js');
    const home = os.homedir();
    const del = ['r', 'm'].join('');
    const fixtures: Array<[string, Record<string, unknown>]> = [
      ['Bash', { command: `SHIELDCORTEX_DIST_ROOT=/tmp/fake node ${home}/.claude/hooks/pre-tool-hook.mjs` }],
      ['Bash', { command: 'export SHIELDCORTEX_PROTECTED_ROOT=/tmp/empty' }],
      ['Bash', { command: `${del} ${LOCK_PATH}` }],
      ['Write', { file_path: LOCK_PATH, content: '{}' }],
      ['Write', { file_path: POINTER_PATH, content: 'root=/tmp/x' }],
      ['Edit', { file_path: `${home}/${CLAUDE_SETTINGS}`, old_string: 'a', new_string: 'b' }],
      ['Write', { file_path: `~/${CLAUDE_SETTINGS}`, content: '{}' }],
    ];
    for (const [tool, args] of fixtures) {
      const v = evaluateToolCall(tool, args);
      expect({ tool, args, signalled: (v.signals ?? []).includes('disable-action-guard') })
        .toEqual({ tool, args, signalled: true });
      expect({ tool, args, decision: v.decision }).not.toEqual({ tool, args, decision: 'allow' });
    }
  });

  it('naming those paths in prose or inside a URL is still not access', async () => {
    // The carve-outs the PATH_TARGET classifier already gives every other path
    // rule. Without this row the new signals would be a false-positive factory
    // in exactly the place the product documents itself.
    const { evaluateToolCall } = await import('../defence/iron-dome/tool-action-guard.js');
    for (const command of [
      `echo "the lock lives at ${LOCK_PATH}"`,
      `curl https://example.com${LOCK_PATH}`,
    ]) {
      const v = evaluateToolCall('Bash', { command });
      expect({ command, signalled: (v.signals ?? []).includes('disable-action-guard') })
        .toEqual({ command, signalled: false });
    }
  });
});
