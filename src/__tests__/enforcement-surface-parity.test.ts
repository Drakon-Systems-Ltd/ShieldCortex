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
    // Text-match the five values at each copy. A drifting fail-closed posture
    // is a surface that is quietly less safe than its sibling — #522 (GPT-6
    // round-6, item 1) was exactly that: both inline copies pinned four keys
    // while the dist constant pinned five.
    for (const [name, src] of [['hook', hookSrc], ['plugin', pluginIndexSrc]] as const) {
      const block = src.slice(src.indexOf('INLINE_STRICT'), src.indexOf('INLINE_STRICT') + 400);
      expect({ surface: name, enabled: /enabled:\s*true/.test(block) }).toEqual({ surface: name, enabled: expected.enabled });
      expect({ surface: name, enforce: /enforce:\s*true/.test(block) }).toEqual({ surface: name, enforce: expected.enforce });
      expect({ surface: name, auto: /autoApprove:\s*\[\]/.test(block) }).toEqual({ surface: name, auto: expected.autoApprove.length === 0 });
      expect({ surface: name, broker: /broker:\s*\{\s*enabled:\s*false\s*\}/.test(block) })
        .toEqual({ surface: name, broker: expected.broker.enabled === false });
      expect({ surface: name, reviewed: /reviewedScripts:\s*\[\]/.test(block) })
        .toEqual({ surface: name, reviewed: expected.reviewedScripts.length === 0 });
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

describe('#509 R4-1 — the guard self-protection floor is ONE list, duplicated verbatim', () => {
  const hermesClientSrc = fs.readFileSync(path.join(repoRoot, 'plugins', 'hermes', 'shieldcortex', 'sc_client.py'), 'utf-8');

  function listAfter(src: string, marker: RegExp): string[] {
    const m = marker.exec(src);
    expect(m).not.toBeNull();
    const body = src.slice(m!.index + m![0].length);
    const close = body.search(/[\])]/);
    return [...body.slice(0, close).matchAll(/['"]([a-z-]+)['"]/g)].map((x) => x[1]);
  }

  it('the hook fallback, the OpenClaw plugin and the Hermes client carry exactly the exported list', async () => {
    const { GUARD_SELF_PROTECTION_SIGNALS } = await import('../defence/iron-dome/tool-action-guard.js');
    const canonical = [...GUARD_SELF_PROTECTION_SIGNALS];
    expect(canonical).toEqual(['touch-approval-store', 'touch-decisions-ledger', 'touch-guard-config', 'disable-action-guard']);
    expect(listAfter(hookSrc, /const FALLBACK_SELF_PROTECTION_SIGNALS = \[/)).toEqual(canonical);
    expect(listAfter(pluginSrc, /export const SELF_PROTECTION_SIGNALS: readonly string\[\] = \[/)).toEqual(canonical);
    expect(listAfter(hermesClientSrc, /^SELF_PROTECTION_SIGNALS = \(/m)).toEqual(canonical);
  });

  it('every surface consults the floor before its shadow/advisory allow', () => {
    expect(hookSrc).toMatch(/if \(shadow && !unscannedBlock && !selfProtected\)/);
    expect(hookSrc).toMatch(/if \(!cfg\.enforce && !unscannedBlock && !selfProtected\)/);
    expect(hookSrc).toMatch(/if \(!cfg\.enforce && !selfProtectSignal\)/);
    expect(pluginSrc).toMatch(/const selfProtected = isSelfProtectionVerdict\(v\.signals\);/);
    expect(pluginSrc).toMatch(/!actionGuardCfg\.enforce && !unscannedBlock && !selfProtected\)/);
    expect(pluginSrc).toMatch(/!actionGuardCfg\.enforce && !selfProtectSignal/);
  });

  it('r5 finding 3: every auto-approval and failure-allow exit consults the floor, in both planes', () => {
    expect(hookSrc).toMatch(/if \(autoApprove\.length > 0 && !unscannedBlock && !selfProtected\)/);
    expect(hookSrc).toMatch(/brokered\?\.outcome === 'pre_clear' && !unscannedBlock && !selfProtected/);
    expect(pluginSrc).toMatch(/if \(autoApprove\.length > 0 && !unscannedBlock && !selfProtected\)/);
    expect(pluginSrc).toMatch(/brokered\?\.outcome === 'pre_clear' && !unscannedBlock && !selfProtected/);
    expect(pluginSrc).toMatch(/const deny = failAction === 'deny' \|\| brokerDenies \|\| selfProtected;/);
    expect(pluginSrc).toMatch(/const failAction: FailureAction = selfProtected \? 'deny' : config\.failurePolicy\[severity\];/);
    expect(pluginSrc).toMatch(/config\.failurePolicy\.high === 'allow' && !selfProtectSignal \? 'allow' : 'deny'/);
  });

  it('every hook fallback row carrying a floor signal is also a dangerous row (the outage scan sees it)', () => {
    for (const sig of ['touch-approval-store', 'touch-decisions-ledger', 'touch-guard-config', 'disable-action-guard']) {
      expect({ sig, inHook: hookSrc.includes(`signal: '${sig}'`), inPlugin: pluginSrc.includes(`signal: '${sig}'`) })
        .toEqual({ sig, inHook: true, inPlugin: true });
    }
  });
});

describe('#509 r5 finding 9 — the Hermes outage floor DECIDES like the core floor on the same inputs', () => {
  // Comparing signal names let the Hermes fallback miss whole rows (the
  // harness settings file, the policy lock) while the names still matched.
  // So this runs the REAL Hermes pre_tool_call — scanner unavailable,
  // SHIELDCORTEX_ENFORCE=0 (advisory) — over a shared table and compares its
  // block/allow with whether the core classifier puts the same command on
  // the self-protection floor.
  const TABLE = [
    'echo {} > ~/.claude/settings.json',
    'echo {} > /etc/shieldcortex/policy.json',
    'echo {} > ~/.openclaw/openclaw.json',
    'SHIELDCORTEX_DIST_ROOT=/tmp/evil shieldcortex doctor',
    'echo {} >> ~/.shieldcortex/approvals/guard-readiness-transitions.jsonl',
    'cp forged.json ~/.shieldcortex/approvals/guard-readiness.json',
    'echo {} > ~/.shieldcortex/config.json',
    'echo x >> ~/.shieldcortex/DECISIONS.md',
    'shieldcortex config --action-guard-disable',
    'npm uninstall -g shieldcortex',
    'cat ~/.claude/settings.json',
    'ls /etc/shieldcortex',
    'sudo systemctl stop ssh',
    'ls -la',
    // #509 r6 S2: the r5 classifier shapes (and the N1 false positives, which
    // must stay off the floor in an outage too).
    'mv ~/.shieldcortex /tmp/x',
    'sudo mv "$HOME/.shieldcortex/" /tmp/x',
    'cp -r /tmp/forged/. ~/.shieldcortex/',
    'rmdir ~/.shieldcortex/approvals',
    'cd ~/.shieldcortex; printf x > approvals/y',
    'cd ~/.shieldcortex && echo {} > config.json',
    'pushd /home/u/.shieldcortex/ && tee leases/x < /tmp/y',
    'cd ~/.shieldcortex; mv * /tmp/x',
    'npm install --prefix ~/.shieldcortex/',
    'echo "rm ~/.shieldcortex"',
    'mv ~/notes.txt /tmp/x',
    'cd /tmp/build && mv ./* /tmp/out',
  ];
  /** Stricter than the core ON PURPOSE: during an outage every fallback (hook,
   *  OpenClaw, Hermes) holds any access to the approval store, reads included
   *  — the #89 read carve-out lives in the core only. Fail-closed, so it is
   *  asserted rather than compared. */
  const STRICTER_IN_OUTAGE = ['cat ~/.shieldcortex/approvals/approvals.json', 'cd ~/.shieldcortex && ls approvals'];

  it('Hermes (outage, advisory) blocks exactly the commands the core classifier puts on the floor', async () => {
    const { evaluateToolCall, GUARD_SELF_PROTECTION_SIGNALS } = await import('../defence/iron-dome/tool-action-guard.js');
    const core = TABLE.map((command) => ({
      command,
      floor: evaluateToolCall('Bash', { command }).signals.some((s: string) => GUARD_SELF_PROTECTION_SIGNALS.includes(s)),
    }));
    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-parity-hermes-'));
    const script = [
      'import json, sys',
      `sys.path.insert(0, ${JSON.stringify(path.join(repoRoot, 'plugins', 'hermes'))})`,
      `sys.path.insert(0, ${JSON.stringify(path.join(repoRoot, 'plugins', 'hermes', 'shieldcortex'))})`,
      'import shieldcortex as plugin',
      'from sc_client import ActionGuardVerdict',
      'plugin.evaluate_tool_call = lambda *a, **k: ActionGuardVerdict("allow", [], "scanner unavailable", available=False)',
      'hooks = {}',
      'class Ctx:',
      '    def register_hook(self, name, fn): hooks[name] = fn',
      'plugin.register(Ctx())',
      'table = json.loads(sys.stdin.read())',
      'print(json.dumps([{"command": c, "floor": hooks["pre_tool_call"]("terminal", {"command": c}) is not None} for c in table]))',
    ].join('\n');
    const { spawnSync } = await import('node:child_process');
    try {
      const run = spawnSync('python3', ['-c', script], {
        input: JSON.stringify([...TABLE, ...STRICTER_IN_OUTAGE]),
        env: { ...process.env, HOME: tmpHome, SHIELDCORTEX_ENFORCE: '0' },
        encoding: 'utf8',
        timeout: 60_000,
      });
      expect({ status: run.status, stderr: run.status === 0 ? '' : run.stderr }).toEqual({ status: 0, stderr: '' });
      const hermes = JSON.parse(run.stdout.trim().split('\n').pop() as string) as Array<{ command: string; floor: boolean }>;
      expect(hermes.slice(0, TABLE.length)).toEqual(core);
      expect(hermes.slice(TABLE.length)).toEqual(STRICTER_IN_OUTAGE.map((command) => ({ command, floor: true })));
      // The table is not vacuous: both answers occur.
      expect(core.some((c) => c.floor) && core.some((c) => !c.floor)).toBe(true);
    } finally {
      fs.rmSync(tmpHome, { recursive: true, force: true });
    }
  });

  // #509 r6 S2: the same table through the OTHER two outage fallbacks — the
  // OpenClaw interceptor with its evaluator throwing, and the Claude Code hook
  // with no dist to load — both advisory, so only the floor holds a call.
  it('OpenClaw (evaluator down) and the Claude Code hook (no dist) hold exactly the same commands, advisory', async () => {
    const { evaluateToolCall, GUARD_SELF_PROTECTION_SIGNALS } = await import('../defence/iron-dome/tool-action-guard.js');
    const { createInterceptor, DEFAULT_CONFIG } = await import('../../plugins/openclaw/interceptor.js');
    const expected = [
      ...TABLE.map((command) => ({
        command,
        floor: evaluateToolCall('Bash', { command }).signals.some((s: string) => GUARD_SELF_PROTECTION_SIGNALS.includes(s)),
      })),
      ...STRICTER_IN_OUTAGE.map((command) => ({ command, floor: true })),
    ];
    const okPipeline = () => ({
      allowed: true,
      firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
      trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
    });
    const openclaw = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, enforce: false, autoApprove: [] } } as never,
      okPipeline as never,
      { evaluateToolCall: (() => { throw new Error('evaluator down'); }) as never },
    );
    const openclawDecisions: Array<{ command: string; floor: boolean }> = [];
    for (const { command } of expected) {
      const held = await openclaw.handleToolCall({ toolName: 'Bash', arguments: { command } }).then(() => false, () => true);
      openclawDecisions.push({ command, floor: held });
    }
    expect(openclawDecisions).toEqual(expected);

    // OpenClaw's native `process` tool: its typed-shell payload keys are part
    // of the outage surface too.
    for (const key of ['data', 'text', 'literal']) {
      const held = await openclaw.handleToolCall({
        toolName: 'process',
        arguments: { action: 'write', sessionId: 'shell-1', [key]: 'cd ~/.shieldcortex; printf x > approvals/y\n' },
      }).then(() => false, () => true);
      const ordinary = await openclaw.handleToolCall({
        toolName: 'process',
        arguments: { action: 'write', sessionId: 'shell-1', [key]: 'ls -la\n' },
      }).then(() => false, () => true);
      expect({ key, held, ordinary }).toEqual({ key, held: true, ordinary: false });
    }

    const tmpHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-parity-hook-'));
    const emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-parity-dist-'));
    const { spawnSync } = await import('node:child_process');
    try {
      fs.mkdirSync(path.join(tmpHome, '.shieldcortex'), { recursive: true });
      fs.writeFileSync(path.join(tmpHome, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: false } }));
      const hookDecisions = expected.map(({ command }) => {
        const run = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'pre-tool-hook.mjs')], {
          input: JSON.stringify({ permission_mode: 'default', tool_name: 'Bash', tool_input: { command } }),
          env: { ...process.env, HOME: tmpHome, SHIELDCORTEX_DIST_ROOT: emptyDist, SHIELDCORTEX_CONFIG_DIR: path.join(tmpHome, '.shieldcortex') },
          encoding: 'utf8',
          timeout: 30_000,
        });
        const out = run.stdout.trim();
        const decision = out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : 'allow';
        return { command, floor: decision === 'ask' || decision === 'deny' };
      });
      expect(hookDecisions).toEqual(expected);
    } finally {
      fs.rmSync(tmpHome, { recursive: true, force: true });
      fs.rmSync(emptyDist, { recursive: true, force: true });
    }
  }, 120_000);
});

// #509 round 7 (Tars, PR #610): "enforce when ready" must mean the same thing
// on both surfaces. The Claude Code hook (BUILT, driven end to end) and the
// OpenClaw interceptor (real evaluator, real guard-readiness bound to its own
// adapter) answer the SAME inputs in the same readiness state, compared by
// the DECISION each actually made — allowed / card (ask) / blocked — never by
// config. Each surface's readiness is its own: the promoted state seeds each
// adapter's own pinned evidence and reviewed-evidence registry.
describe('#509 r7 — hook and interceptor decide alike in shadow, promoted and demoted states', () => {
  const DAY = 24 * 60 * 60 * 1000;
  const REAL_DIST = path.join(repoRoot, 'dist');
  const CATASTROPHIC_MARK = 'sc-parity-catastrophic-tier';
  const CATASTROPHIC_VERDICT = { decision: 'block', severity: 'catastrophic', family: 'fs', action: 'recursive-delete', reason: 'catastrophic (parity fixture)', signals: ['recursive-force-delete'] };
  const INPUTS: Array<[string, Record<string, unknown>]> = [
    ['dangerous', { command: 'sudo modprobe softdog' }],
    ['benign', { command: 'ls -la' }],
    ['self-protection floor', { command: `echo {} > ~/${['.shieldcortex', 'approvals', 'parity-r7.json'].join('/')}` }],
    ['unscanned (schema-invalid)', { command: 'ls', evil: 'x' }],
    // r8 (N3): the catastrophic tier and a real session-lease freeze (a FROZEN
    // record in the isolated DECISIONS.md) — floors in every state. The
    // catastrophic command text cannot be written into this file (the Action
    // Guard refuses it), so a marker stands for it and BOTH surfaces' evaluator
    // gives it the guard's verdict for that tier (see CATASTROPHIC_VERDICT).
    ['catastrophic', { command: CATASTROPHIC_MARK }],
    ['lease (frozen scope)', { command: 'npm publish' }],
  ];

  /** r8 (N3): 'hook-only' / 'openclaw-only' — ONE surface's evidence is
   *  seeded, and BOTH hold reviewed effectiveness evidence, so the other
   *  surface would promote if it counted that evidence. */
  type State = 'shadow' | 'promoted' | 'demoted' | 'hook-only' | 'openclaw-only';

  async function decisions(state: State): Promise<{ hook: Record<string, string>; openclaw: Record<string, string> }> {
    const reviewedState = state === 'promoted' || state === 'hook-only' || state === 'openclaw-only';
    const { pathToFileURL } = await import('node:url');
    const { spawnSync } = await import('node:child_process');
    const readiness = await import('../defence/iron-dome/guard-readiness.js');
    const { evaluateToolCall } = await import('../defence/iron-dome/tool-action-guard.js');
    const lease = await import('../defence/iron-dome/session-lease-store.js');
    const { createInterceptor, DEFAULT_CONFIG } = await import('../../plugins/openclaw/interceptor.js');
    const { buildReadinessRuntime } = await import('../../plugins/openclaw/index.js');
    const distReadiness = await import(pathToFileURL(path.join(REAL_DIST, 'defence', 'iron-dome', 'guard-readiness.js')).href);

    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-parity-r7-'));
    const distRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-parity-r7-dist-'));
    const sc = path.join(home, '.shieldcortex');
    const audit = path.join(sc, 'audit');
    const saved = { HOME: process.env.HOME, CFG: process.env.SHIELDCORTEX_CONFIG_DIR, AUDIT: process.env.SHIELDCORTEX_AUDIT_DIR };
    process.env.HOME = home;
    process.env.SHIELDCORTEX_CONFIG_DIR = sc;
    process.env.SHIELDCORTEX_AUDIT_DIR = audit;
    try {
      fs.mkdirSync(audit, { recursive: true });
      // The hook's dist: real modules, a recording webhook (nothing leaves the
      // box), and — for 'promoted' only — a registry holding reviewed evidence
      // for the hook's pin (a build that ships it; never config).
      const realIron = path.join(REAL_DIST, 'defence', 'iron-dome');
      const shimIron = path.join(distRoot, 'defence', 'iron-dome');
      fs.mkdirSync(shimIron, { recursive: true });
      for (const f of fs.readdirSync(realIron)) {
        if (!f.endsWith('.js') || f === 'webhook-notify-channel.js' || f === 'guard-readiness.js' || f === 'tool-action-guard.js') continue;
        fs.writeFileSync(path.join(shimIron, f), `export * from ${JSON.stringify(pathToFileURL(path.join(realIron, f)).href)};\n`);
      }
      const realReadiness = JSON.stringify(pathToFileURL(path.join(realIron, 'guard-readiness.js')).href);
      fs.writeFileSync(path.join(shimIron, 'guard-readiness.js'), [
        `import * as real from ${realReadiness};`,
        `export * from ${realReadiness};`,
        'const pin = real.currentReadinessPin();',
        `const REVIEWED = ${reviewedState} && pin ? [{ ...pin, reviewedAt: new Date(Date.now() - 86400000).toISOString(), reviewedBy: 'parity fixture', reference: 'parity fixture', cases: 60 }] : [];`,
        'export function resolveReadiness(opts) { return real.resolveReadiness({ ...opts, effectivenessRegistry: REVIEWED }); }',
      ].join('\n'));
      // The real evaluator, except the catastrophic marker (see INPUTS).
      const realGuard = JSON.stringify(pathToFileURL(path.join(realIron, 'tool-action-guard.js')).href);
      fs.writeFileSync(path.join(shimIron, 'tool-action-guard.js'), [
        `import * as real from ${realGuard};`,
        `export * from ${realGuard};`,
        `export function evaluateToolCall(tool, args, ...rest) { return args?.command === ${JSON.stringify(CATASTROPHIC_MARK)} ? ${JSON.stringify(CATASTROPHIC_VERDICT)} : real.evaluateToolCall(tool, args, ...rest); }`,
      ].join('\n'));
      // A standing freeze on npm publishes: the real session-lease plane refuses
      // `npm publish` on both surfaces.
      fs.mkdirSync(sc, { recursive: true });
      fs.writeFileSync(path.join(sc, 'DECISIONS.md'), '| FROZEN | 2026-09-28 | nobody publishes to npm until review |\n');
      fs.writeFileSync(path.join(shimIron, 'webhook-notify-channel.js'),
        "export function createWebhookNotifyChannel() { return { name: 'webhook', async send() { return { delivered: true }; } }; }\n");
      const notify = { enabled: true, webhookUrl: 'https://hooks.example.invalid/parity' };
      fs.writeFileSync(path.join(sc, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true, readinessGate: true, notify } }));

      const pins = { hook: distReadiness.currentReadinessPin(), openclaw: readiness.currentReadinessPin('openclaw-interceptor')! };
      let seq = 0;
      const seed = (adapter: 'claude-code-hook' | 'openclaw-interceptor', pin: unknown) => {
        const now = Date.now();
        const lines: string[] = [];
        const row = (r: Record<string, unknown>) => { seq += 1; lines.push(JSON.stringify({ auditEventId: `p${seq}`, readinessPin: pin, ...r })); };
        for (let i = 0; i < 1000; i += 1) {
          const stop = i < 5;
          row({ ts: new Date(now - 8 * DAY + Math.floor((i * 8 * DAY) / 1000) + 1000).toISOString(), type: 'intercept', origin: adapter, tool: 'Bash', severity: stop ? 'high' : 'low', action: stop ? 'require_approval' : 'allow', outcome: stop ? 'would_hold' : 'allowed' });
        }
        for (let i = 0; i < 25; i += 1) {
          const t = now - DAY + i * 60_000;
          row({ ts: new Date(t).toISOString(), type: 'approval_reach', origin: adapter, reachId: `${adapter}${i}`, attemptId: `${adapter}a${i}`, phase: 'request' });
          row({ ts: new Date(t + 30_000).toISOString(), type: 'approval_reach', origin: adapter, reachId: `${adapter}${i}`, attemptId: `${adapter}a${i}`, phase: 'answer', answer: 'approve' });
        }
        // Rows are spread over 9 days: one file per day, as the audit writes them.
        for (const l of lines) {
          const day = String(JSON.parse(l).ts).slice(0, 10);
          fs.appendFileSync(path.join(audit, `realtime-${day}.jsonl`), `${l}\n`);
        }
      };
      for (const adapter of ['claude-code-hook', 'openclaw-interceptor'] as const) {
        const journal = readiness.transitionsPathFor(readiness.readinessPaths({ home, adapter }));
        fs.mkdirSync(path.dirname(journal), { recursive: true });
        const entries: Array<Record<string, unknown>> = [{ ts: new Date(Date.now() - 30 * DAY).toISOString(), event: 'init', to: 'shadow' }];
        if (state === 'demoted') {
          entries.push({ ts: new Date(Date.now() - 3 * DAY).toISOString(), event: 'promote', to: 'enforcing' });
          entries.push({ ts: new Date(Date.now() - 2 * DAY).toISOString(), event: 'demote', to: 'shadow', reason: 'parity fixture' });
        }
        fs.writeFileSync(journal, entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
      }
      if (state === 'promoted' || state === 'hook-only') seed('claude-code-hook', pins.hook);
      if (state === 'promoted' || state === 'openclaw-only') seed('openclaw-interceptor', pins.openclaw);

      const hook: Record<string, string> = {};
      for (const [name, input] of INPUTS) {
        const run = spawnSync(process.execPath, [path.join(repoRoot, 'scripts', 'pre-tool-hook.mjs')], {
          input: JSON.stringify({ session_id: 'parity-r7', cwd: '/tmp', hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name: 'Bash', tool_input: input }),
          env: { ...process.env, HOME: home, USERPROFILE: home, SHIELDCORTEX_DIST_ROOT: distRoot, SHIELDCORTEX_CONFIG_DIR: sc },
          encoding: 'utf8',
          timeout: 30_000,
        });
        const out = run.stdout.trim();
        const d = out ? JSON.parse(out).hookSpecificOutput?.permissionDecision : undefined;
        hook[name] = d === 'ask' ? 'card' : d === 'deny' ? 'blocked' : 'allowed';
      }

      const okPipeline = () => ({
        allowed: true,
        firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
        trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
      });
      const rt = buildReadinessRuntime(readiness as never, notify, {
        home,
        effectivenessRegistry: reviewedState
          ? [{ ...pins.openclaw, reviewedAt: new Date(Date.now() - DAY).toISOString(), reviewedBy: 'parity fixture', reference: 'parity fixture', cases: 60 }]
          : [],
        deliver: async () => ({ deliveredVia: 'webhook', attempts: [{ channel: 'webhook', result: { delivered: true } }] }),
      });
      const openclawGuard = createInterceptor(
        { ...DEFAULT_CONFIG, actionGuard: { ...DEFAULT_CONFIG.actionGuard, enabled: true, enforce: true, readinessGate: true, notify }, logger: { info: () => {}, warn: () => {} } } as never,
        okPipeline as never,
        {
          evaluateToolCall: ((tool: string, args: Record<string, unknown>, ...rest: unknown[]) => (args?.command === CATASTROPHIC_MARK
            ? CATASTROPHIC_VERDICT
            : (evaluateToolCall as (...a: unknown[]) => unknown)(tool, args, ...rest))) as never,
          // As the plugin wires it (index.ts): the real fs-backed lease plane.
          checkActionLease: (tool: string, args: Record<string, unknown>, sessionId?: string) =>
            lease.evaluateToolCallLease(tool, args, { self: sessionId ?? '' }),
          readiness: rt,
        } as never,
      );
      const openclaw: Record<string, string> = {};
      for (const [name, input] of INPUTS) {
        let asked = false;
        const res = await openclawGuard.handleToolCall({
          toolName: 'Bash', arguments: input, requireApproval: async () => { asked = true; return false; },
        } as never).then(() => 'ok', () => 'threw');
        openclaw[name] = asked ? 'card' : res === 'ok' ? 'allowed' : 'blocked';
      }
      return { hook, openclaw };
    } finally {
      if (saved.HOME === undefined) delete process.env.HOME; else process.env.HOME = saved.HOME;
      if (saved.CFG === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR; else process.env.SHIELDCORTEX_CONFIG_DIR = saved.CFG;
      if (saved.AUDIT === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR; else process.env.SHIELDCORTEX_AUDIT_DIR = saved.AUDIT;
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(distRoot, { recursive: true, force: true });
    }
  }

  const FLOORS = { 'self-protection floor': 'card', 'unscanned (schema-invalid)': 'card', catastrophic: 'blocked', 'lease (frozen scope)': 'blocked' };
  const SHADOWED = { dangerous: 'allowed', benign: 'allowed', ...FLOORS };
  const ENFORCED = { dangerous: 'card', benign: 'allowed', ...FLOORS };
  const EXPECTED: Record<'shadow' | 'promoted' | 'demoted', Record<string, string>> = {
    shadow: SHADOWED,
    promoted: ENFORCED,
    demoted: SHADOWED,
  };

  for (const state of ['shadow', 'promoted', 'demoted'] as const) {
    it(`${state}: the same inputs get the same decision on both surfaces`, async () => {
      const { hook, openclaw } = await decisions(state);
      expect(openclaw).toEqual(hook);
      expect(hook).toEqual(EXPECTED[state]);
    }, 120_000);
  }

  // r8 (N3): readiness is per surface. One surface's evidence never promotes
  // the other, even when both hold reviewed effectiveness evidence — and the
  // floors hold on the one still watching.
  it('hook promoted, OpenClaw not: only the hook enforces the dangerous call', async () => {
    const { hook, openclaw } = await decisions('hook-only');
    expect(hook).toEqual(ENFORCED);
    expect(openclaw).toEqual(SHADOWED);
  }, 120_000);

  it('OpenClaw promoted, hook not: only OpenClaw enforces the dangerous call', async () => {
    const { hook, openclaw } = await decisions('openclaw-only');
    expect(openclaw).toEqual(ENFORCED);
    expect(hook).toEqual(SHADOWED);
  }, 120_000);
});
