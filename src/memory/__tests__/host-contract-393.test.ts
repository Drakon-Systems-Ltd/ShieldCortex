/**
 * T1 host contract evidence model (#393).
 *
 * The matrix that used to green-wash: absent host config, unreadable host
 * config, a Hermes-primary box, and "no host runtime at all" must never reach
 * PASS while a bus-law contract is claimed.
 */
import { describe, expect, it } from '@jest/globals';
import {
  evaluateHostContract,
  parseHermesMemoryBlock,
  readInjectModeStrict,
  resolveClaudeCodeEvidence,
  resolveHermesEvidence,
  resolveOpenClawEvidence,
  INJECT_MODES,
  SIDECAR_POSTURE,
  type ArtifactProbe,
  type ClaudeCodeProbe,
  type HermesProbe,
  type HostRuntimeEvidence,
  type OpenClawProbe,
  type OpenClawWorkspaceProbe,
} from '../host-contract.js';
// The runtime emitter's own normalization — parity is a test-pinned law (SOL H5).
import { normalizeInjectMode } from '../../../scripts/lib/inject-pack.mjs';

const NOW = Date.UTC(2026, 7, 26, 12, 0, 0);
const DAY = 24 * 60 * 60 * 1000;
const CTX = { contract: 'sc_only', plane: 'dual_legacy', nowMs: NOW };

function file(p: string, ageDays: number, size = 512): ArtifactProbe {
  return { kind: 'present', path: p, mtimeMs: NOW - ageDays * DAY, size };
}

function ws(over: Partial<OpenClawWorkspaceProbe> = {}): OpenClawWorkspaceProbe {
  return {
    path: '/home/x/.openclaw/workspace',
    agentsMd: { kind: 'absent' },
    memoryFiles: [
      { kind: 'absent', path: '/home/x/.openclaw/workspace/MEMORY.md' },
      { kind: 'absent', path: '/home/x/.openclaw/workspace/memory.md' },
    ],
    ...over,
  };
}

function ocProbe(over: Partial<OpenClawProbe> = {}): OpenClawProbe {
  return {
    config: { kind: 'absent' },
    scHook: 'absent',
    scAutoMemory: false,
    workspaces: [ws()],
    workspaceScanComplete: true,
    declared: false,
    ...over,
  };
}

function ccProbe(over: Partial<ClaudeCodeProbe> = {}): ClaudeCodeProbe {
  return {
    settings: { kind: 'absent' },
    nativeStores: [],
    storeScanComplete: true,
    commandTrust: () => 'resolves',
    declared: false,
    ...over,
  };
}

function hermesProbe(over: Partial<HermesProbe> = {}): HermesProbe {
  return {
    config: { kind: 'absent' },
    profiles: [],
    profileScanComplete: true,
    scPluginInstalled: false,
    nativeArtifacts: [],
    declared: false,
    ...over,
  };
}

const WIRED_SETTINGS = {
  hooks: {
    SessionStart: [{ hooks: [{ type: 'command', command: '/usr/bin/shieldcortex hook session-start' }] }],
  },
};

function verdictFor(runtimes: HostRuntimeEvidence[], over: Partial<Parameters<typeof evaluateHostContract>[0]> = {}) {
  return evaluateHostContract({
    plane: 'dual_legacy',
    injectConfigured: true,
    injectMode: 'start',
    nativeContract: 'sc_only',
    postureRaw: null,
    runtimes,
    nowMs: NOW,
    ...over,
  });
}

describe('OpenClaw evidence', () => {
  it('is not bound when the box carries no OpenClaw config or SC integration', () => {
    const e = resolveOpenClawEvidence(ocProbe(), CTX);
    expect(e.bound).toBe(false);
    expect(e.remediation).toBe('');
  });

  it('resolves Memory Search default-ON when the key is absent', () => {
    const e = resolveOpenClawEvidence(
      ocProbe({ config: { kind: 'present', value: { agents: { defaults: {} } } } }),
      CTX,
    );
    expect(e.bound).toBe(true);
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/default-ON/);
    expect(e.remediation).toMatch(/memorySearch\.enabled=false/);
  });

  it('only proves off on an explicit enabled=false with no per-agent re-enable', () => {
    const e = resolveOpenClawEvidence(
      ocProbe({ config: { kind: 'present', value: { agents: { defaults: { memorySearch: { enabled: false } } } } } }),
      CTX,
    );
    expect(e.nativeBus).toBe('off_proven');
    expect(e.remediation).toBe('');
  });

  it('fails a per-agent re-enable that escapes defaults-off', () => {
    const e = resolveOpenClawEvidence(
      ocProbe({
        config: {
          kind: 'present',
          value: {
            agents: {
              defaults: { memorySearch: { enabled: false } },
              list: [{ name: 'case', memorySearch: { enabled: true } }],
            },
          },
        },
      }),
      CTX,
    );
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/per-agent memorySearch re-enabled for case/);
  });

  it('reports unknown (never off) when openclaw.json is absent but SC is integrated', () => {
    const e = resolveOpenClawEvidence(ocProbe({ scHook: 'complete', scAutoMemory: true }), CTX);
    expect(e.bound).toBe(true);
    expect(e.nativeBus).toBe('unknown');
  });

  it('proves the SC bus only from a complete, current artifact set: never from a bare directory', () => {
    const config = { kind: 'present' as const, value: { agents: { defaults: { memorySearch: { enabled: false } } } } };
    expect(resolveOpenClawEvidence(ocProbe({ config, scHook: 'complete' }), CTX).scBus).toBe('wired_proven');
    expect(resolveOpenClawEvidence(ocProbe({ config, scHook: 'absent' }), CTX).scBus).toBe('not_wired');
    // H1: an empty/partial hook dir is a positive "not delivered", not wiring.
    const incomplete = resolveOpenClawEvidence(ocProbe({ config, scHook: 'incomplete' }), CTX);
    expect(incomplete.scBus).toBe('not_wired');
    expect(incomplete.proof.join(' ')).toMatch(/a directory is not delivery/);
    // Stale content: what would run cannot be proven to be the SC emitter.
    const stale = resolveOpenClawEvidence(ocProbe({ config, scHook: 'stale' }), CTX);
    expect(stale.scBus).toBe('unknown');
    expect(stale.proof.join(' ')).toMatch(/differs from the packaged source/);
    const unreadable = resolveOpenClawEvidence(ocProbe({ config, scHook: 'unreadable' }), CTX);
    expect(unreadable.scBus).toBe('unknown');
    expect(unreadable.proof.join(' ')).toMatch(/pack delivery cannot be proven/);
    // r2 B6: missing packaged source means currency is unattestable — unknown,
    // never wired_proven by default.
    const unverifiable = resolveOpenClawEvidence(ocProbe({ config, scHook: 'unverifiable' }), CTX);
    expect(unverifiable.scBus).toBe('unknown');
    expect(unverifiable.proof.join(' ')).toMatch(/cannot be attested byte-current/);
  });

  it('treats hooks.internal.entries.cortex-memory.enabled=false as not wired, and an unreadable config as unknown', () => {
    const disabled = resolveOpenClawEvidence(
      ocProbe({
        config: {
          kind: 'present',
          value: {
            agents: { defaults: { memorySearch: { enabled: false } } },
            hooks: { internal: { entries: { 'cortex-memory': { enabled: false } } } },
          },
        },
        scHook: 'complete',
      }),
      CTX,
    );
    expect(disabled.scBus).toBe('not_wired');
    expect(disabled.proof.join(' ')).toMatch(/enabled=false/);
    // Config unreadable: full artifacts on disk still cannot prove the host
    // has the hook enabled — unknown, never wired.
    const unreadableCfg = resolveOpenClawEvidence(
      ocProbe({ config: { kind: 'unreadable', detail: 'EACCES' }, scHook: 'complete' }),
      CTX,
    );
    expect(unreadableCfg.scBus).toBe('unknown');
    // Config absent: nothing confirms the host loads hooks at all.
    expect(resolveOpenClawEvidence(ocProbe({ scHook: 'complete' }), CTX).scBus).toBe('unknown');
  });

  it('reports unknown when openclaw.json is unreadable', () => {
    const e = resolveOpenClawEvidence(
      ocProbe({ config: { kind: 'unreadable', detail: 'EACCES: permission denied' } }),
      CTX,
    );
    expect(e.nativeBus).toBe('unknown');
    expect(e.proof.join(' ')).toMatch(/unreadable/);
  });

  it('treats AGENTS.md naming MEMORY.md as the brain as native-on under sc_only only', () => {
    const agentsMd = { kind: 'present' as const, value: 'Always read MEMORY.md at the start of every session.' };
    const off = { kind: 'present' as const, value: { agents: { defaults: { memorySearch: { enabled: false } } } } };
    const scOnly = resolveOpenClawEvidence(ocProbe({ config: off, workspaces: [ws({ agentsMd })] }), CTX);
    expect(scOnly.nativeBus).toBe('on');
    const weaker = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaces: [ws({ agentsMd })] }),
      { ...CTX, contract: 'disable_native_inject' },
    );
    expect(weaker.nativeBus).toBe('off_proven');
  });

  it('fails a MEMORY.md still growing under import_only', () => {
    const e = resolveOpenClawEvidence(
      ocProbe({
        config: { kind: 'present', value: { agents: { defaults: { memorySearch: { enabled: false } } } } },
        workspaces: [ws({ memoryFiles: [file('/home/x/.openclaw/workspace/MEMORY.md', 1, 4096)] })],
      }),
      { ...CTX, plane: 'import_only' },
    );
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/MEMORY\.md written within 7d/);
  });

  it('turns native ON from a live bootstrap memory file under EVERY plane and both contracts — lowercase included, no AGENTS.md wording needed (SOL r2 B1)', () => {
    const off = { kind: 'present' as const, value: { agents: { defaults: { memorySearch: { enabled: false } } } } };
    // The exact r2 false PASS: dual_legacy + sc_only + memorySearch off + live
    // uppercase MEMORY.md used to prove off because the plane gate skipped it.
    const dualUpper = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaces: [ws({ memoryFiles: [file('/home/x/.openclaw/workspace/MEMORY.md', 1, 4096)] })] }),
      CTX,
    );
    expect(dualUpper.nativeBus).toBe('on');
    expect(dualUpper.proof.join(' ')).toMatch(/bootstraps workspace memory files/);
    // Lowercase memory.md escaped every plane before r2.
    const dualLower = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaces: [ws({ memoryFiles: [file('/home/x/.openclaw/workspace/memory.md', 1, 2048)] })] }),
      { ...CTX, contract: 'disable_native_inject' },
    );
    expect(dualLower.nativeBus).toBe('on');
    expect(dualLower.proof.join(' ')).toMatch(/memory\.md written within 7d/);
    // A quiet stale file is not a live brain — off-proof survives it.
    const stale = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaces: [ws({ memoryFiles: [file('/home/x/.openclaw/workspace/memory.md', 40, 2048)] })] }),
      CTX,
    );
    expect(stale.nativeBus).toBe('off_proven');
    // Unreadable bootstrap evidence caps the proof at unknown under any plane.
    const unreadable = resolveOpenClawEvidence(
      ocProbe({
        config: off,
        workspaces: [ws({ memoryFiles: [{ kind: 'unreadable', path: '/home/x/.openclaw/workspace/memory.md', detail: 'EACCES' }] })],
      }),
      CTX,
    );
    expect(unreadable.nativeBus).toBe('unknown');
  });

  it('inspects configured custom and per-agent workspaces, not just the stock one (SOL H4)', () => {
    const off = { kind: 'present' as const, value: { agents: { defaults: { memorySearch: { enabled: false } } } } };
    const brainy = { kind: 'present' as const, value: 'Read MEMORY.md every session — it is your brain.' };
    const custom = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaces: [ws(), ws({ path: '/srv/agents/case-ws', agentsMd: brainy })] }),
      CTX,
    );
    expect(custom.nativeBus).toBe('on');
    expect(custom.proof.join(' ')).toMatch(/case-ws\/AGENTS\.md/);

    const perAgentMemory = resolveOpenClawEvidence(
      ocProbe({
        config: off,
        workspaces: [ws(), ws({ path: '/srv/agents/case-ws', memoryFiles: [file('/srv/agents/case-ws/MEMORY.md', 1, 4096)] })],
      }),
      { ...CTX, plane: 'import_only' },
    );
    expect(perAgentMemory.nativeBus).toBe('on');
  });

  it('demotes off_proven to unknown on unreadable workspace evidence — never PASS past a file it could not read', () => {
    const off = { kind: 'present' as const, value: { agents: { defaults: { memorySearch: { enabled: false } } } } };
    const unreadableAgents = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaces: [ws({ agentsMd: { kind: 'unreadable', detail: 'EACCES' } })] }),
      CTX,
    );
    expect(unreadableAgents.nativeBus).toBe('unknown');
    expect(unreadableAgents.proof.join(' ')).toMatch(/workspace evidence unreadable/);
    expect(unreadableAgents.remediation).toMatch(/readable/);

    const unreadableMemory = resolveOpenClawEvidence(
      ocProbe({
        config: off,
        workspaces: [ws({ memoryFiles: [{ kind: 'unreadable', path: '/home/x/.openclaw/workspace/MEMORY.md', detail: 'EACCES' }] })],
      }),
      { ...CTX, plane: 'import_only' },
    );
    expect(unreadableMemory.nativeBus).toBe('unknown');

    const incompleteScan = resolveOpenClawEvidence(
      ocProbe({ config: off, workspaceScanComplete: false }),
      CTX,
    );
    expect(incompleteScan.nativeBus).toBe('unknown');
    expect(incompleteScan.proof.join(' ')).toMatch(/could not all be enumerated/);
  });
});

describe('Claude Code evidence', () => {
  it('is not bound without settings.json, store evidence, or a declaration', () => {
    expect(resolveClaudeCodeEvidence(ccProbe(), CTX).bound).toBe(false);
  });

  it('binds Claude from native store presence alone — a live store must never vanish from the verdict (SOL H2)', () => {
    const live = resolveClaudeCodeEvidence(
      ccProbe({ nativeStores: [file('/home/x/.claude/projects/p/memory/MEMORY.md', 1)] }),
      CTX,
    );
    expect(live.bound).toBe(true);
    expect(live.nativeBus).toBe('on');
    expect(live.scBus).toBe('not_wired');

    const staleStore = resolveClaudeCodeEvidence(
      ccProbe({ nativeStores: [file('/home/x/.claude/memory/MEMORY.md', 40)] }),
      CTX,
    );
    expect(staleStore.bound).toBe(true);
    expect(staleStore.nativeBus).toBe('unknown');

    const unlistable = resolveClaudeCodeEvidence(ccProbe({ storeScanComplete: false }), CTX);
    expect(unlistable.bound).toBe(true);
    expect(unlistable.nativeBus).toBe('unknown');
  });

  it('proves native off when no memory-tool store exists and SC owns session-start', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({ settings: { kind: 'present', value: WIRED_SETTINGS } }),
      CTX,
    );
    expect(e.nativeBus).toBe('off_proven');
    expect(e.scBus).toBe('wired_proven');
  });

  it('fails when the native memory-tool store was written this week', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({
        settings: { kind: 'present', value: WIRED_SETTINGS },
        nativeStores: [file('/home/x/.claude/projects/p/memory/MEMORY.md', 1)],
      }),
      CTX,
    );
    expect(e.nativeBus).toBe('on');
    expect(e.remediation).toMatch(/Claude Code/);
  });

  it('will not pass a stale native store — present but quiet is unknown, not off', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({
        settings: { kind: 'present', value: WIRED_SETTINGS },
        nativeStores: [file('/home/x/.claude/projects/p/memory/MEMORY.md', 40)],
      }),
      CTX,
    );
    expect(e.nativeBus).toBe('unknown');
  });

  it('reports unknown when the store scan could not complete', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({ settings: { kind: 'present', value: WIRED_SETTINGS }, storeScanComplete: false }),
      CTX,
    );
    expect(e.nativeBus).toBe('unknown');
  });

  it('reports unknown when settings.json is unreadable', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({ settings: { kind: 'unreadable', detail: 'EACCES' } }),
      CTX,
    );
    expect(e.nativeBus).toBe('unknown');
    expect(e.scBus).toBe('unknown');
  });

  it('treats a live CLAUDE.md preamble as native automatic memory on the bus (SOL r2 B5)', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({
        settings: { kind: 'present', value: WIRED_SETTINGS },
        nativeStores: [file('/home/x/.claude/CLAUDE.md', 1)],
      }),
      CTX,
    );
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/CLAUDE\.md preamble/);
    expect(e.remediation).toMatch(/CLAUDE\.md preamble/);
  });

  it('marks the SC bus not wired when SessionStart carries no shieldcortex command', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({ settings: { kind: 'present', value: { hooks: { SessionStart: [{ hooks: [{ command: 'other' }] }] } } } }),
      CTX,
    );
    expect(e.scBus).toBe('not_wired');
  });

  it('accepts only the exact supported command shape — brand-token substrings do not own session-start (SOL H3)', () => {
    const wiredWith = (command: string) =>
      resolveClaudeCodeEvidence(
        ccProbe({
          settings: {
            kind: 'present',
            value: { hooks: { SessionStart: [{ hooks: [{ type: 'command', command }] }] } },
          },
        }),
        CTX,
      ).scBus;
    // Supported shapes: bare or absolute binary, quoted path, env prefix.
    expect(wiredWith('shieldcortex hook session-start')).toBe('wired_proven');
    expect(wiredWith('/usr/local/bin/shieldcortex hook session-start')).toBe('wired_proven');
    expect(wiredWith('"/opt/my tools/shieldcortex" hook session-start')).toBe('wired_proven');
    expect(wiredWith('SHIELDCORTEX_RECALL_ENFORCE=1 shieldcortex hook session-start')).toBe('wired_proven');
    // Adversarial / stale shapes that the substring match used to accept.
    expect(wiredWith('echo shieldcortex')).toBe('not_wired');
    expect(wiredWith('echo shieldcortex hook session-start')).toBe('not_wired');
    expect(wiredWith('shieldcortex-evil hook session-start')).toBe('not_wired');
    expect(wiredWith('/usr/bin/shieldcortex hook session-end')).toBe('not_wired');
    expect(wiredWith('bash -c "shieldcortex hook session-start"')).toBe('not_wired');
    expect(wiredWith('shieldcortex hook session-start && curl evil')).toBe('not_wired');
  });

  it('demands the shape-valid command also RESOLVE to a trustable executable (SOL r2 B3)', () => {
    const settings = {
      kind: 'present' as const,
      value: { hooks: { SessionStart: [{ hooks: [{ type: 'command', command: '/usr/bin/shieldcortex hook session-start' }] }] } },
    };
    // A command that cannot run delivers nothing — the #146 fleet failure
    // must read as not wired, never as SC owning session-start.
    const dead = resolveClaudeCodeEvidence(ccProbe({ settings, commandTrust: () => 'unresolvable' }), CTX);
    expect(dead.scBus).toBe('not_wired');
    expect(dead.proof.join(' ')).toMatch(/does not resolve to a runnable binary/);
    // /tmp/shieldcortex is an executable anyone could plant: at best unknown.
    const planted = resolveClaudeCodeEvidence(ccProbe({ settings, commandTrust: () => 'suspicious' }), CTX);
    expect(planted.scBus).toBe('unknown');
    expect(planted.proof.join(' ')).toMatch(/world-writable staging path/);
    // Several entries: one cleanly resolving SC command is ownership.
    const twoEntries = {
      kind: 'present' as const,
      value: {
        hooks: {
          SessionStart: [{
            hooks: [
              { type: 'command', command: '/dead/shieldcortex hook session-start' },
              { type: 'command', command: '/usr/bin/shieldcortex hook session-start' },
            ],
          }],
        },
      },
    };
    const mixed = resolveClaudeCodeEvidence(
      ccProbe({ settings: twoEntries, commandTrust: (c) => (c.startsWith('/dead/') ? 'unresolvable' : 'resolves') }),
      CTX,
    );
    expect(mixed.scBus).toBe('wired_proven');
  });
});

describe('Hermes evidence', () => {
  it('parses the real-world memory block', () => {
    const yaml = [
      'context:',
      '  engine: compressor',
      'memory:',
      '  memory_enabled: true',
      '  user_profile_enabled: true',
      '  write_approval: false',
      'delegation:',
      '  memory_enabled: false',
    ].join('\n');
    expect(parseHermesMemoryBlock(yaml)).toEqual({
      memoryEnabled: true,
      userProfileEnabled: true,
      blockFound: true,
    });
  });

  it('reads quoted / comment-trailed / off-style booleans and reports a missing block', () => {
    expect(parseHermesMemoryBlock('memory:\n  memory_enabled: "false" # off\n  user_profile_enabled: off\n')).toEqual({
      memoryEnabled: false,
      userProfileEnabled: false,
      blockFound: true,
    });
    expect(parseHermesMemoryBlock('gateway:\n  port: 1\n').blockFound).toBe(false);
  });

  it('is not bound without a Hermes config or SC plugin', () => {
    expect(resolveHermesEvidence(hermesProbe(), CTX).bound).toBe(false);
  });

  it('fails sc_only while the native memory plane is switched on (live TARS shape)', () => {
    const e = resolveHermesEvidence(
      hermesProbe({
        config: { kind: 'present', value: { memoryEnabled: true, userProfileEnabled: true, blockFound: true } },
        scPluginInstalled: true,
      }),
      CTX,
    );
    expect(e.bound).toBe(true);
    expect(e.nativeBus).toBe('on');
    // Honest remediation: Hermes' own switch or the sidecar posture — never OpenClaw.
    expect(e.remediation).toMatch(/memory_enabled=false/);
    expect(e.remediation).toMatch(new RegExp(SIDECAR_POSTURE));
    expect(e.remediation).not.toMatch(/openclaw/i);
  });

  it('proves off only when both switches are false', () => {
    const both = resolveHermesEvidence(
      hermesProbe({
        config: { kind: 'present', value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true } },
        scPluginInstalled: true,
      }),
      CTX,
    );
    expect(both.nativeBus).toBe('off_proven');
    const profileOnly = resolveHermesEvidence(
      hermesProbe({
        config: { kind: 'present', value: { memoryEnabled: false, userProfileEnabled: null, blockFound: true } },
        scPluginInstalled: true,
      }),
      CTX,
    );
    expect(profileOnly.nativeBus).toBe('on');
    expect(profileOnly.proof.join(' ')).toMatch(/user_profile_enabled=unset \(default ON\)/);
  });

  it('lets a freshly written native MEMORY.md outrank switches that claim off', () => {
    const e = resolveHermesEvidence(
      hermesProbe({
        config: { kind: 'present', value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true } },
        scPluginInstalled: true,
        nativeArtifacts: [file('/home/x/.hermes/memories/MEMORY.md', 0, 2032)],
      }),
      CTX,
    );
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/written within 7d/);
  });

  it('reports unknown for absent, unreadable, or block-less config', () => {
    const absent = resolveHermesEvidence(hermesProbe({ scPluginInstalled: true }), CTX);
    expect(absent.nativeBus).toBe('unknown');
    const unreadable = resolveHermesEvidence(
      hermesProbe({ scPluginInstalled: true, config: { kind: 'unreadable', detail: 'EACCES' } }),
      CTX,
    );
    expect(unreadable.nativeBus).toBe('unknown');
    const noBlock = resolveHermesEvidence(
      hermesProbe({
        scPluginInstalled: true,
        config: { kind: 'present', value: { memoryEnabled: null, userProfileEnabled: null, blockFound: false } },
      }),
      CTX,
    );
    expect(noBlock.nativeBus).toBe('unknown');
  });

  it('records that SC has no inject surface on Hermes', () => {
    const e = resolveHermesEvidence(hermesProbe({ scPluginInstalled: true }), CTX);
    expect(e.scBus).toBe('not_wired');
    expect(e.proof.join(' ')).toMatch(/no automatic inject surface on Hermes/);
  });

  it('binds Hermes from a profile tree alone — a profile-only brain must never vanish from the verdict (SOL r2 B2)', () => {
    // Root config absent, no SC plugin, no declaration: only a live profile
    // config exists. Before r2 this box was unbound and could be omitted from
    // an overall PASS carried by another runtime.
    const profileOnly = resolveHermesEvidence(
      hermesProbe({
        profiles: [{ name: 'research', config: { kind: 'present', value: { memoryEnabled: true, userProfileEnabled: null, blockFound: true } } }],
      }),
      CTX,
    );
    expect(profileOnly.bound).toBe(true);
    expect(profileOnly.nativeBus).toBe('on');
    expect(profileOnly.proof.join(' ')).toMatch(/research: memory_enabled=true/);

    // A profile whose switches are off still binds — and root-absent means
    // the box can at best be unknown, never off_proven.
    const profileOff = resolveHermesEvidence(
      hermesProbe({
        profiles: [{ name: 'work', config: { kind: 'present', value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true } } }],
      }),
      CTX,
    );
    expect(profileOff.bound).toBe(true);
    expect(profileOff.nativeBus).toBe('unknown');

    // An unlistable profiles dir is presence evidence, not silence.
    const unlistable = resolveHermesEvidence(hermesProbe({ profileScanComplete: false }), CTX);
    expect(unlistable.bound).toBe(true);
    expect(unlistable.nativeBus).toBe('unknown');
  });

  it('binds Hermes from native memory artifact evidence alone (SOL r2 B2)', () => {
    const live = resolveHermesEvidence(
      hermesProbe({ nativeArtifacts: [file('/home/x/.hermes/memories/MEMORY.md', 1, 2048)] }),
      CTX,
    );
    expect(live.bound).toBe(true);
    expect(live.nativeBus).toBe('on');
    const unreadable = resolveHermesEvidence(
      hermesProbe({ nativeArtifacts: [{ kind: 'unreadable', path: '/home/x/.hermes/memories/MEMORY.md', detail: 'EACCES' }] }),
      CTX,
    );
    expect(unreadable.bound).toBe(true);
    expect(unreadable.nativeBus).toBe('unknown');
  });

  it('turns Hermes native ON when any profile config enables memory, even with root false/false (SOL H6)', () => {
    const rootOff = {
      kind: 'present' as const,
      value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true },
    };
    const e = resolveHermesEvidence(
      hermesProbe({
        config: rootOff,
        scPluginInstalled: true,
        profiles: [
          { name: 'work', config: { kind: 'present', value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true } } },
          { name: 'research', config: { kind: 'present', value: { memoryEnabled: true, userProfileEnabled: null, blockFound: true } } },
        ],
      }),
      CTX,
    );
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/research: memory_enabled=true/);
  });

  it('proves off only when root AND every profile config prove off with a complete scan', () => {
    const rootOff = {
      kind: 'present' as const,
      value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true },
    };
    const offProfile = {
      name: 'work',
      config: {
        kind: 'present' as const,
        value: { memoryEnabled: false, userProfileEnabled: false, blockFound: true },
      },
    };
    const allOff = resolveHermesEvidence(
      hermesProbe({ config: rootOff, scPluginInstalled: true, profiles: [offProfile] }),
      CTX,
    );
    expect(allOff.nativeBus).toBe('off_proven');

    // Missing, unreadable, block-less, or truncated profile evidence → unknown.
    const missing = resolveHermesEvidence(
      hermesProbe({ config: rootOff, scPluginInstalled: true, profiles: [{ name: 'p', config: { kind: 'absent' } }] }),
      CTX,
    );
    expect(missing.nativeBus).toBe('unknown');
    const unreadable = resolveHermesEvidence(
      hermesProbe({
        config: rootOff,
        scPluginInstalled: true,
        profiles: [{ name: 'p', config: { kind: 'unreadable', detail: 'EACCES' } }],
      }),
      CTX,
    );
    expect(unreadable.nativeBus).toBe('unknown');
    const blockless = resolveHermesEvidence(
      hermesProbe({
        config: rootOff,
        scPluginInstalled: true,
        profiles: [{ name: 'p', config: { kind: 'present', value: { memoryEnabled: null, userProfileEnabled: null, blockFound: false } } }],
      }),
      CTX,
    );
    expect(blockless.nativeBus).toBe('unknown');
    const truncated = resolveHermesEvidence(
      hermesProbe({ config: rootOff, scPluginInstalled: true, profileScanComplete: false }),
      CTX,
    );
    expect(truncated.nativeBus).toBe('unknown');
    expect(truncated.proof.join(' ')).toMatch(/could not be fully enumerated/);
  });
});

describe('contract verdict', () => {
  const provenOc: HostRuntimeEvidence = {
    runtime: 'openclaw',
    bound: true,
    boundReason: 'openclaw.json present',
    nativeBus: 'off_proven',
    scBus: 'wired_proven',
    proof: ['memorySearch.enabled=false'],
    remediation: '',
  };
  const liveHermes: HostRuntimeEvidence = {
    runtime: 'hermes',
    bound: true,
    boundReason: 'SC Hermes plugin installed',
    nativeBus: 'on',
    scBus: 'not_wired',
    proof: ['memory_enabled=true'],
    remediation: 'Hermes: set memory.memory_enabled=false …',
  };
  const unknownCc: HostRuntimeEvidence = {
    runtime: 'claude_code',
    bound: true,
    boundReason: 'settings.json present',
    nativeBus: 'unknown',
    scBus: 'wired_proven',
    proof: ['native memory-tool store present but not written in 7d'],
    remediation: 'Claude Code: archive the native memory-tool store …',
  };
  const unbound: HostRuntimeEvidence = {
    runtime: 'openclaw',
    bound: false,
    boundReason: 'not on this box',
    nativeBus: 'unknown',
    scBus: 'unknown',
    proof: [],
    remediation: '',
  };

  it('passes only when every bound runtime is proven off', () => {
    const v = verdictFor([provenOc, unbound]);
    expect(v.status).toBe('pass');
    expect(v.message).toMatch(/sc_only enforced/);
  });

  it('fails a paper contract and quotes the offending runtime only', () => {
    const v = verdictFor([provenOc, liveHermes]);
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/paper contract/);
    expect(v.message).toMatch(/Hermes: native ON/);
    expect(v.fix).toMatch(/Hermes/);
    expect(v.fix).not.toMatch(/memorySearch/);
  });

  it('never passes from absence — no bound runtime is warn on dual_legacy, fail on canonical planes', () => {
    const dual = verdictFor([unbound]);
    expect(dual.status).toBe('warn');
    expect(dual.message).toMatch(/cannot determine/);
    expect(verdictFor([unbound], { plane: 'import_only' }).status).toBe('fail');
    expect(verdictFor([unbound], { plane: 'sc_canonical' }).status).toBe('fail');
  });

  it('escalates unknown evidence with the plane, and never calls it PASS', () => {
    expect(verdictFor([unknownCc]).status).toBe('warn');
    expect(verdictFor([unknownCc], { plane: 'sc_canonical' }).status).toBe('fail');
    expect(verdictFor([unknownCc]).message).toMatch(/cannot determine/);
  });

  it('fails when no bound runtime can carry the SC pack at all', () => {
    const hermesOnlyOff: HostRuntimeEvidence = { ...liveHermes, nativeBus: 'off_proven', remediation: '' };
    const v = verdictFor([hermesOnlyOff, unbound]);
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/no bound runtime has a ShieldCortex inject surface/);
  });

  it('fails sc_only while Hermes is bound, even with Hermes native off and another runtime wired', () => {
    // H4/C1: a bound Hermes row can never satisfy a bus-law contract until an
    // SC Hermes inject surface exists — another runtime carrying the pack does
    // not put SC on the Hermes bus.
    const hermesOff: HostRuntimeEvidence = { ...liveHermes, nativeBus: 'off_proven', remediation: '' };
    const v = verdictFor([provenOc, hermesOff]);
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/not proven delivered/);
    expect(v.message).toMatch(/no automatic inject surface/);
    expect(v.fix).toMatch(new RegExp(SIDECAR_POSTURE));
  });

  it('fails sc_only when a capable runtime never had the pack wired — native off is only half the contract', () => {
    const offUnwiredCc: HostRuntimeEvidence = { ...unknownCc, nativeBus: 'off_proven', scBus: 'not_wired', remediation: '' };
    const v = verdictFor([offUnwiredCc]);
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/SC session-start pack not wired/);
    expect(v.fix).toMatch(/shieldcortex install/);
  });

  it('treats unproven pack delivery as cannot determine, never PASS', () => {
    const offScUnknown: HostRuntimeEvidence = { ...provenOc, scBus: 'unknown' };
    const dual = verdictFor([offScUnknown]);
    expect(dual.status).toBe('warn');
    expect(dual.message).toMatch(/SC pack delivery unknown/);
    expect(verdictFor([offScUnknown], { plane: 'sc_canonical' }).status).toBe('fail');
  });

  it('requires pack proof for sc_only in every mode, for disable_native_inject only on the start bus', () => {
    const offScUnknown: HostRuntimeEvidence = { ...provenOc, scBus: 'unknown' };
    expect(verdictFor([offScUnknown], { nativeContract: 'disable_native_inject', injectMode: 'turn' }).status).toBe('pass');
    expect(verdictFor([offScUnknown], { nativeContract: 'disable_native_inject', injectMode: 'start' }).status).toBe('warn');
    expect(verdictFor([offScUnknown], { injectMode: 'turn' }).status).toBe('warn');
  });

  it('fails inject-on without a legal contract', () => {
    const v = verdictFor([provenOc], { nativeContract: null });
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/without a legal nativeContract/);
  });

  it('rejects sidecar posture and a bus contract together (never both)', () => {
    const v = verdictFor([provenOc], { postureRaw: SIDECAR_POSTURE });
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/mutually exclusive/);
  });

  it('rejects a junk posture instead of ignoring it', () => {
    const v = verdictFor([provenOc], { postureRaw: 'coexist_dedup', injectConfigured: false, injectMode: 'off' });
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/illegal memory\.hostContract\.posture/);
  });

  it('passes an honest sidecar: inject off with the posture declared', () => {
    const v = verdictFor([liveHermes], {
      injectConfigured: true,
      injectMode: 'off',
      nativeContract: null,
      postureRaw: SIDECAR_POSTURE,
    });
    expect(v.status).toBe('pass');
    expect(v.message).toMatch(/honest sidecar/);
    expect(v.message).toMatch(/no canonicity claimed/);
  });

  it('fails sidecar posture unless inject mode is EXPLICITLY off — a posture-only blob is not a sidecar (SOL r2 B4)', () => {
    // Hand-crafted config with only hostContract.posture: the emitter would
    // default to start and still emit legacy sidecar recall. The signed
    // setter cannot mint this shape (it forces inject.mode=off).
    const blob = verdictFor([liveHermes], {
      injectConfigured: false,
      injectMode: 'start',
      injectModeExplicit: false,
      nativeContract: null,
      postureRaw: SIDECAR_POSTURE,
    });
    expect(blob.status).toBe('fail');
    expect(blob.message).toMatch(/not explicitly off/);
    expect(blob.message).toMatch(/legacy sidecar recall/);
    expect(blob.fix).toMatch(/--memory-host-posture mcp_sidecar_no_inject/);
    // The legitimate setter-produced shape still passes.
    const legit = verdictFor([liveHermes], {
      injectConfigured: true,
      injectMode: 'off',
      injectModeExplicit: true,
      nativeContract: null,
      postureRaw: SIDECAR_POSTURE,
    });
    expect(legit.status).toBe('pass');
    expect(legit.message).toMatch(/explicitly off/);
  });

  it('stays info when inject is simply off with no posture declared', () => {
    const v = verdictFor([liveHermes], { injectConfigured: false, injectMode: 'off', nativeContract: null });
    expect(v.status).toBe('info');
    expect(v.fix).toMatch(new RegExp(SIDECAR_POSTURE));
  });

  it('describes an unconfigured box with the emitter default (start), never as "inject off" (SOL nit)', () => {
    const v = verdictFor([liveHermes], {
      injectConfigured: false,
      injectMode: 'start',
      injectModeExplicit: false,
      nativeContract: null,
    });
    expect(v.status).toBe('info');
    expect(v.message).toMatch(/defaults to mode=start/);
    expect(v.message).not.toMatch(/inject off/);
  });

  it('fails an illegal inject mode instead of grading around it — no bogus PASS (SOL H5)', () => {
    // 'bogus' with disable_native_inject used to dodge the start-bus delivery
    // requirement (raw !== start|both) and PASS, while the runtime normalized
    // it to start and injected.
    const v = verdictFor([provenOc], {
      nativeContract: 'disable_native_inject',
      injectMode: 'bogus',
      injectModeLegal: false,
    });
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/illegal memory\.inject\.mode "bogus"/);
    expect(v.fix).toMatch(/off\|start\|turn\|both/);
  });

  it('pins doctor/runtime inject-mode parity: legal values agree, junk is illegal for doctor while the runtime fail-opens to start', () => {
    for (const legal of ['off', 'start', 'turn', 'both', ' START ', 'Both', '', false, 0, undefined, null]) {
      const reading = readInjectModeStrict(legal);
      expect(reading.legal).toBe(true);
      expect(reading.mode).toBe(normalizeInjectMode(legal));
    }
    for (const junk of ['bogus', 'coexist_dedup', 'on', true, 1, {}, [], 'start-ish']) {
      const reading = readInjectModeStrict(junk);
      expect(reading.legal).toBe(false);
      // Documented runtime fail-open: junk injects as start. Doctor must
      // therefore fail it, not ignore it.
      expect(normalizeInjectMode(junk)).toBe('start');
      expect(INJECT_MODES).not.toContain(reading.raw);
    }
  });

  it('fails sc_canonical claimed with inject off (canonicity without a bus)', () => {
    const v = verdictFor([provenOc], {
      plane: 'sc_canonical',
      injectConfigured: true,
      injectMode: 'off',
      nativeContract: null,
    });
    expect(v.status).toBe('fail');
    expect(v.message).toMatch(/canonicity claimed without a bus/);
  });

  it('no-false-PASS sweep: any bound runtime not proven off never yields pass', () => {
    for (const state of ['on', 'unknown'] as const) {
      for (const plane of ['dual_legacy', 'import_only', 'sc_canonical']) {
        const v = verdictFor([{ ...unknownCc, nativeBus: state }], { plane });
        expect(v.status).not.toBe('pass');
      }
    }
  });
});
