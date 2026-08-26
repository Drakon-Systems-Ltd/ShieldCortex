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
  resolveClaudeCodeEvidence,
  resolveHermesEvidence,
  resolveOpenClawEvidence,
  SIDECAR_POSTURE,
  type ArtifactProbe,
  type ClaudeCodeProbe,
  type HermesProbe,
  type HostRuntimeEvidence,
  type OpenClawProbe,
} from '../host-contract.js';

const NOW = Date.UTC(2026, 7, 26, 12, 0, 0);
const DAY = 24 * 60 * 60 * 1000;
const CTX = { contract: 'sc_only', plane: 'dual_legacy', nowMs: NOW };

function file(p: string, ageDays: number, size = 512): ArtifactProbe {
  return { kind: 'present', path: p, mtimeMs: NOW - ageDays * DAY, size };
}

function ocProbe(over: Partial<OpenClawProbe> = {}): OpenClawProbe {
  return {
    config: { kind: 'absent' },
    scHook: 'absent',
    scAutoMemory: false,
    agentsMd: { kind: 'absent' },
    memoryMd: { kind: 'absent', path: '/home/x/.openclaw/workspace/MEMORY.md' },
    declared: false,
    ...over,
  };
}

function ccProbe(over: Partial<ClaudeCodeProbe> = {}): ClaudeCodeProbe {
  return {
    settings: { kind: 'absent' },
    nativeStores: [],
    storeScanComplete: true,
    declared: false,
    ...over,
  };
}

function hermesProbe(over: Partial<HermesProbe> = {}): HermesProbe {
  return {
    config: { kind: 'absent' },
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
    const e = resolveOpenClawEvidence(ocProbe({ scHook: 'installed', scAutoMemory: true }), CTX);
    expect(e.bound).toBe(true);
    expect(e.nativeBus).toBe('unknown');
  });

  it('resolves the SC bus from the hook tri-state: installed=wired, absent=not_wired, unreadable=unknown', () => {
    const config = { kind: 'present' as const, value: { agents: { defaults: { memorySearch: { enabled: false } } } } };
    expect(resolveOpenClawEvidence(ocProbe({ config, scHook: 'installed' }), CTX).scBus).toBe('wired');
    expect(resolveOpenClawEvidence(ocProbe({ config, scHook: 'absent' }), CTX).scBus).toBe('not_wired');
    const unreadable = resolveOpenClawEvidence(ocProbe({ config, scHook: 'unreadable' }), CTX);
    expect(unreadable.scBus).toBe('unknown');
    expect(unreadable.proof.join(' ')).toMatch(/pack delivery cannot be proven/);
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
    const scOnly = resolveOpenClawEvidence(ocProbe({ config: off, agentsMd }), CTX);
    expect(scOnly.nativeBus).toBe('on');
    const weaker = resolveOpenClawEvidence(
      ocProbe({ config: off, agentsMd }),
      { ...CTX, contract: 'disable_native_inject' },
    );
    expect(weaker.nativeBus).toBe('off_proven');
  });

  it('fails a MEMORY.md still growing under import_only', () => {
    const e = resolveOpenClawEvidence(
      ocProbe({
        config: { kind: 'present', value: { agents: { defaults: { memorySearch: { enabled: false } } } } },
        memoryMd: file('/home/x/.openclaw/workspace/MEMORY.md', 1, 4096),
      }),
      { ...CTX, plane: 'import_only' },
    );
    expect(e.nativeBus).toBe('on');
    expect(e.proof.join(' ')).toMatch(/MEMORY\.md written within 7d/);
  });
});

describe('Claude Code evidence', () => {
  it('is not bound without settings.json or a declaration', () => {
    expect(resolveClaudeCodeEvidence(ccProbe(), CTX).bound).toBe(false);
  });

  it('proves native off when no memory-tool store exists and SC owns session-start', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({ settings: { kind: 'present', value: WIRED_SETTINGS } }),
      CTX,
    );
    expect(e.nativeBus).toBe('off_proven');
    expect(e.scBus).toBe('wired');
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

  it('marks the SC bus not wired when SessionStart carries no shieldcortex command', () => {
    const e = resolveClaudeCodeEvidence(
      ccProbe({ settings: { kind: 'present', value: { hooks: { SessionStart: [{ hooks: [{ command: 'other' }] }] } } } }),
      CTX,
    );
    expect(e.scBus).toBe('not_wired');
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
});

describe('contract verdict', () => {
  const provenOc: HostRuntimeEvidence = {
    runtime: 'openclaw',
    bound: true,
    boundReason: 'openclaw.json present',
    nativeBus: 'off_proven',
    scBus: 'wired',
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
    scBus: 'wired',
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

  it('stays info when inject is simply off with no posture declared', () => {
    const v = verdictFor([liveHermes], { injectConfigured: false, injectMode: 'off', nativeContract: null });
    expect(v.status).toBe('info');
    expect(v.fix).toMatch(new RegExp(SIDECAR_POSTURE));
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
