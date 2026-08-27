/**
 * Memory-plane signed CLI flags: `shieldcortex config --memory-inject-contract`
 * and `--auto-memory-sampling`. Same class as the #275 Action Guard notify
 * flags: doctor's empty-brain fail said "Set memory.inject.nativeContract …
 * in ~/.shieldcortex/config.json" and the sampling warn said "Edit
 * ~/.shieldcortex/config.json", so operators hand-edited the file — which
 * invalidated the embedded `_sig` HMAC and forced defenceMode strict. These
 * flags write through mutateRawConfig/writeRawConfig, so the config is
 * re-signed and the integrity check stays green.
 */

import fs from 'fs';
import path from 'path';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { handleCloudConfig } from '../cloud/cli.js';
import {
  getConfigDir,
  clearCloudConfigCache,
  readRawConfig,
  isConfigTampered,
  setMemoryInjectContract,
  setMemoryPlane,
  setMemoryHostPosture,
  setMemoryHostRuntimes,
  setAutoMemorySamplingTurns,
} from '../cloud/config.js';

const configFile = () => path.join(getConfigDir(), 'config.json');
const legacySigFile = () => path.join(getConfigDir(), '.config-sig');

function resetConfigDir(): void {
  fs.rmSync(configFile(), { force: true });
  fs.rmSync(legacySigFile(), { force: true });
  clearCloudConfigCache();
}

function readOnDisk(): Record<string, any> {
  return JSON.parse(fs.readFileSync(configFile(), 'utf-8'));
}

function mockExit(): jest.SpiedFunction<typeof process.exit> {
  return jest
    .spyOn(process, 'exit')
    .mockImplementation(((): never => { throw new Error('exit'); }) as never);
}

beforeEach(() => {
  resetConfigDir();
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  resetConfigDir();
});

describe('config --memory-inject-contract (signed empty-brain fix path)', () => {
  it('sc_only writes memory.inject.nativeContract with a 64-hex `_sig`; no tamper, no forced strict', () => {
    handleCloudConfig(['--memory-inject-contract', 'sc_only']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.inject.nativeContract).toBe('sc_only');
    expect(typeof onDisk._sig).toBe('string');
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(false);
    expect(raw.defenceMode).not.toBe('strict');
  });

  it('disable_native_inject writes the same signed shape', () => {
    handleCloudConfig(['--memory-inject-contract', 'disable_native_inject']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.inject.nativeContract).toBe('disable_native_inject');
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(false);
    expect(raw.defenceMode).not.toBe('strict');
  });

  it('rejects a junk contract value (coexist_dedup stays illegal) and leaves the config untouched', () => {
    handleCloudConfig(['--mode', 'balanced']);
    const before = fs.readFileSync(configFile(), 'utf-8');
    const exitSpy = mockExit();
    expect(() =>
      handleCloudConfig(['--memory-inject-contract', 'coexist_dedup']),
    ).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(before);
  });

  it('rejects a missing contract value', () => {
    const exitSpy = mockExit();
    expect(() => handleCloudConfig(['--memory-inject-contract'])).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  it('preserves sibling inject keys (mode, hostId) and unrelated top-level keys', () => {
    // Seed a pre-existing (unsigned legacy) config the way a live host has one:
    // inject already configured, plus an unrelated top-level key.
    fs.writeFileSync(configFile(), JSON.stringify({
      proactiveRecall: true,
      memory: {
        inject: {
          mode: 'start',
          hostId: 'tars',
          agentId: 'hermes-primary',
          budgets: { start: { tokens: 900 } },
        },
      },
    }, null, 2) + '\n');
    clearCloudConfigCache();
    handleCloudConfig(['--memory-inject-contract', 'sc_only']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.inject.nativeContract).toBe('sc_only');
    expect(onDisk.memory.inject.mode).toBe('start');
    expect(onDisk.memory.inject.hostId).toBe('tars');
    expect(onDisk.memory.inject.agentId).toBe('hermes-primary');
    expect(onDisk.memory.inject.budgets).toEqual({ start: { tokens: 900 } });
    expect(onDisk.proactiveRecall).toBe(true);
  });

  it('does not mint the legacy aliases memoryNativeInjectContract / memory.nativeInjectContract', () => {
    handleCloudConfig(['--memory-inject-contract', 'sc_only']);
    const onDisk = readOnDisk();
    expect(onDisk.memoryNativeInjectContract).toBeUndefined();
    expect(onDisk.memory.nativeInjectContract).toBeUndefined();
  });

  it('setMemoryInjectContract rejects illegal values at the API layer too', () => {
    expect(() => setMemoryInjectContract('coexist_dedup')).toThrow(/sc_only, disable_native_inject/);
    expect(() => setMemoryInjectContract('')).toThrow(/sc_only, disable_native_inject/);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  it('the hand-edit doctor used to recommend DOES trip tamper + strict (why the flag exists)', () => {
    handleCloudConfig(['--memory-inject-contract', 'sc_only']);
    const onDisk = readOnDisk();
    // What the old fix told operators to do: set the key by hand. The stale
    // `_sig` rides along, so the next read flags tampering and forces strict.
    onDisk.memory.inject.nativeContract = 'disable_native_inject';
    fs.writeFileSync(configFile(), JSON.stringify(onDisk, null, 2) + '\n');
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(true);
    expect(raw.defenceMode).toBe('strict');
  });
});

describe('config --auto-memory-sampling (signed sampling fix path)', () => {
  it('writes autoMemory.stopHookSamplingTurns signed, preserving sibling autoMemory keys', () => {
    fs.writeFileSync(configFile(), JSON.stringify({
      autoMemory: { enableStop: true, enableSessionEnd: true },
    }, null, 2) + '\n');
    clearCloudConfigCache();
    handleCloudConfig(['--auto-memory-sampling', '3']);
    const onDisk = readOnDisk();
    expect(onDisk.autoMemory.stopHookSamplingTurns).toBe(3);
    expect(onDisk.autoMemory.enableStop).toBe(true);
    expect(onDisk.autoMemory.enableSessionEnd).toBe(true);
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    const raw = readRawConfig();
    expect(isConfigTampered()).toBe(false);
    expect(raw.defenceMode).not.toBe('strict');
  });

  it.each(['0', '21', '2.5', 'abc'])('rejects out-of-range/non-integer value %s', (value) => {
    const exitSpy = mockExit();
    expect(() => handleCloudConfig(['--auto-memory-sampling', value])).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  it('rejects a missing value', () => {
    const exitSpy = mockExit();
    expect(() => handleCloudConfig(['--auto-memory-sampling'])).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  it('setAutoMemorySamplingTurns rejects non-integers and out-of-range at the API layer too', () => {
    expect(() => setAutoMemorySamplingTurns(0)).toThrow(/between 1 and 20/);
    expect(() => setAutoMemorySamplingTurns(21)).toThrow(/between 1 and 20/);
    expect(() => setAutoMemorySamplingTurns(2.5)).toThrow(/between 1 and 20/);
    expect(() => setAutoMemorySamplingTurns(Number.NaN)).toThrow(/between 1 and 20/);
    expect(fs.existsSync(configFile())).toBe(false);
  });
});

describe('config --memory-plane (signed Track A / #348)', () => {
  it('import_only writes memory.plane + planeSetAt with _sig', () => {
    handleCloudConfig(['--memory-plane', 'import_only']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.plane).toBe('import_only');
    expect(onDisk.memory.planeSetAt).toMatch(/^\d{4}-/);
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    expect(isConfigTampered()).toBe(false);
  });

  it('rejects illegal plane and leaves config untouched', () => {
    handleCloudConfig(['--mode', 'balanced']);
    const before = fs.readFileSync(configFile(), 'utf-8');
    const exitSpy = mockExit();
    expect(() => handleCloudConfig(['--memory-plane', 'bidir'])).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(before);
  });

  it('setMemoryPlane API rejects illegal values', () => {
    expect(() => setMemoryPlane('multi_master')).toThrow(/Invalid memory\.plane/);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  it('re-setting the plane advances planeSetAt — the drift time-box must not read a stale stamp (#394)', () => {
    handleCloudConfig(['--memory-plane', 'dual_legacy']);
    const first = readOnDisk().memory.planeSetAt as string;
    // Rewind the stamp on disk the way an aged install looks, then re-sign by
    // going back through the signed setter.
    const rewound = new Date(Date.parse(first) - 30 * 24 * 60 * 60 * 1000).toISOString();
    const rawCfg = readOnDisk();
    rawCfg.memory.planeSetAt = rewound;
    fs.writeFileSync(configFile(), `${JSON.stringify(rawCfg, null, 2)}\n`);
    clearCloudConfigCache();
    handleCloudConfig(['--memory-plane', 'import_only']);
    const after = readOnDisk();
    expect(after.memory.plane).toBe('import_only');
    expect(Date.parse(after.memory.planeSetAt as string)).toBeGreaterThan(Date.parse(rewound));
    expect(after._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    expect(isConfigTampered()).toBe(false);
  });

  it('preserves inject sibling keys when setting plane', () => {
    fs.writeFileSync(configFile(), JSON.stringify({
      memory: {
        inject: { mode: 'start', nativeContract: 'sc_only', hostId: 'tars' },
      },
    }, null, 2) + '\n');
    clearCloudConfigCache();
    handleCloudConfig(['--memory-plane', 'sc_canonical']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.plane).toBe('sc_canonical');
    expect(onDisk.memory.inject.nativeContract).toBe('sc_only');
    expect(onDisk.memory.inject.hostId).toBe('tars');
  });
});

describe('config --memory-host-posture / --memory-host-runtime (#393 T1 signed fix path)', () => {
  it('mcp_sidecar_no_inject records the posture AND turns inject off in one signed write', () => {
    handleCloudConfig(['--memory-inject-contract', 'sc_only']);
    handleCloudConfig(['--memory-host-posture', 'mcp_sidecar_no_inject']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.hostContract.posture).toBe('mcp_sidecar_no_inject');
    expect(typeof onDisk.memory.hostContract.postureSetAt).toBe('string');
    // Never both: the sidecar posture cannot coexist with a live inject bus.
    expect(onDisk.memory.inject.mode).toBe('off');
    // The contract value survives so flipping back does not lose it.
    expect(onDisk.memory.inject.nativeContract).toBe('sc_only');
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
    clearCloudConfigCache();
    expect(isConfigTampered()).toBe(false);
    expect(readRawConfig().defenceMode).not.toBe('strict');
  });

  it('bus_contract clears the posture AND its postureSetAt stamp without switching inject on behind the operator', () => {
    handleCloudConfig(['--memory-host-posture', 'mcp_sidecar_no_inject']);
    handleCloudConfig(['--memory-host-posture', 'bus_contract']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.hostContract.posture).toBeUndefined();
    // SOL nit: a stale stamp with no posture reads as "sidecar was set at T".
    expect(onDisk.memory.hostContract.postureSetAt).toBeUndefined();
    expect(onDisk.memory.inject.mode).toBe('off');
    expect(onDisk._sig).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a junk posture and a junk runtime, leaving the config untouched', () => {
    handleCloudConfig(['--mode', 'balanced']);
    const before = fs.readFileSync(configFile(), 'utf-8');
    const exitSpy = mockExit();
    expect(() => handleCloudConfig(['--memory-host-posture', 'coexist_dedup'])).toThrow('exit');
    expect(() => handleCloudConfig(['--memory-host-runtime', 'openclaw,gemini'])).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(before);
  });

  it('combined flags are all-or-nothing: a later invalid arg aborts before ANY signed write lands (SOL nit)', () => {
    handleCloudConfig(['--mode', 'balanced']);
    const before = fs.readFileSync(configFile(), 'utf-8');
    const exitSpy = mockExit();
    // Valid posture followed by junk runtime: pre-preflight this committed the
    // posture (inject forced off!) and then exited on the runtime.
    expect(() =>
      handleCloudConfig(['--memory-host-posture', 'mcp_sidecar_no_inject', '--memory-host-runtime', 'bogus']),
    ).toThrow('exit');
    // Valid contract followed by junk plane; valid runtime followed by junk
    // sampling — nothing may land in either order.
    expect(() =>
      handleCloudConfig(['--memory-inject-contract', 'sc_only', '--memory-plane', 'multi_master']),
    ).toThrow('exit');
    expect(() =>
      handleCloudConfig(['--memory-host-runtime', 'hermes', '--auto-memory-sampling', 'lots']),
    ).toThrow('exit');
    expect(exitSpy).toHaveBeenCalledWith(1);
    expect(fs.readFileSync(configFile(), 'utf-8')).toBe(before);
  });

  it('declares bound runtimes, deduped, without inventing any proof of native-off', () => {
    handleCloudConfig(['--memory-host-runtime', 'hermes,hermes,claude_code']);
    const onDisk = readOnDisk();
    expect(onDisk.memory.hostContract.runtimes).toEqual(['hermes', 'claude_code']);
    expect(onDisk.memory.hostContract.nativeOff).toBeUndefined();
    expect(onDisk.memory.hostContract.posture).toBeUndefined();
  });

  it('rejects illegal values at the API layer too', () => {
    expect(() => setMemoryHostPosture('sc_only')).toThrow(/mcp_sidecar_no_inject, bus_contract/);
    expect(() => setMemoryHostRuntimes([])).toThrow(/openclaw, claude_code, hermes/);
    expect(fs.existsSync(configFile())).toBe(false);
  });
});
