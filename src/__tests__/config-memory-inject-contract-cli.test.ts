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
