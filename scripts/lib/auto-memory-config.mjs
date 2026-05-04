import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CONFIG_PATH = join(homedir(), '.shieldcortex', 'config.json');

const DEFAULTS = Object.freeze({
  maxTranscriptBytes: 1024 * 1024,
  maxTranscriptLines: 5000,
  keepSlashCommandProse: true,
  stopHookSamplingTurns: 10,
  stopHookWindowBytes: 256 * 1024,
  enableSessionEnd: false,
  enableStop: false,
});

export function getAutoMemoryConfig() {
  let raw = {};
  try {
    if (existsSync(CONFIG_PATH)) {
      raw = JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
    }
  } catch {
    // fall through to defaults
  }
  const overrides = (raw && typeof raw.autoMemory === 'object' && raw.autoMemory) || {};
  return {
    maxTranscriptBytes: pickPositiveInt(overrides.maxTranscriptBytes, DEFAULTS.maxTranscriptBytes),
    maxTranscriptLines: pickPositiveInt(overrides.maxTranscriptLines, DEFAULTS.maxTranscriptLines),
    keepSlashCommandProse: typeof overrides.keepSlashCommandProse === 'boolean'
      ? overrides.keepSlashCommandProse
      : DEFAULTS.keepSlashCommandProse,
    stopHookSamplingTurns: pickPositiveInt(overrides.stopHookSamplingTurns, DEFAULTS.stopHookSamplingTurns),
    stopHookWindowBytes: pickPositiveInt(overrides.stopHookWindowBytes, DEFAULTS.stopHookWindowBytes),
    enableSessionEnd: overrides.enableSessionEnd === true,
    enableStop: overrides.enableStop === true,
  };
}

function pickPositiveInt(value, fallback) {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
    return Math.floor(value);
  }
  return fallback;
}
