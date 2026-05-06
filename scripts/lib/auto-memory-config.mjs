import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

function getConfigPath() {
  // Honour the same SHIELDCORTEX_CONFIG_DIR override that src/cloud/config.ts
  // uses, so the runtime gate and the rest of the system always resolve to the
  // same config file (and so tests can isolate via a temp dir).
  const override = process.env.SHIELDCORTEX_CONFIG_DIR?.trim();
  const dir = override || join(homedir(), '.shieldcortex');
  return join(dir, 'config.json');
}

const DEFAULTS = Object.freeze({
  maxTranscriptBytes: 1024 * 1024,
  maxTranscriptLines: 5000,
  keepSlashCommandProse: true,
  // Lowered 10 → 5 in v4.14.0. At 1-in-10 the realistic capture rate over
  // typical sessions was ~7%, which left LTM near-empty (#44). Salience
  // bypass below catches high-signal turns at any cadence.
  stopHookSamplingTurns: 5,
  // Bypass the modulo gate when the last assistant turn carries a fenced
  // code block or hits multiple keyword categories — those turns are
  // disproportionately what we want to remember.
  stopHookSalienceBypass: true,
  stopHookWindowBytes: 256 * 1024,
  enableSessionEnd: false,
  enableStop: false,
});

export function getAutoMemoryConfig() {
  let raw = {};
  try {
    const configPath = getConfigPath();
    if (existsSync(configPath)) {
      raw = JSON.parse(readFileSync(configPath, 'utf-8'));
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
    stopHookSalienceBypass: typeof overrides.stopHookSalienceBypass === 'boolean'
      ? overrides.stopHookSalienceBypass
      : DEFAULTS.stopHookSalienceBypass,
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
