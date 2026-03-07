/**
 * Iron Dome — Behaviour Protection Layer
 *
 * Protects agent BEHAVIOUR (instruction gating, action approval, injection scanning)
 * while the existing defence layer protects agent MEMORY.
 *
 * Main exports for the Iron Dome module.
 */

import { getDatabase } from '../../database/init.js';
import type { IronDomeConfig, IronDomeProfile, ConfirmationOverrides, IronDomeConfirmationProtocol } from './config.js';
import { DEFAULT_IRON_DOME_CONFIG, IRON_DOME_PROFILES } from './config.js';
import type { ConfirmationTier } from './confirmation-gate.js';
import { mergeConfirmationProtocol } from './confirmation-gate.js';
import { logIronDomeAudit } from './audit.js';
import { isFeatureEnabled } from '../../license/gate.js';
import { getCloudIronDomeCache } from '../../cloud/iron-dome-sync.js';
import type { CloudPolicy } from '../../cloud/iron-dome-sync.js';
import { isDatabaseInitialized } from '../../database/init.js';
import { handleKillPhrase } from './kill-switch.js';
import { activateKillSwitch } from '../../api/control.js';

// ── Re-exports ──

export { DEFAULT_IRON_DOME_CONFIG, IRON_DOME_PROFILES } from './config.js';
export type { IronDomeConfig, IronDomeProfile, IronDomePiiRules, IronDomeSubAgentRestrictions, IronDomeConfirmationProtocol, ConfirmationOverrides } from './config.js';

export { classifyAction, requiresConfirmation, requiresAnnouncement, mergeConfirmationProtocol } from './confirmation-gate.js';
export type { ConfirmationTier, ConfirmationResult } from './confirmation-gate.js';

import { getExternalPatternCount as _getExternalPatternCount } from './injection-scanner.js';
export { scanForInjection, setExternalPatterns, getExternalPatternCount } from './injection-scanner.js';
export type { InjectionScanResult, InjectionDetection, InjectionSeverity, InjectionCategory } from './injection-scanner.js';

export { isChannelTrusted, validateGateway } from './gateway.js';
export type { GatewayResult } from './gateway.js';

export { isActionAllowed } from './action-gate.js';
export type { ActionGateResult, ActionDecision } from './action-gate.js';

export { checkPII } from './pii-guard.js';
export type { PiiCheckResult, PiiViolation } from './pii-guard.js';

export { handleKillPhrase } from './kill-switch.js';
export type { KillSwitchResult } from './kill-switch.js';
// checkKillPhrase is defined in this file (wired version that triggers emergency stop)

export { logIronDomeAudit } from './audit.js';
export type { IronDomeAuditEvent } from './audit.js';

// ── Iron Dome State Management ──

// In-memory config (persisted to SQLite iron_dome_config table)
let activeConfig: IronDomeConfig = { ...DEFAULT_IRON_DOME_CONFIG };

/**
 * Ensure the iron_dome_config table exists.
 */
function ensureTable(): void {
  try {
    const db = getDatabase();
    db.exec(`
      CREATE TABLE IF NOT EXISTS iron_dome_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
  } catch {
    // Database may not be initialised yet — config stays in memory
  }
}

/**
 * Load Iron Dome configuration from the database.
 */
function loadConfig(): IronDomeConfig {
  try {
    ensureTable();
    const db = getDatabase();
    const row = db.prepare('SELECT value FROM iron_dome_config WHERE key = ?').get('config') as { value: string } | undefined;
    if (row) {
      activeConfig = JSON.parse(row.value);
      return activeConfig;
    }
  } catch {
    // Fall through to default
  }
  return activeConfig;
}

/**
 * Save Iron Dome configuration to the database.
 */
function saveConfig(config: IronDomeConfig): void {
  try {
    ensureTable();
    const db = getDatabase();
    db.prepare(`
      INSERT INTO iron_dome_config (key, value, updated_at)
      VALUES ('config', ?, datetime('now'))
      ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
    `).run(JSON.stringify(config));
  } catch (err) {
    console.error('[iron-dome] Failed to save config:', err);
  }
}

/**
 * Activate Iron Dome with an optional profile.
 */
export function activateIronDome(profile?: IronDomeProfile): IronDomeConfig {
  let config: IronDomeConfig;

  if (profile && IRON_DOME_PROFILES[profile]) {
    config = {
      ...IRON_DOME_PROFILES[profile],
      enabled: true,
    };
  } else {
    config = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
    };
  }

  activeConfig = config;
  saveConfig(config);

  logIronDomeAudit({
    action: 'activate',
    allowed: true,
    reason: profile ? `Activated with profile: ${profile}` : 'Activated with default config',
  });

  return config;
}

/**
 * Deactivate Iron Dome.
 */
export function deactivateIronDome(): void {
  activeConfig = { ...DEFAULT_IRON_DOME_CONFIG, enabled: false };
  saveConfig(activeConfig);

  logIronDomeAudit({
    action: 'deactivate',
    allowed: true,
    reason: 'Iron Dome deactivated',
  });
}

/**
 * Check input for the kill phrase and trigger emergency stop if detected.
 * Activates full kill switch lockdown — blocks ALL agent operations
 * (not just memory writes). Iron Dome stays active to keep protecting.
 */
export function checkKillPhrase(input: string): import('./kill-switch.js').KillSwitchResult {
  const config = loadConfig();
  const result = handleKillPhrase(input, config);
  if (result.triggered) {
    activateKillSwitch({
      source: 'kill_phrase',
      phrase: result.phrase,
    });
  }
  return result;
}

/**
 * Get the current Iron Dome status and configuration.
 */
export function getIronDomeStatus(): {
  enabled: boolean;
  config: IronDomeConfig;
  profile?: IronDomeProfile;
  cloudPolicy?: boolean;
  externalPatterns?: number;
} {
  const config = loadConfig();
  const cache = getCloudIronDomeCache();

  return {
    enabled: config.enabled,
    config,
    profile: config.profile,
    cloudPolicy: !!(cache?.policy),
    externalPatterns: _getExternalPatternCount(),
  };
}

/**
 * Get the effective Iron Dome configuration, merging policy overrides.
 *
 * Priority: local enabled flag > local custom policy (if active) > cloud policy overrides > base profile defaults
 *
 * If a local custom policy is active (dashboard-managed, SQLite), it takes
 * precedence over cloud policies. Otherwise falls through to cloud policy
 * overrides, then built-in profile defaults.
 */
export function getEffectiveIronDomeConfig(): IronDomeConfig {
  const localConfig = loadConfig();

  // If Iron Dome isn't enabled locally, don't apply any overrides
  if (!localConfig.enabled) return localConfig;

  // Custom policies require a Pro licence — return local config
  // (which uses built-in profiles) unchanged for free users
  if (!isFeatureEnabled('custom_iron_dome_policies')) return localConfig;

  // Check for active local custom policy (takes precedence over cloud)
  if (isDatabaseInitialized()) {
    try {
      const { getActiveIronDomePolicy } = require('./custom-policies.js');
      const activePolicy = getActiveIronDomePolicy();
      if (activePolicy) {
        const policyConfig = JSON.parse(activePolicy.config);
        // Use the custom policy's base profile, fall back to local
        const profileKey = policyConfig.baseProfile as IronDomeProfile;
        const baseProfile = profileKey ? IRON_DOME_PROFILES[profileKey] : null;
        const merged: IronDomeConfig = {
          ...(baseProfile ?? localConfig),
          enabled: true,
        };
        // Apply policy config overrides
        if (policyConfig.trustedChannels && Array.isArray(policyConfig.trustedChannels)) {
          merged.trustedChannels = policyConfig.trustedChannels;
        }
        if (typeof policyConfig.killPhrase === 'string') {
          merged.killPhrase = policyConfig.killPhrase;
        }
        if (policyConfig.requireApproval && Array.isArray(policyConfig.requireApproval)) {
          merged.requireApproval = policyConfig.requireApproval;
        }
        if (policyConfig.autoApprove && Array.isArray(policyConfig.autoApprove)) {
          merged.autoApprove = policyConfig.autoApprove;
        }
        if (policyConfig.piiRules && typeof policyConfig.piiRules === 'object') {
          merged.piiRules = { ...merged.piiRules, ...policyConfig.piiRules };
        }
        if (policyConfig.subAgentRestrictions && typeof policyConfig.subAgentRestrictions === 'object') {
          merged.subAgentRestrictions = { ...merged.subAgentRestrictions, ...policyConfig.subAgentRestrictions };
        }
        if (policyConfig.confirmationProtocol && typeof policyConfig.confirmationProtocol === 'object') {
          merged.confirmationProtocol = { ...merged.confirmationProtocol, ...policyConfig.confirmationProtocol };
        }
        return merged;
      }
    } catch {
      // Custom policies store not available — fall through to cloud
    }
  }

  const cache = getCloudIronDomeCache();
  if (!cache?.policy) return localConfig;

  const cloudPolicy: CloudPolicy = cache.policy;
  const profileKey = cloudPolicy.base_profile as IronDomeProfile;
  const baseProfile = IRON_DOME_PROFILES[profileKey];
  if (!baseProfile) return localConfig;

  // Start with the cloud base profile
  const merged: IronDomeConfig = {
    ...baseProfile,
    enabled: true,
  };

  // Apply config_overrides from cloud policy
  const overrides = cloudPolicy.config_overrides;
  if (overrides.trustedChannels && Array.isArray(overrides.trustedChannels)) {
    merged.trustedChannels = overrides.trustedChannels as string[];
  }
  if (typeof overrides.killPhrase === 'string') {
    merged.killPhrase = overrides.killPhrase;
  }
  if (overrides.requireApproval && Array.isArray(overrides.requireApproval)) {
    merged.requireApproval = overrides.requireApproval as string[];
  }
  if (overrides.autoApprove && Array.isArray(overrides.autoApprove)) {
    merged.autoApprove = overrides.autoApprove as string[];
  }
  if (overrides.piiRules && typeof overrides.piiRules === 'object') {
    const pii = overrides.piiRules as Record<string, unknown>;
    merged.piiRules = {
      ...merged.piiRules,
      ...(pii.neverOutput && Array.isArray(pii.neverOutput) ? { neverOutput: pii.neverOutput as string[] } : {}),
      ...(pii.aggregatesOnly && Array.isArray(pii.aggregatesOnly) ? { aggregatesOnly: pii.aggregatesOnly as string[] } : {}),
    };
  }
  if (overrides.subAgentRestrictions && typeof overrides.subAgentRestrictions === 'object') {
    const sub = overrides.subAgentRestrictions as Record<string, unknown>;
    merged.subAgentRestrictions = {
      ...merged.subAgentRestrictions,
      ...(sub.blockedOperations && Array.isArray(sub.blockedOperations) ? { blockedOperations: sub.blockedOperations as string[] } : {}),
      ...(typeof sub.sanitiseContext === 'boolean' ? { sanitiseContext: sub.sanitiseContext } : {}),
    };
  }
  if (overrides.confirmationProtocol && typeof overrides.confirmationProtocol === 'object') {
    const conf = overrides.confirmationProtocol as Record<string, unknown>;
    merged.confirmationProtocol = {
      ...merged.confirmationProtocol,
      ...(conf.red && Array.isArray(conf.red) ? { red: conf.red as string[] } : {}),
      ...(conf.amber && Array.isArray(conf.amber) ? { amber: conf.amber as string[] } : {}),
      ...(conf.green && Array.isArray(conf.green) ? { green: conf.green as string[] } : {}),
    };
  }

  return merged;
}

// ── Confirmation Override Management ──

/**
 * Get the effective (merged) confirmation protocol — base + user overrides.
 */
export function getEffectiveConfirmationProtocol(): IronDomeConfirmationProtocol {
  const config = loadConfig();
  const base = config.confirmationProtocol ?? DEFAULT_IRON_DOME_CONFIG.confirmationProtocol;
  return mergeConfirmationProtocol(base, config.confirmationOverrides);
}

/**
 * Get just the user overrides (without the base protocol).
 */
export function getConfirmationOverrides(): ConfirmationOverrides {
  const config = loadConfig();
  return config.confirmationOverrides ?? {};
}

/**
 * Move an action to a different confirmation tier.
 * Adds the action to user overrides so it takes precedence over profile defaults.
 */
export function moveConfirmationAction(action: string, tier: ConfirmationTier): void {
  const config = loadConfig();
  const overrides = config.confirmationOverrides ?? {};

  const normAction = action.toLowerCase();

  // Remove from all override tiers first
  if (overrides.red) overrides.red = overrides.red.filter(a => a.toLowerCase() !== normAction);
  if (overrides.amber) overrides.amber = overrides.amber.filter(a => a.toLowerCase() !== normAction);
  if (overrides.green) overrides.green = overrides.green.filter(a => a.toLowerCase() !== normAction);

  // Add to the target tier
  if (!overrides[tier]) overrides[tier] = [];
  overrides[tier]!.push(normAction);

  config.confirmationOverrides = overrides;
  activeConfig = config;
  saveConfig(config);

  logIronDomeAudit({
    action: 'confirmation_override',
    actionType: normAction,
    allowed: true,
    reason: `Moved "${normAction}" to ${tier.toUpperCase()} tier`,
  });
}

/**
 * Remove a user override for an action (reverts to profile default).
 * Returns true if the action was found in overrides, false if it wasn't overridden.
 */
export function removeConfirmationOverride(action: string): boolean {
  const config = loadConfig();
  const overrides = config.confirmationOverrides;
  if (!overrides) return false;

  const normAction = action.toLowerCase();
  let found = false;

  for (const tier of ['red', 'amber', 'green'] as const) {
    if (overrides[tier]) {
      const before = overrides[tier]!.length;
      overrides[tier] = overrides[tier]!.filter(a => a.toLowerCase() !== normAction);
      if (overrides[tier]!.length < before) found = true;
    }
  }

  if (found) {
    config.confirmationOverrides = overrides;
    activeConfig = config;
    saveConfig(config);

    logIronDomeAudit({
      action: 'confirmation_override',
      actionType: normAction,
      allowed: true,
      reason: `Removed override for "${normAction}" (reverted to default)`,
    });
  }

  return found;
}
