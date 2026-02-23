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

// ── Re-exports ──

export { DEFAULT_IRON_DOME_CONFIG, IRON_DOME_PROFILES } from './config.js';
export type { IronDomeConfig, IronDomeProfile, IronDomePiiRules, IronDomeSubAgentRestrictions, IronDomeConfirmationProtocol, ConfirmationOverrides } from './config.js';

export { classifyAction, requiresConfirmation, requiresAnnouncement, mergeConfirmationProtocol } from './confirmation-gate.js';
export type { ConfirmationTier, ConfirmationResult } from './confirmation-gate.js';

export { scanForInjection } from './injection-scanner.js';
export type { InjectionScanResult, InjectionDetection, InjectionSeverity, InjectionCategory } from './injection-scanner.js';

export { isChannelTrusted, validateGateway } from './gateway.js';
export type { GatewayResult } from './gateway.js';

export { isActionAllowed } from './action-gate.js';
export type { ActionGateResult, ActionDecision } from './action-gate.js';

export { checkPII } from './pii-guard.js';
export type { PiiCheckResult, PiiViolation } from './pii-guard.js';

export { handleKillPhrase } from './kill-switch.js';
export type { KillSwitchResult } from './kill-switch.js';

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
 * Get the current Iron Dome status and configuration.
 */
export function getIronDomeStatus(): {
  enabled: boolean;
  config: IronDomeConfig;
  profile?: IronDomeProfile;
} {
  const config = loadConfig();
  return {
    enabled: config.enabled,
    config,
    profile: config.profile,
  };
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
