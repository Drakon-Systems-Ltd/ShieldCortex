/**
 * Iron Dome — Kill Switch
 *
 * Handles kill phrase detection. When the kill phrase is detected
 * in input, Iron Dome immediately halts all processing.
 */

import type { IronDomeConfig } from './config.js';
import { logIronDomeAudit } from './audit.js';

export interface KillSwitchResult {
  triggered: boolean;
  phrase: string;
}

/**
 * Check if the input contains the kill phrase.
 */
export function handleKillPhrase(
  input: string,
  config: IronDomeConfig,
): KillSwitchResult {
  if (!config.enabled || !config.killPhrase) {
    return { triggered: false, phrase: '' };
  }

  const normInput = input.toLowerCase().trim();
  const normPhrase = config.killPhrase.toLowerCase().trim();
  const triggered = normInput.includes(normPhrase);

  if (triggered) {
    logIronDomeAudit({
      action: 'kill_switch',
      allowed: false,
      reason: `Kill phrase "${config.killPhrase}" detected`,
    });
  }

  return {
    triggered,
    phrase: config.killPhrase,
  };
}
