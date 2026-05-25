/**
 * Persistent state for the Pro-tier upsell nudge.
 *
 * Lives in its own file (`~/.shieldcortex/upsell-state.json`) rather than
 * inside `config.json` so a corrupt write — or a hand-edit gone wrong — can't
 * damage the cloud-sync configuration. The state is purely for throttling
 * and mute; losing it just means the nudge could re-show prematurely (worst
 * case: one extra impression).
 */

import fs from 'fs';
import path from 'path';
import os from 'os';

export interface UpsellState {
  /** Epoch ms when the Pro upsell was last rendered to the user. */
  proLastShownAt: number | null;
  /** When true, never show the Pro upsell again until the user un-mutes. */
  proMuted: boolean;
}

const DEFAULT_STATE: UpsellState = {
  proLastShownAt: null,
  proMuted: false,
};

function statePath(): string {
  return path.join(os.homedir(), '.shieldcortex', 'upsell-state.json');
}

/**
 * Read state from disk. Never throws — returns defaults on any failure
 * (missing file, malformed JSON, permission error). The upsell flow is
 * always best-effort; a broken state file should not affect the doctor's
 * exit code or user experience.
 */
export function getUpsellState(): UpsellState {
  try {
    const raw = fs.readFileSync(statePath(), 'utf-8');
    const parsed = JSON.parse(raw) as Partial<UpsellState>;
    return {
      proLastShownAt:
        typeof parsed.proLastShownAt === 'number' && Number.isFinite(parsed.proLastShownAt)
          ? parsed.proLastShownAt
          : null,
      proMuted: parsed.proMuted === true,
    };
  } catch {
    return { ...DEFAULT_STATE };
  }
}

/**
 * Merge updates into state and persist. Creates `~/.shieldcortex/` if it
 * doesn't exist (first-run case). Silent on write errors — same rationale
 * as the read path.
 */
export function setUpsellState(updates: Partial<UpsellState>): void {
  try {
    const dir = path.dirname(statePath());
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    const current = getUpsellState();
    const next: UpsellState = { ...current, ...updates };
    fs.writeFileSync(statePath(), JSON.stringify(next, null, 2), 'utf-8');
  } catch {
    /* best-effort */
  }
}

/** Convenience: mark the upsell as shown now. Used by doctor after rendering. */
export function markUpsellShown(now: number = Date.now()): void {
  setUpsellState({ proLastShownAt: now });
}
