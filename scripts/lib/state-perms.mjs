// scripts/lib/state-perms.mjs
//
// #218 — the .mjs half of "create state-tree paths already owner-only".
//
// The TS source has src/setup/state-permissions.ts (SECURE_DIR_MODE 0o700,
// SECURE_OPEN_MODE 0o600, mkdirSecure). The hooks and the installer are a
// separate build that cannot import from src/, so the same two modes live here
// as the ONE source of truth for the script side — no bare 0o700 literal
// scattered across six hooks.
//
// Why it matters: mkdir's mode binds only at CREATION and is ignored for a dir
// that already exists, and open(2)/writeFile without a mode use 0666 & ~umask
// (644, or 664 under umask 002). Every path a hook or the installer recreates
// after the install-time hardening pass would otherwise land loose again, and
// doctor fails on it after the next gateway restart.

import { mkdirSync } from 'node:fs';

/** Owner-only directory mode. Mirrors SECURE_DIR_MODE. */
export const STATE_DIR_MODE = 0o700;

/** Owner-only file mode for openSync/writeFileSync. Mirrors SECURE_FILE_MODE. */
export const STATE_FILE_MODE = 0o600;

/** Create a directory (and parents) inside the state tree already owner-only. */
export function mkdirSecure(dir) {
  mkdirSync(dir, { recursive: true, mode: STATE_DIR_MODE });
}
