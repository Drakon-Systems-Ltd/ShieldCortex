/**
 * Per-Session API Auth Token
 *
 * Generates a random token on server start, writes it to
 * ~/.shieldcortex/.api-token (0600 permissions), and validates
 * incoming requests against it. Cleaned up on shutdown.
 */

import { randomBytes, timingSafeEqual } from 'crypto';
import { mkdirSecure } from '../setup/state-permissions.js';
import { readFileSync, writeFileSync, unlinkSync, existsSync, mkdirSync, chmodSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

const CONFIG_DIR = join(homedir(), '.shieldcortex');
const TOKEN_FILE = join(CONFIG_DIR, '.api-token');

// In-memory cache — avoids repeated file reads
let cachedToken: string | null = null;

/** Operator-configured long-lived token (non-loopback / automation). */
function envApiToken(): string | null {
  const v = (process.env.SHIELDCORTEX_API_TOKEN || '').trim();
  return v.length > 0 ? v : null;
}

/**
 * Generate a new session token, write to disk, and return it.
 * Called once on server start.
 */
export function generateSessionToken(): string {
  // Prefer operator env token when set (required for non-loopback binds).
  const fromEnv = envApiToken();
  if (fromEnv) {
    cachedToken = fromEnv;
    // Still write a session file for local dashboard tooling when possible,
    // but never log the value.
    try {
      mkdirSecure(CONFIG_DIR);
      writeFileSync(TOKEN_FILE, fromEnv, { mode: 0o600 });
      try { chmodSync(TOKEN_FILE, 0o600); } catch { /* best-effort */ }
    } catch {
      // Env token alone is enough to authenticate; disk write is convenience.
    }
    return fromEnv;
  }
  const token = randomBytes(32).toString('hex');
  mkdirSecure(CONFIG_DIR);
  writeFileSync(TOKEN_FILE, token, { mode: 0o600 });
  try {
    chmodSync(TOKEN_FILE, 0o600);
  } catch {
    // Best-effort on platforms that don't support chmod
  }
  cachedToken = token;
  return token;
}

/**
 * Read the current session token from disk (or cache).
 */
export function getSessionToken(): string | null {
  if (cachedToken) return cachedToken;
  const fromEnv = envApiToken();
  if (fromEnv) {
    cachedToken = fromEnv;
    return cachedToken;
  }
  try {
    if (existsSync(TOKEN_FILE)) {
      cachedToken = readFileSync(TOKEN_FILE, 'utf-8').trim();
      return cachedToken;
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * Validate a token using constant-time comparison.
 */
export function validateSessionToken(token: string): boolean {
  const expected = getSessionToken();
  if (!expected) return false;
  try {
    const a = Buffer.from(token, 'utf-8');
    const b = Buffer.from(expected, 'utf-8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Delete the token file on shutdown.
 */
export function cleanupSessionToken(): void {
  cachedToken = null;
  try {
    if (existsSync(TOKEN_FILE)) {
      unlinkSync(TOKEN_FILE);
    }
  } catch { /* ignore */ }
}
