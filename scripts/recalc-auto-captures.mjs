#!/usr/bin/env node
/**
 * Issue #49 — back-catalogue recalc for auto-captured memories.
 *
 * One-off maintenance command. It:
 *   (a) re-flags auto-captured FRAGMENTS (mid-sentence start / trailing `?` /
 *       any current rejection-corpus hit) into the review queue by setting
 *       their status to `suppressed` — excluded from recall and eligible for
 *       the standard `prune` purge. Nothing is hand-deleted.
 *   (b) re-scores stale auto rows whose salience still exceeds the 0.6 auto cap
 *       and that are older than 7 days, under the CURRENT (capped) rules.
 *
 * DRY-RUN BY DEFAULT — prints what it WOULD do and changes nothing. Pass
 * `--apply` to commit (a DB backup is written first). The flag + re-score work
 * reuses the store/prune primitives in src/ (compiled to dist/), so this thin
 * wrapper requires a build:  `npm run build`.
 *
 * Usage:
 *   node scripts/recalc-auto-captures.mjs            # dry-run
 *   node scripts/recalc-auto-captures.mjs --apply    # commit changes
 *   node scripts/recalc-auto-captures.mjs --db <path> [--backup-dir <path>]
 */

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import fs from 'node:fs';

const here = path.dirname(fileURLToPath(import.meta.url));
const distEntry = path.resolve(here, '..', 'dist', 'cli', 'migrate-legacy.js');

if (!fs.existsSync(distEntry)) {
  console.error('[recalc] Compiled CLI not found at dist/cli/migrate-legacy.js.');
  console.error('[recalc] Build first:  npm run build');
  process.exit(1);
}

const { handleMemoriesCommand } = await import(pathToFileURL(distEntry).href);

// Reuse the exact same argument handling as `shieldcortex memories recalc`.
await handleMemoriesCommand(['recalc', ...process.argv.slice(2)]);
