/**
 * Post-build: copy .next/static and public into the standalone output.
 *
 * Next.js standalone mode only emits server files — static assets must
 * be copied manually so the standalone server can serve them.
 * See: https://nextjs.org/docs/app/api-reference/config/next-config-js/output#automatically-copying-traced-files
 */

import { cpSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const dashboardRoot = resolve(__dirname, '..');
const standalone = resolve(dashboardRoot, '.next/standalone/dashboard');

if (!existsSync(standalone)) {
  console.log('[copy-static] No standalone output found — skipping.');
  process.exit(0);
}

// Copy .next/static → standalone/.next/static
const staticSrc = resolve(dashboardRoot, '.next/static');
const staticDest = resolve(standalone, '.next/static');
if (existsSync(staticSrc)) {
  cpSync(staticSrc, staticDest, { recursive: true });
  console.log('[copy-static] Copied .next/static → standalone');
}

// Copy public → standalone/public
const publicSrc = resolve(dashboardRoot, 'public');
const publicDest = resolve(standalone, 'public');
if (existsSync(publicSrc)) {
  cpSync(publicSrc, publicDest, { recursive: true });
  console.log('[copy-static] Copied public → standalone');
}

console.log('[copy-static] Done.');
