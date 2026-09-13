#!/usr/bin/env node
/**
 * Fixture API entrypoint for dashboard v2 verification.
 *
 * Boots the repo's visualization API against the database given in
 * SC_FIXTURE_DB, bypassing src/index.ts's hardcoded :3001 "already running"
 * probe so a second, port-isolated fixture instance can run alongside another
 * local instance. Port comes from PORT (visualization-server default 3001).
 * All isolation env (fixture db path, skip-embeddings, config dir) is supplied
 * by the caller — see docs/design/2026-09-13-dashboard-v2-ux.md §11/§13.7.
 */
// Run the TypeScript source through tsx's loader (repo devDependency).
await import('tsx/esm/api').then(({ register }) => register());

const dbPath = process.env.SC_FIXTURE_DB;
if (!dbPath) {
  console.error('SC_FIXTURE_DB is required');
  process.exit(1);
}
const { startVisualizationServer } = await import('../../src/api/visualization-server.ts');
startVisualizationServer(dbPath);
