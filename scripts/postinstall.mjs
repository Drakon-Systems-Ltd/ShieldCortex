#!/usr/bin/env node
/**
 * Postinstall script - prints setup instructions after global install.
 * Does NOT auto-run setup (can fail in CI, user might not have Claude Code).
 */

// Only show message for global installs (not local dev or CI)
const isGlobal = process.env.npm_config_global === 'true';
const isCI = process.env.CI === 'true' || process.env.CONTINUOUS_INTEGRATION === 'true';

if (isGlobal && !isCI) {
  console.log('');
  console.log('\x1b[36m╭───────────────────────────────────────────────────────╮\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  \x1b[1mShieldCortex installed!\x1b[0m                              \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m                                                       \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  \x1b[1mNext step:\x1b[0m                                          \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  \x1b[33mshieldcortex setup\x1b[0m                                  \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m                                                       \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  This adds persistent memory to Claude Code.         \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  Your conversations will remember context across     \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  sessions, compactions, and projects.                \x1b[36m│\x1b[0m');
  console.log('\x1b[36m╰───────────────────────────────────────────────────────╯\x1b[0m');
  console.log('');
}
