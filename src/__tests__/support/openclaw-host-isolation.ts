/**
 * #260 r15 (Jarvis 1): host isolation for suites that can reach a code path
 * that launches OpenClaw. A test in this PR once ran a REAL `openclaw` with a
 * forced install: emptying PATH did not stop `which openclaw` from finding it.
 *
 * Two layers, both required:
 *  - the code under test takes its launcher as an explicit parameter, and the
 *    suite passes a recording fake (see `repairOpenClawManagedPins`'s deps);
 *  - {@link installLaunchTripwire} mocks `child_process` so every real
 *    launcher throws AND is recorded; {@link expectNoLaunch} fails the test if
 *    any was called, even when the code under test swallowed the throw.
 *
 * {@link isolateHostEnv} scrubs the variables that can point code at a host's
 * OpenClaw, ShieldCortex, multi-clawd or Claude state and points HOME at a
 * temp dir. It keeps only the Jest config sandbox (`SHIELDCORTEX_CONFIG_DIR`,
 * `SHIELDCORTEX_AUDIT_DIR`, set by scripts/jest-config-sandbox.mjs, which
 * point INTO the sandbox) and `SHIELDCORTEX_SKIP_EMBEDDINGS` (set by
 * run-jest). Scrubbing those would widen what a test can touch.
 *
 * Call {@link installLaunchTripwire} at the top level of the test file, BEFORE
 * any (dynamic) import of code that uses `child_process`.
 */
import { createRequire } from 'module';
import { expect, jest } from '@jest/globals';

type Launcher = ReturnType<typeof jest.fn>;
const LAUNCHERS = ['execSync', 'execFileSync', 'spawnSync', 'spawn', 'exec', 'execFile', 'fork'] as const;

export interface LaunchTripwire {
  launchers: Record<(typeof LAUNCHERS)[number], Launcher>;
  /** Forget earlier calls (beforeEach). */
  reset(): void;
}

export function installLaunchTripwire(): LaunchTripwire {
  const launchers = Object.fromEntries(LAUNCHERS.map((name) => [name, jest.fn((...args: unknown[]): never => {
    throw new Error(`tripwire: child_process.${name}(${JSON.stringify(args[0])}) must not run in this suite`);
  })])) as LaunchTripwire['launchers'];
  // The real module's other exports stay; a self-import here would recurse.
  const actual = createRequire(import.meta.url)('child_process') as Record<string, unknown>;
  jest.unstable_mockModule('child_process', () => ({ ...actual, ...launchers, default: { ...actual, ...launchers } }));
  return {
    launchers,
    reset() {
      for (const fn of Object.values(launchers)) fn.mockClear();
    },
  };
}

/** Fail the test if any real launcher was called. */
export function expectNoLaunch(tripwire: LaunchTripwire): void {
  const called = Object.entries(tripwire.launchers)
    .filter(([, fn]) => fn.mock.calls.length > 0)
    .map(([name, fn]) => [name, fn.mock.calls.map((c) => c[0])]);
  expect(called).toEqual([]);
}

const SCRUB = /^(OPENCLAW_|SHIELDCORTEX_|MULTI_CLAWD_|CLAUDE)/;
const KEEP = new Set(['SHIELDCORTEX_CONFIG_DIR', 'SHIELDCORTEX_AUDIT_DIR', 'SHIELDCORTEX_SKIP_EMBEDDINGS']);

/**
 * Scrub host-pointing variables and set HOME (and USERPROFILE) to `home`.
 * Returns a function that restores the environment exactly as it was.
 */
export function isolateHostEnv(home: string): () => void {
  const saved = { ...process.env };
  for (const key of Object.keys(process.env)) {
    if (SCRUB.test(key) && !KEEP.has(key)) delete process.env[key];
  }
  process.env.HOME = home;
  process.env.USERPROFILE = home;
  return () => {
    for (const key of Object.keys(process.env)) {
      if (!(key in saved)) delete process.env[key];
    }
    Object.assign(process.env, saved);
  };
}
