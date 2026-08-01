import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { describe, expect, it } from '@jest/globals';

/**
 * v4.12.6 makes `shieldcortex openclaw install` auto-restart the OpenClaw
 * gateway after install (with `--no-gateway-restart` opt-out), symmetric
 * with `uninstall --deep`. Without this, an upgrade of the npm package
 * leaves the running gateway with the old plugin in memory until something
 * else triggers a restart — observed on Edith 2026-04-25 where the npm
 * package was on 4.12.5 but the loaded plugin was still 4.12.2, silently
 * producing zero memories.
 *
 * Runtime invocation isn't viable here because src/setup/openclaw.ts
 * trips the baseline ESM/CJS issue Jest has on this repo (same reason
 * hook-hash-stability uses source analysis). We assert source-level
 * invariants instead.
 */
describe('openclaw install — auto gateway restart (v4.12.6)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const openclawSource = fs.readFileSync(path.join(repoRoot, 'src', 'setup', 'openclaw.ts'), 'utf-8');

  it('OpenClawInstallOptions declares restartGateway', () => {
    expect(openclawSource).toMatch(/restartGateway\?:\s*boolean/);
  });

  it('handleOpenClawCommand parses --no-gateway-restart and inverts it', () => {
    expect(openclawSource).toMatch(/extraArgs\.includes\(['"]--no-gateway-restart['"]\)/);
    expect(openclawSource).toMatch(/restartGateway\s*=\s*!extraArgs\.includes/);
  });

  it('handleOpenClawCommand passes restartGateway to installOpenClawHook', () => {
    const installCase = openclawSource.match(
      /case\s+['"]install['"]:\s*\n[\s\S]*?installOpenClawHook\(([^)]*)\)/,
    );
    expect(installCase).not.toBeNull();
    expect(installCase![1]).toMatch(/restartGateway/);
  });

  it('installOpenClawHook gates the restart behind options.restartGateway !== false (default true)', () => {
    // Restart fires by default; only an explicit `false` opts out.
    expect(openclawSource).toMatch(/options\.restartGateway\s*!==\s*false/);
  });

  it('installOpenClawHook only restarts when something was actually installed', () => {
    // Don't waste a restart when both --no-hooks and --no-plugins are passed
    // and nothing landed on disk.
    expect(openclawSource).toMatch(/didInstallSomething\s*=\s*installed\s*>\s*0\s*\|\|\s*pluginInstallMode\s*!==\s*['"]skipped['"]/);
  });

  it('install advertises --no-gateway-restart in the usage block', () => {
    expect(openclawSource).toMatch(/--no-gateway-restart/);
    const usageBlock = openclawSource.match(/Install options:[\s\S]*?process\.exit\(1\)/);
    expect(usageBlock).not.toBeNull();
    expect(usageBlock![0]).toMatch(/--no-gateway-restart/);
  });

  it('reuses restartOpenClawGateway from deep-clean (does not duplicate the implementation)', () => {
    // Accept either a static `import ... from './deep-clean.js'`
    // or a dynamic `await import('./deep-clean.js')`.
    expect(openclawSource).toMatch(/(?:from|import\s*\()\s*['"]\.\/deep-clean(?:\.js)?['"]/);
    expect(openclawSource).toMatch(/restartOpenClawGateway/);
  });

  it('on restart failure, prints platform-specific manual restart instructions', async () => {
    // Asserted against the shared resolver rather than by grepping this file
    // for literals: the literals moved once already, and a test that only knows
    // where the string USED to live proves nothing about what an operator sees.
    const { gatewayRestartCommand } = await import('../setup/gateway-restart-command.js');

    expect(gatewayRestartCommand('linux').command).toBe('systemctl --user restart openclaw-gateway');
    expect(gatewayRestartCommand('darwin', 501).command)
      .toBe('launchctl kickstart -k gui/501/ai.openclaw.gateway');
    // A Mac must never be handed the Linux command — the live #154 failure.
    expect(gatewayRestartCommand('darwin', 501).advice).not.toMatch(/systemctl/);
    expect(gatewayRestartCommand('linux').advice).not.toMatch(/launchctl/);

    // And the install path must route through it rather than reintroducing a
    // hardcoded branch of its own.
    expect(openclawSource).toMatch(/gatewayRestartAdvice\(\)/);
    expect(openclawSource).not.toMatch(/'\s*systemctl --user restart openclaw-gateway\s*'/);
  });

  it('refuses to invent a command for a platform it has not verified', async () => {
    // Guessing is how a Mac got told to run systemctl. Unknown means unknown.
    const { gatewayRestartCommand } = await import('../setup/gateway-restart-command.js');
    const win = gatewayRestartCommand('win32');
    expect(win.command).toBeNull();
    expect(win.advice).not.toMatch(/systemctl|launchctl/);
  });

  it('prints a copy-pasteable darwin command even when the uid is unreadable', async () => {
    const { gatewayRestartCommand } = await import('../setup/gateway-restart-command.js');
    expect(gatewayRestartCommand('darwin', null).command)
      .toBe('launchctl kickstart -k gui/$(id -u)/ai.openclaw.gateway');
  });
});

describe('restartOpenClawGateway — never fires from a test runner', () => {
  // Unmocked install-path tests were restarting the LIVE gateway on the host
  // during `npm test` (Jarvis 2026-07-02: 8 live bounces in one morning, each
  // killing every in-flight agent turn). The implementation must refuse to
  // exec when running under Jest, regardless of what any test passes in.
  it('returns skipped under JEST_WORKER_ID without exec-ing anything', async () => {
    const { restartOpenClawGateway } = await import('../setup/deep-clean.js');
    expect(process.env.JEST_WORKER_ID).toBeDefined();
    const result = await restartOpenClawGateway();
    expect(result.attempted).toBe(false);
    expect(result.restarted).toBe(false);
    expect(result.method).toBe('skipped');
  });

  it('source guards on JEST_WORKER_ID, NODE_ENV=test, and the manual escape hatch', () => {
    const thisFile = fileURLToPath(import.meta.url);
    const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
    const deepCleanSource = fs.readFileSync(
      path.join(repoRoot, 'src', 'setup', 'deep-clean.ts'),
      'utf-8',
    );
    const guard = deepCleanSource.match(
      /restartOpenClawGateway[\s\S]{0,800}?JEST_WORKER_ID[\s\S]{0,300}?SHIELDCORTEX_SKIP_GATEWAY_RESTART/,
    );
    expect(guard).not.toBeNull();
    // The guard must come before the first execSync in the function body.
    const fnBody = deepCleanSource.slice(deepCleanSource.indexOf('export async function restartOpenClawGateway'));
    expect(fnBody.indexOf('JEST_WORKER_ID')).toBeLessThan(fnBody.indexOf('execSync'));
  });
});

describe('restartOpenClawGateway — host-safety invariant: no implicit restart headless', () => {
  // Directive (Michael, 2026-07-02): ShieldCortex must never break the
  // gateway or the agent. The remaining auto-vector after PR #64 was
  // `shieldcortex setup`/`update` run headless (agent, cron, SSH exec):
  // installOpenClawHook ends with a best-effort gateway restart that would
  // kill every in-flight turn on the host — including the agent running
  // the install. Non-TTY sessions now require the explicit
  // SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1 consent to restart.
  function withEnv(patch: Record<string, string | undefined>, fn: () => Promise<void>): Promise<void> {
    const saved = new Map<string, string | undefined>();
    for (const key of Object.keys(patch)) saved.set(key, process.env[key]);
    for (const [key, value] of Object.entries(patch)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    return fn().finally(() => {
      for (const [key, value] of saved) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    });
  }

  it('non-TTY without consent env returns the non-interactive skip (never reaches exec)', async () => {
    const originalIsTTY = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    Object.defineProperty(process.stdin, 'isTTY', { value: undefined, configurable: true });
    try {
      await withEnv(
        { JEST_WORKER_ID: undefined, NODE_ENV: 'production', SHIELDCORTEX_SKIP_GATEWAY_RESTART: undefined, SHIELDCORTEX_ALLOW_GATEWAY_RESTART: undefined },
        async () => {
          const { restartOpenClawGateway } = await import('../setup/deep-clean.js');
          const result = await restartOpenClawGateway();
          expect(result.attempted).toBe(false);
          expect(result.restarted).toBe(false);
          expect(result.method).toBe('skipped');
          expect(result.detail).toMatch(/non-interactive/);
        },
      );
    } finally {
      if (originalIsTTY) Object.defineProperty(process.stdin, 'isTTY', originalIsTTY);
      else Reflect.deleteProperty(process.stdin, 'isTTY');
    }
  });

  it('consent env cannot bypass the test-runner guard (ordering)', async () => {
    await withEnv({ SHIELDCORTEX_ALLOW_GATEWAY_RESTART: '1' }, async () => {
      const { restartOpenClawGateway } = await import('../setup/deep-clean.js');
      expect(process.env.JEST_WORKER_ID).toBeDefined();
      const result = await restartOpenClawGateway();
      expect(result.attempted).toBe(false);
      expect(result.detail).toMatch(/test runner/);
    });
  });

  it('source shape: consent gate sits after the test-runner guard and before execSync', () => {
    const thisFile = fileURLToPath(import.meta.url);
    const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
    const deepCleanSource = fs.readFileSync(
      path.join(repoRoot, 'src', 'setup', 'deep-clean.ts'),
      'utf-8',
    );
    const fnBody = deepCleanSource.slice(
      deepCleanSource.indexOf('export async function restartOpenClawGateway'),
    );
    const jestGuard = fnBody.indexOf('JEST_WORKER_ID');
    const consentGate = fnBody.indexOf('SHIELDCORTEX_ALLOW_GATEWAY_RESTART');
    const ttyCheck = fnBody.indexOf('process.stdin.isTTY');
    const firstExec = fnBody.indexOf('execSync');
    expect(jestGuard).toBeGreaterThan(-1);
    expect(consentGate).toBeGreaterThan(jestGuard);
    expect(ttyCheck).toBeGreaterThan(jestGuard);
    expect(firstExec).toBeGreaterThan(consentGate);
    expect(firstExec).toBeGreaterThan(ttyCheck);
  });
});
