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

  it('on restart failure, prints platform-specific manual restart instructions', () => {
    // Linux hosts get systemctl, macOS gets launchctl. Edith would have
    // benefited from this clear next-step.
    expect(openclawSource).toMatch(/systemctl --user restart openclaw-gateway/);
    expect(openclawSource).toMatch(/launchctl kickstart -k gui\/\$UID\/ai\.openclaw\.gateway/);
  });
});
