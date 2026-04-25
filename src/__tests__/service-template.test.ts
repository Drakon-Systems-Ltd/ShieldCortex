import { describe, expect, it } from '@jest/globals';
import { systemdUnit, type ServiceConfig } from '../service/templates';

/**
 * v4.12.10 — the systemd unit must NOT use `StandardOutput=append:/abs/path`
 * to anywhere under ~/.shieldcortex (or any other dir that can be removed).
 * That format crash-loops with exit 209/STDOUT if the dir is ever deleted,
 * because systemd opens the StandardOutput file before any ExecStart*.
 *
 * The fix is journald — no filesystem dependency. Logs accessible via
 * `journalctl --user -u shieldcortex-dashboard.service`.
 *
 * This test guards the template so a future "let's just write a file"
 * change can't silently re-introduce the crash loop on operators who
 * later run `uninstall --clean-logs` or `rm -rf ~/.shieldcortex`.
 */
describe('systemdUnit template — journald logging (v4.12.10)', () => {
  const baseConfig: ServiceConfig = {
    nodePath: '/usr/bin/node',
    nodeBinDir: '/usr/bin',
    entryPoint: '/home/u/.npm-global/lib/node_modules/shieldcortex/dist/index.js',
    logsDir: '/home/u/.shieldcortex/logs',
    mode: 'worker',
  };

  it('routes StandardOutput and StandardError to journald, not append:', () => {
    const unit = systemdUnit(baseConfig);
    expect(unit).toMatch(/^StandardOutput=journal$/m);
    expect(unit).toMatch(/^StandardError=journal$/m);
    expect(unit).not.toMatch(/StandardOutput=append:/);
    expect(unit).not.toMatch(/StandardError=append:/);
  });

  it('does not embed the logsDir path anywhere in the unit (no fs dependency)', () => {
    const unit = systemdUnit(baseConfig);
    expect(unit).not.toContain(baseConfig.logsDir);
    expect(unit).not.toContain('.shieldcortex/logs');
  });

  it('declares a SyslogIdentifier per mode so journalctl filtering is clean', () => {
    expect(systemdUnit({ ...baseConfig, mode: 'worker' })).toMatch(/^SyslogIdentifier=shieldcortex-worker$/m);
    expect(systemdUnit({ ...baseConfig, mode: 'api' })).toMatch(/^SyslogIdentifier=shieldcortex-api$/m);
    expect(systemdUnit({ ...baseConfig, mode: 'dashboard' })).toMatch(/^SyslogIdentifier=shieldcortex-dashboard$/m);
  });

  it('keeps the rest of the unit shape (Restart, RestartSec, Type, WantedBy)', () => {
    const unit = systemdUnit(baseConfig);
    expect(unit).toMatch(/^Type=simple$/m);
    expect(unit).toMatch(/^Restart=on-failure$/m);
    expect(unit).toMatch(/^RestartSec=5$/m);
    expect(unit).toMatch(/^WantedBy=default\.target$/m);
  });
});
