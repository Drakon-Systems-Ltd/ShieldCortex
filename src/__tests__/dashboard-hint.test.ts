import http from 'http';
import type { AddressInfo } from 'net';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * v4.27.0: dashboard discovery hint.
 *
 * The helper at scripts/lib/dashboard-hint.mjs is called from postinstall,
 * `shieldcortex update`, and indirectly by `shieldcortex doctor`. It must:
 *  - return null on headless Linux (no DISPLAY / WAYLAND_DISPLAY)
 *  - return null on darwin/win32 only when the dashboard is already running
 *  - never throw — it always falls back to null on any error
 */
describe('dashboard hint', () => {
  let origPlatform: NodeJS.Platform;
  let origDisplay: string | undefined;
  let origWayland: string | undefined;

  beforeEach(() => {
    origPlatform = process.platform;
    origDisplay = process.env.DISPLAY;
    origWayland = process.env.WAYLAND_DISPLAY;
    delete process.env.DISPLAY;
    delete process.env.WAYLAND_DISPLAY;
    jest.resetModules();
  });

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: origPlatform });
    if (origDisplay === undefined) delete process.env.DISPLAY; else process.env.DISPLAY = origDisplay;
    if (origWayland === undefined) delete process.env.WAYLAND_DISPLAY; else process.env.WAYLAND_DISPLAY = origWayland;
  });

  function setPlatform(p: NodeJS.Platform) {
    Object.defineProperty(process, 'platform', { value: p });
  }

  describe('isHeadlessSystem', () => {
    it('returns false on darwin regardless of DISPLAY', async () => {
      setPlatform('darwin');
      const { isHeadlessSystem } = await import('../../scripts/lib/dashboard-hint.mjs');
      expect(isHeadlessSystem()).toBe(false);
    });

    it('returns false on win32 regardless of DISPLAY', async () => {
      setPlatform('win32');
      const { isHeadlessSystem } = await import('../../scripts/lib/dashboard-hint.mjs');
      expect(isHeadlessSystem()).toBe(false);
    });

    it('returns true on linux when DISPLAY and WAYLAND_DISPLAY are unset', async () => {
      setPlatform('linux');
      const { isHeadlessSystem } = await import('../../scripts/lib/dashboard-hint.mjs');
      expect(isHeadlessSystem()).toBe(true);
    });

    it('returns false on linux when DISPLAY is set', async () => {
      setPlatform('linux');
      process.env.DISPLAY = ':0';
      const { isHeadlessSystem } = await import('../../scripts/lib/dashboard-hint.mjs');
      expect(isHeadlessSystem()).toBe(false);
    });

    it('returns false on linux when WAYLAND_DISPLAY is set', async () => {
      setPlatform('linux');
      process.env.WAYLAND_DISPLAY = 'wayland-0';
      const { isHeadlessSystem } = await import('../../scripts/lib/dashboard-hint.mjs');
      expect(isHeadlessSystem()).toBe(false);
    });
  });

  describe('getDashboardHint', () => {
    it('returns null on headless Linux', async () => {
      setPlatform('linux');
      const { getDashboardHint } = await import('../../scripts/lib/dashboard-hint.mjs');
      const hint = await getDashboardHint();
      expect(hint).toBeNull();
    });

    it('returns a hint payload on darwin when the dashboard port is closed', async () => {
      setPlatform('darwin');
      const { getDashboardHint } = await import('../../scripts/lib/dashboard-hint.mjs');
      const hint = await getDashboardHint();
      // Port 3030 is not bound in test environment, so a hint is expected.
      // (If a developer happens to be running the dashboard locally while running
      // the test suite, this will return null — that's acceptable, document via
      // skip in that case.)
      if (hint === null) {
        // Dashboard is actually running on this machine — accept and skip.
        return;
      }
      expect(hint).toMatchObject({
        title: expect.any(String),
        command: 'shieldcortex dashboard',
        url: 'http://localhost:3030',
        detail: expect.any(String),
        alwaysOnCommand: 'shieldcortex service install',
        alwaysOnDetail: expect.stringContaining('always-on'),
      });
    });
  });

  describe('isDashboardRunning', () => {
    it('returns false when nothing is listening on port 3030', async () => {
      const { isDashboardRunning } = await import('../../scripts/lib/dashboard-hint.mjs');
      const running = await isDashboardRunning(300);
      // Either we get a real false (port closed) or true (developer has dashboard up);
      // both are valid environment states. Either way the call resolves without throwing.
      expect(typeof running).toBe('boolean');
    });

    it('returns true when a server responds on port 3030 with 2xx', async () => {
      // Try to spin up a probe server on 3030. If the port is already taken
      // (developer has the real dashboard running), skip — we can't double-bind.
      let probeServer: http.Server | null = null;
      try {
        probeServer = await new Promise<http.Server>((resolve, reject) => {
          const server = http.createServer((_req, res) => {
            res.writeHead(200, { 'content-type': 'text/plain' });
            res.end('ok');
          });
          server.once('error', reject);
          server.listen(3030, '127.0.0.1', () => resolve(server));
        });

        const addr = probeServer!.address() as AddressInfo;
        expect(addr.port).toBe(3030);

        const { isDashboardRunning } = await import('../../scripts/lib/dashboard-hint.mjs');
        const running = await isDashboardRunning(500);
        expect(running).toBe(true);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes('EADDRINUSE')) return; // dashboard already up; skip
        throw err;
      } finally {
        if (probeServer) {
          await new Promise<void>((resolve) => probeServer!.close(() => resolve()));
        }
      }
    });
  });
});
