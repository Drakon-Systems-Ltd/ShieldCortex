import {
  parseLaunchctlState,
  parseEtimeToSeconds,
  isProcessStale,
  detectStaleDashboard,
  maybeKickStaleDashboard,
  type StaleProbeDeps,
} from './dashboard-staleness';

const RUNNING = 'com.shieldcortex.dashboard = {\n\tstate = running\n\tpid = 1070\n}';
const STOPPED = 'com.shieldcortex.dashboard = {\n\tstate = not running\n}';

function deps(over: Partial<StaleProbeDeps & { kick: () => boolean }> = {}): StaleProbeDeps & { kick: () => boolean } {
  return {
    platform: 'darwin',
    printService: () => RUNNING,
    processStartMs: () => 100_000, // started long before the install was written
    installMtimeMs: () => 500_000, // install written after the process started → stale
    kick: () => true,
    ...over,
  };
}

describe('parseLaunchctlState', () => {
  it('reads running state + pid', () => {
    expect(parseLaunchctlState(RUNNING)).toEqual({ running: true, pid: 1070 });
  });
  it('reads a not-running service with no pid', () => {
    expect(parseLaunchctlState(STOPPED)).toEqual({ running: false, pid: null });
  });
  it('handles empty / junk output', () => {
    expect(parseLaunchctlState('')).toEqual({ running: false, pid: null });
  });
});

describe('parseEtimeToSeconds (macOS `ps -o etime=` — etimes is not a valid keyword there)', () => {
  it('parses mm:ss', () => {
    expect(parseEtimeToSeconds('32:21')).toBe(32 * 60 + 21);
  });
  it('parses hh:mm:ss', () => {
    expect(parseEtimeToSeconds('1:02:03')).toBe(3600 + 2 * 60 + 3);
  });
  it('parses dd-hh:mm:ss', () => {
    expect(parseEtimeToSeconds('3-01:02:03')).toBe(3 * 86400 + 3600 + 2 * 60 + 3);
  });
  it('tolerates leading/trailing whitespace from ps', () => {
    expect(parseEtimeToSeconds('   32:21  ')).toBe(32 * 60 + 21);
  });
  it('returns null for junk / empty', () => {
    expect(parseEtimeToSeconds('')).toBeNull();
    expect(parseEtimeToSeconds('garbage')).toBeNull();
  });
});

describe('isProcessStale', () => {
  it('is stale when the process started before the install (beyond margin)', () => {
    expect(isProcessStale(100_000, 500_000, 2000)).toBe(true);
  });
  it('is not stale when the process started after the install', () => {
    expect(isProcessStale(600_000, 500_000, 2000)).toBe(false);
  });
  it('is not stale within the clock-skew margin', () => {
    expect(isProcessStale(499_000, 500_000, 2000)).toBe(false);
  });
});

describe('detectStaleDashboard', () => {
  it('flags a running process that predates the install', () => {
    const r = detectStaleDashboard(deps());
    expect(r.stale).toBe(true);
    expect(r.pid).toBe(1070);
  });
  it('skips on non-darwin platforms', () => {
    expect(detectStaleDashboard(deps({ platform: 'linux' })).stale).toBe(false);
  });
  it('skips when the service is not loaded', () => {
    expect(detectStaleDashboard(deps({ printService: () => null })).stale).toBe(false);
  });
  it('skips when the service is loaded but not running', () => {
    expect(detectStaleDashboard(deps({ printService: () => STOPPED })).stale).toBe(false);
  });
  it('is not stale when the process is newer than the install', () => {
    expect(detectStaleDashboard(deps({ processStartMs: () => 600_000 })).stale).toBe(false);
  });
  it('fails soft when the process start time is unknown', () => {
    expect(detectStaleDashboard(deps({ processStartMs: () => null })).stale).toBe(false);
  });
  it('fails soft when the install mtime is unknown', () => {
    expect(detectStaleDashboard(deps({ installMtimeMs: () => null })).stale).toBe(false);
  });
});

describe('maybeKickStaleDashboard', () => {
  it('kicks the service when stale', () => {
    let kicked = 0;
    const r = maybeKickStaleDashboard(deps({ kick: () => (kicked++, true) }));
    expect(kicked).toBe(1);
    expect(r.kicked).toBe(true);
    expect(r.pid).toBe(1070);
  });
  it('does not kick when the process is current', () => {
    let kicked = 0;
    const r = maybeKickStaleDashboard(deps({ processStartMs: () => 600_000, kick: () => (kicked++, true) }));
    expect(kicked).toBe(0);
    expect(r.kicked).toBe(false);
  });
  it('reports kick-failed when the kick throws/returns false', () => {
    const r = maybeKickStaleDashboard(deps({ kick: () => false }));
    expect(r.kicked).toBe(false);
    expect(r.reason).toBe('kick-failed');
  });
});
