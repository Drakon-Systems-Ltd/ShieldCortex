import { formatStatsBanner } from '../stats-banner.js';
import type { LifetimeStats } from '../../defence/audit/queries.js';

function makeStats(overrides: Partial<LifetimeStats> = {}): LifetimeStats {
  return {
    totalScans:        0,
    threatsBlocked:    0,
    quarantined:       0,
    credentialLeaks:   0,
    memoriesProtected: 0,
    ...overrides,
  };
}

describe('formatStatsBanner', () => {
  it('returns null for zero stats (fresh install)', () => {
    expect(formatStatsBanner(makeStats())).toBeNull();
  });

  it('shows threats blocked when blocked > 0', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 100, threatsBlocked: 47, memoriesProtected: 53 }));
    expect(banner).not.toBeNull();
    expect(banner).toContain('47');
    expect(banner).toContain('threats blocked');
  });

  it('includes quarantined in threats blocked total', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 100, threatsBlocked: 10, quarantined: 5, memoriesProtected: 85 }));
    expect(banner).toContain('15'); // 10 + 5
    expect(banner).toContain('threats blocked');
  });

  it('shows credential leaks when present', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 50, credentialLeaks: 3, memoriesProtected: 47 }));
    expect(banner).not.toBeNull();
    expect(banner).toContain('3');
    expect(banner).toContain('credential leak');
  });

  it('uses plural for multiple credential leaks', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 50, credentialLeaks: 3, memoriesProtected: 47 }));
    expect(banner).toContain('credential leaks');
  });

  it('uses singular for one credential leak', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 50, credentialLeaks: 1, memoriesProtected: 49 }));
    expect(banner).toContain('credential leak');
    // Ensure it's not "leaks" (plural)
    expect(banner).not.toMatch(/1 credential leaks/);
  });

  it('shows memories scanned when protected > 0', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 1000, memoriesProtected: 892 }));
    expect(banner).not.toBeNull();
    expect(banner).toContain('892');
    expect(banner).toContain('memories scanned');
  });

  it('formats large numbers with commas', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 1247, memoriesProtected: 1185, threatsBlocked: 47 }));
    expect(banner).toContain('1,185'); // memoriesProtected (totalScans only shown when no other stats)
    expect(banner).toMatch(/1,\d{3}/);
  });

  it('falls back to scan count when only totalScans is set', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 50 }));
    expect(banner).not.toBeNull();
    expect(banner).toContain('50');
    expect(banner).toContain('scans completed');
  });

  it('includes shield emoji and ShieldCortex label', () => {
    const banner = formatStatsBanner(makeStats({ totalScans: 10, memoriesProtected: 10 }));
    expect(banner).toContain('ShieldCortex');
    expect(banner).toContain('🛡️');
  });
});
