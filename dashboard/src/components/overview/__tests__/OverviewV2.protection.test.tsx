import { render, screen } from '@testing-library/react';
import { OverviewV2 } from '@/components/overview/OverviewV2';
import { useIronDomeStatus, useControlStatus } from '@/hooks/useIronDome';
import { useContradictions, useStats, useCheckForUpdates } from '@/hooks/useMemories';
import { useReviewQueue } from '@/hooks/useReviewQueue';
import { useAuditStats, useQuarantine, useDefenceConfig } from '@/hooks/useDefence';
import { useHealthScore } from '@/hooks/useHealthScore';
import { useLicenseStatus } from '@/hooks/useLicense';
import { useXRayStatus } from '@/hooks/useXRay';

// #693: the Protection tile's Iron Dome row reports /api/iron-dome/status and
// nothing else. It must not read as an aggregate protection level, must not
// imply anything about Action Guard, and only a confirmed boolean `true` is "on".
jest.mock('@/hooks/useIronDome');
jest.mock('@/hooks/useMemories');
jest.mock('@/hooks/useReviewQueue');
jest.mock('@/hooks/useDefence');
jest.mock('@/hooks/useHealthScore');
jest.mock('@/hooks/useLicense');
jest.mock('@/hooks/useXRay');
jest.mock('@/components/MemoryWebSocketProvider', () => ({
  useWebSocketEvent: () => {},
  useWebSocketStatus: () => ({ isConnected: false, connectionFailed: false, reconnect: () => {} }),
}));
jest.mock('next/dynamic', () => ({ __esModule: true, default: () => () => null }));
jest.mock('@/components/overview/FirstRunGuide', () => ({ FirstRunGuide: () => null }));
jest.mock('@/components/shield/CloudUpsellCard', () => ({ CloudUpsellCard: () => null }));
jest.mock('@/lib/store', () => ({
  useDashboardStore: (sel?: (s: { projectFilter: null }) => unknown) => (sel ? sel({ projectFilter: null }) : { projectFilter: null }),
}));

type Q = { data: unknown; isError: boolean };
const q = (data: unknown, isError = false) => ({ data, isError, refetch: jest.fn() }) as never;
const pending = (): Q => ({ data: undefined, isError: false });

function setIronDome(r: Q) {
  (useIronDomeStatus as jest.Mock).mockReturnValue(q(r.data, r.isError));
}

/** The text of a Protection-tile row (label + pill), e.g. "Iron Dome● on". */
function rowText(label: string): string {
  return screen.getByText(label, { selector: 'span' }).parentElement!.textContent ?? '';
}

beforeEach(() => {
  for (const hook of [useControlStatus, useContradictions, useStats, useCheckForUpdates, useReviewQueue,
    useAuditStats, useQuarantine, useHealthScore, useLicenseStatus, useXRayStatus]) {
    (hook as jest.Mock).mockReturnValue(q(pending().data));
  }
  // Write firewall and operations confirmed healthy, so a differing Iron Dome
  // value is visible against them rather than aggregated with them.
  (useDefenceConfig as jest.Mock).mockReturnValue(q({ mode: 'strict', tampered: false }));
  (useControlStatus as jest.Mock).mockReturnValue(q({ killSwitchActive: false, paused: false, mode: 'running' }));
});

describe('Overview Protection tile — Iron Dome is its own row (#693)', () => {
  it('labels the row Iron Dome, never "Protection level"', () => {
    setIronDome({ data: { enabled: true }, isError: false });
    render(<OverviewV2 />);
    expect(rowText('Iron Dome')).toMatch(/\bon$/);
    expect(screen.queryByText(/Protection level/i)).not.toBeInTheDocument();
  });

  it('Iron Dome off shows off, even while the write firewall is enforced', () => {
    setIronDome({ data: { enabled: false }, isError: false });
    render(<OverviewV2 />);
    expect(rowText('Iron Dome')).toMatch(/\boff$/);
    expect(rowText('Write firewall')).toMatch(/enforced \(strict\)/);
  });

  it.each([
    ['a string "true"', { enabled: 'true' }],
    ['a missing field', {}],
    ['a null body', null],
  ])('malformed status (%s) is unknown, not on', (_name, data) => {
    setIronDome({ data, isError: false });
    render(<OverviewV2 />);
    expect(rowText('Iron Dome')).toMatch(/unknown \(unreadable status\)/);
    expect(rowText('Iron Dome')).not.toMatch(/\bon\b/);
  });

  it('loading says checking, a failed first fetch says unavailable', () => {
    setIronDome(pending());
    const { unmount } = render(<OverviewV2 />);
    expect(rowText('Iron Dome')).toMatch(/checking…/);
    unmount();
    setIronDome({ data: undefined, isError: true });
    render(<OverviewV2 />);
    expect(rowText('Iron Dome')).toMatch(/unavailable/);
  });

  it('a failed refetch drops a last-known "on" to unconfirmed', () => {
    setIronDome({ data: { enabled: true }, isError: true });
    render(<OverviewV2 />);
    expect(rowText('Iron Dome')).toMatch(/unconfirmed · refetch failed/);
    expect(rowText('Iron Dome')).not.toMatch(/\bon\b/);
  });

  it.each([
    ['on', { enabled: true }],
    ['off', { enabled: false }],
  ])('Iron Dome %s says nothing about Action Guard beyond "not shown here"', (_name, data) => {
    setIronDome({ data, isError: false });
    render(<OverviewV2 />);
    const mentions = screen.getAllByText(/Action Guard/);
    expect(mentions).toHaveLength(1);
    expect(mentions[0]).toHaveTextContent('Action Guard status is not shown here');
  });
});
