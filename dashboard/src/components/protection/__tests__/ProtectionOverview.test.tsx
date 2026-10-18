import { render, screen, within } from '@testing-library/react';
import { ProtectionOverview } from '@/components/protection/ProtectionOverview';
import { useIronDomeStatus } from '@/hooks/useIronDome';
import { useAuditStats, useQuarantine } from '@/hooks/useDefence';
import { useInterceptorEvents } from '@/hooks/useInterceptorEvents';

// #693: the first stat card measures Iron Dome only. It must not be labelled
// as an overall protection level, must say Action Guard is not included, and
// only a confirmed boolean `true` may read "On".
jest.mock('@/hooks/useIronDome');
jest.mock('@/hooks/useDefence');
jest.mock('@/hooks/useInterceptorEvents');
jest.mock('next/navigation', () => ({
  usePathname: () => '/protection',
  useSearchParams: () => new URLSearchParams(''),
  useRouter: () => ({ replace: jest.fn(), push: jest.fn(), prefetch: jest.fn(), back: jest.fn() }),
}));
// The tab bodies have their own data and tests; only the stats row is under test.
jest.mock('@/components/dome/IronDomeView', () => ({ IronDomeView: () => null }));
jest.mock('@/components/quarantine/QuarantineView', () => ({ QuarantineView: () => null }));
jest.mock('@/components/audit/AuditLogView', () => ({ AuditLogView: () => null }));
jest.mock('@/components/protection/InterceptorEventsView', () => ({ InterceptorEventsView: () => null }));
jest.mock('@/components/protection/PolicyManagementView', () => ({ PolicyManagementView: () => null }));

const q = (data: unknown, isError = false) => ({ data, isError, refetch: jest.fn() }) as never;

beforeEach(() => {
  (useAuditStats as jest.Mock).mockReturnValue(q({ blockedCount: 0 }));
  (useQuarantine as jest.Mock).mockReturnValue(q({ total: 0 }));
  (useInterceptorEvents as jest.Mock).mockReturnValue(q({ summary: { total: 0 } }));
});

/** The Iron Dome stat card: label, value and hint. */
function ironDomeCard(): HTMLElement {
  return screen.getByText('Iron Dome', { selector: 'span' }).parentElement!.parentElement!;
}
function ironDomeValue(): string {
  return ironDomeCard().children[1].textContent ?? '';
}

describe('Protection stats row — Iron Dome card (#693)', () => {
  it.each([
    ['confirmed on', { enabled: true }, false, 'On'],
    ['confirmed off', { enabled: false }, false, 'Off'],
    ['loading', undefined, false, 'Checking…'],
    ['failed first fetch', undefined, true, 'Unavailable'],
    ['failed refetch, last known on', { enabled: true }, true, 'Unconfirmed'],
    ['failed refetch, last known off', { enabled: false }, true, 'Off'],
    ['malformed enabled ("true")', { enabled: 'true' }, false, 'Unknown'],
    ['malformed body (null)', null, false, 'Unknown'],
  ])('%s → %s', (_name, data, isError, expected) => {
    (useIronDomeStatus as jest.Mock).mockReturnValue(q(data, isError));
    render(<ProtectionOverview />);
    expect(ironDomeValue()).toBe(expected);
  });

  it('is labelled Iron Dome, not "Protection level", and excludes Action Guard', () => {
    (useIronDomeStatus as jest.Mock).mockReturnValue(q({ enabled: true }));
    render(<ProtectionOverview />);
    expect(ironDomeCard()).toHaveTextContent('Does not include Action Guard.');
    // The Status tab keeps its navigation name; no stat card claims a level.
    const statsRow = ironDomeCard().parentElement!;
    expect(within(statsRow).queryByText(/Protection level/i)).not.toBeInTheDocument();
  });

  it('says when the shown value is from a failed check', () => {
    (useIronDomeStatus as jest.Mock).mockReturnValue(q({ enabled: false }, true));
    render(<ProtectionOverview />);
    expect(ironDomeCard()).toHaveTextContent('Last check failed. Does not include Action Guard.');
  });
});
