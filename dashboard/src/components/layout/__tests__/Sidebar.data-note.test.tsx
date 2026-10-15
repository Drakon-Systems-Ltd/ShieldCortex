import { render, screen } from '@testing-library/react';
import { Sidebar } from '@/components/layout/Sidebar';
import { useCloudStatus, type CloudConfig } from '@/hooks/useCloudStatus';

// #693: the sidebar footer used to say "Data stays on this computer" in every
// state, while Settings can sync metadata or full content to the cloud. The
// note now follows the confirmed cloud config and claims nothing it can't see.
jest.mock('@/hooks/useCloudStatus');
// Needs you summary shape from main (#692): every list confirmed, nothing waiting, so no badge.
jest.mock('@/hooks/useNeedsYou', () => ({
  useNeedsYou: () => ({ confirmedTotal: 0, exact: true, anyFailed: false, anyPending: false, allClear: true }),
}));
jest.mock('next/navigation', () => ({ usePathname: () => '/overview' }));
jest.mock('@/lib/store', () => ({
  useDashboardStore: () => ({ sidebarPinned: false, toggleSidebarPinned: jest.fn(), projectFilter: null }),
}));

const mockCloud = useCloudStatus as jest.MockedFunction<typeof useCloudStatus>;

function config(enabled: boolean, contentMode: 'full' | 'metadata'): CloudConfig {
  return {
    enabled,
    apiKeySet: enabled,
    baseUrl: 'https://api.shieldcortex.ai',
    syncControls: { projectMode: 'all', projects: [], contentMode, excludeSensitive: false },
    openclawMemory: { autoMemory: false, dedupe: false, noveltyThreshold: 0.88, maxRecent: 300 },
  };
}
const q = (data: CloudConfig | undefined, isError = false) => ({ data, isError, refetch: jest.fn() }) as never;

describe('Sidebar data note (#693)', () => {
  it.each([
    ['cloud sync off', q(config(false, 'full')), 'Stored on this computer · cloud sync off'],
    ['full-content sync on', q(config(true, 'full')), 'Cloud sync on · memory content leaves this computer'],
    ['metadata-only sync on', q(config(true, 'metadata')), 'Cloud sync on · metadata leaves this computer'],
    ['config loading', q(undefined), 'Checking cloud sync…'],
    ['config fetch failed', q(undefined, true), 'Cloud sync status unknown'],
    // Last known "off" with a failed refetch must not keep the local claim.
    ['config refetch failed', q(config(false, 'full'), true), 'Cloud sync status unknown'],
  ])('%s', (_name, result, expected) => {
    mockCloud.mockReturnValue(result);
    render(<Sidebar />);
    expect(screen.getByText(expected)).toBeInTheDocument();
  });

  it.each([
    ['sync off', q(config(false, 'full'))],
    ['sync on', q(config(true, 'full'))],
    ['loading', q(undefined)],
    ['failed', q(undefined, true)],
  ])('never makes the unconditional "Data stays on this computer" promise (%s)', (_name, result) => {
    mockCloud.mockReturnValue(result);
    render(<Sidebar />);
    expect(screen.queryByText(/Data stays on this computer/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/stays on this computer/i)).not.toBeInTheDocument();
  });

  it('keeps the five-item nav whatever the sync state', () => {
    mockCloud.mockReturnValue(q(config(true, 'full')));
    render(<Sidebar />);
    expect(screen.getAllByRole('link').map((a) => a.textContent)).toEqual(['Home', 'Needs you', 'Memory', 'Protection', 'Settings']);
  });
});
