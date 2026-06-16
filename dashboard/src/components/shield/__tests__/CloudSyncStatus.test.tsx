import { render, screen } from '@testing-library/react';
import { CloudSyncStatus } from '@/components/shield/CloudSyncStatus';
import { useCloudSyncStatus } from '@/hooks/useCloudSyncStatus';

// The component imports the hook via a relative path that resolves to the same
// module the `@/` alias maps to, so this mock intercepts it.
jest.mock('@/hooks/useCloudSyncStatus');
jest.mock('@/lib/store', () => ({ useDashboardStore: () => () => {} }));

const mockHook = useCloudSyncStatus as jest.MockedFunction<typeof useCloudSyncStatus>;

describe('CloudSyncStatus — error/loading states (Phase 1)', () => {
  it('surfaces an error card with retry when the query errors (instead of rendering blank)', () => {
    mockHook.mockReturnValue({ data: undefined, isLoading: false, isError: true, refetch: jest.fn() } as never);
    render(<CloudSyncStatus />);
    expect(screen.getByText('Cloud sync status unavailable')).toBeInTheDocument();
    expect(screen.getByText('Retry')).toBeInTheDocument();
  });

  it('renders nothing while loading (compact status card)', () => {
    mockHook.mockReturnValue({ data: undefined, isLoading: true, isError: false, refetch: jest.fn() } as never);
    const { container } = render(<CloudSyncStatus />);
    expect(container).toBeEmptyDOMElement();
  });
});
