import { fireEvent, render, screen, within } from '@testing-library/react';
import { QuarantineView } from '@/components/quarantine/QuarantineView';
import {
  useQuarantine,
  useApproveQuarantine,
  useRejectQuarantine,
  useBulkApproveQuarantine,
  useBulkRejectQuarantine,
  useReviewCopilotStatus,
  useAnnotateQuarantine,
  useAnnotatePendingQuarantine,
  type QuarantineItem,
} from '@/hooks/useDefence';

// #824/#828: the Quarantine view reports approvals that ended rejected, and the
// wording does not claim a re-scan (BLOCK rows and rate limits refuse without one).
jest.mock('@/hooks/useDefence');
jest.mock('@/lib/store', () => ({ useDashboardStore: () => ({ projectFilter: null }) }));

function item(id: number): QuarantineItem {
  return {
    id,
    title: `held note ${id}`,
    content: 'content',
    source_type: 'cli',
    source_identifier: 'mcp',
    reason: 'held',
    threat_indicators: '[]',
    anomaly_score: 0.5,
    status: 'pending',
    created_at: '2026-10-18T00:00:00Z',
    reviewed_at: null,
    reviewed_by: null,
    annotation: null,
  };
}

/** A mutation hook result whose mutate() resolves with the next queued result. */
function mutation(results: unknown[] = []) {
  const queue = [...results];
  return {
    mutate: jest.fn((_arg: unknown, opts?: { onSuccess?: (r: unknown) => void }) => {
      opts?.onSuccess?.(queue.shift());
    }),
    error: null,
    isPending: false,
  } as never;
}

function setup({ single = [] as unknown[], bulk = [] as unknown[] } = {}) {
  (useQuarantine as jest.Mock).mockReturnValue({
    data: { items: [item(1), item(2)], total: 2 },
    isLoading: false,
    isError: false,
    error: null,
    refetch: jest.fn(),
  });
  (useReviewCopilotStatus as jest.Mock).mockReturnValue({ data: undefined });
  (useApproveQuarantine as jest.Mock).mockReturnValue(mutation(single));
  (useBulkApproveQuarantine as jest.Mock).mockReturnValue(mutation(bulk));
  (useRejectQuarantine as jest.Mock).mockReturnValue(mutation());
  (useBulkRejectQuarantine as jest.Mock).mockReturnValue(mutation());
  (useAnnotateQuarantine as jest.Mock).mockReturnValue(mutation());
  (useAnnotatePendingQuarantine as jest.Mock).mockReturnValue(mutation());
  render(<QuarantineView />);
}

function approveOne(id: number) {
  const card = screen.getByText(`held note ${id}`).closest('.glass-card') as HTMLElement;
  fireEvent.click(within(card).getByRole('button', { name: /Approve/ }));
  expect(screen.getByText(/Its content is re-scanned first and may still be refused\./)).toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox'), { target: { value: 'YES' } });
  const dialog = screen.getByText('Approve quarantined item?').parentElement as HTMLElement;
  fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
}

function approveAll() {
  fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
  const bar = screen.getByText('2 selected').parentElement as HTMLElement;
  fireEvent.click(within(bar).getByRole('button', { name: 'Approve' }));
  expect(screen.getByText(/Their content is re-scanned first and some may still be refused\./)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Approve 2 items' }));
}

describe('QuarantineView approval notices (#824, #828)', () => {
  it('a refused single approval shows the status and the reason', () => {
    setup({ single: [{ success: false, id: 1, status: 'rejected', reason: 'hard-blocked content is never re-admitted' }] });
    approveOne(1);
    expect(screen.getByRole('status')).toHaveTextContent(
      'Item #1 was not approved: hard-blocked content is never re-admitted. It is now rejected.',
    );
  });

  it('a mixed bulk batch shows the rejected count without claiming a re-scan', () => {
    setup({ bulk: [{ success: true, updated: 2, total: 2, promoted: 1, rejected: 1 }] });
    approveAll();
    const notice = screen.getByRole('status');
    expect(notice).toHaveTextContent(
      '1 of 2 selected items was not approved: it could not be admitted. It is now rejected, not added to memory.',
    );
    expect(notice).not.toHaveTextContent(/re-scan/);
  });

  it('the notice clears on a later successful approval', () => {
    setup({
      single: [
        { success: false, id: 1, status: 'rejected', reason: 'still held on re-scan: agent_manipulation' },
        { success: true, id: 2, status: 'approved', memoryId: 7 },
      ],
    });
    approveOne(1);
    expect(screen.getByRole('status')).toHaveTextContent('Item #1 was not approved');
    approveOne(2);
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });

  it.each([
    ['zero', { success: true, updated: 2, total: 2, promoted: 2, rejected: 0 }],
    ['absent', { success: true, updated: 2, total: 2, promoted: 2 }],
  ])('no notice when the rejected count is %s', (_name, result) => {
    setup({ bulk: [result] });
    approveAll();
    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
