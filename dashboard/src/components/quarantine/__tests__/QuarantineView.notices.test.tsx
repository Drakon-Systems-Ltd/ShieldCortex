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

function setup({ single = [] as unknown[], bulk = [] as unknown[], items = [item(1), item(2)] } = {}) {
  (useQuarantine as jest.Mock).mockReturnValue({
    data: { items, total: items.length },
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
  return render(<QuarantineView />);
}

function approveOne(id: number) {
  const card = screen.getByText(`held note ${id}`).closest('.glass-card') as HTMLElement;
  fireEvent.click(within(card).getByRole('button', { name: /Approve/ }));
  expect(screen.getByText(/Approval is not guaranteed: if the item cannot be admitted, it is rejected instead\./)).toBeInTheDocument();
  const dialog = screen.getByText('Approve quarantined item?').parentElement as HTMLElement;
  expect(within(dialog).queryByText(/re-scan/)).not.toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox'), { target: { value: 'YES' } });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Approve' }));
}

function approveAll() {
  fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
  const bar = screen.getByText('2 selected').parentElement as HTMLElement;
  fireEvent.click(within(bar).getByRole('button', { name: 'Approve' }));
  expect(screen.getByText(/Approval is not guaranteed: any that cannot be admitted are rejected instead\./)).toBeInTheDocument();
  const bulkDialog = screen.getByText('Approve 2 items?').parentElement as HTMLElement;
  expect(within(bulkDialog).queryByText(/re-scan/)).not.toBeInTheDocument();
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

  it.each([
    ['only memory-file findings', ['memory_file', 'memory_file'], 'Memory-file findings will be marked reviewed without editing files.'],
    [
      'memory-file findings and other items',
      ['memory_file', 'cli'],
      'Memory-file findings will be marked reviewed without editing files. The other selected items will be tried for approval; any that cannot be admitted are rejected instead.',
    ],
  ])('the bulk approve dialog for %s describes only what will happen', (_name, sources, text) => {
    setup({ items: sources.map((source_type, i) => ({ ...item(i + 1), source_type })) });
    fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
    const bar = screen.getByText('2 selected').parentElement as HTMLElement;
    fireEvent.click(within(bar).getByRole('button', { name: 'Approve' }));
    const bulkDialog = screen.getByText('Approve 2 items?').parentElement as HTMLElement;
    expect(within(bulkDialog).getByText(text, { exact: true })).toBeInTheDocument();
    expect(within(bulkDialog).queryByText(/re-scan/)).not.toBeInTheDocument();
  });
});

// #831: the bulk count, dialog copy and submitted ids only cover selected items that
// are still pending, after the list refreshes or an item is reviewed on its own.
describe('QuarantineView bulk selection after the pending list changes (#831)', () => {
  const memoryFile = (id: number) => ({ ...item(id), source_type: 'memory_file' });

  function refreshPending(items: QuarantineItem[], rerender: ReturnType<typeof render>['rerender']) {
    (useQuarantine as jest.Mock).mockReturnValue({
      data: { items, total: items.length },
      isLoading: false,
      isError: false,
      error: null,
      refetch: jest.fn(),
    });
    rerender(<QuarantineView />);
  }

  function openBulk(action: 'Approve' | 'Reject', count: number) {
    const bar = screen.getByText(`${count} selected`).parentElement as HTMLElement;
    fireEvent.click(within(bar).getByRole('button', { name: action }));
    return screen.getByText(`${action} ${count} item${count !== 1 ? 's' : ''}?`).parentElement as HTMLElement;
  }

  function submitBulk(action: 'Approve' | 'Reject', count: number) {
    fireEvent.click(screen.getByRole('button', { name: `${action} ${count} item${count !== 1 ? 's' : ''}` }));
  }

  it('bulk approve counts and submits only the items still pending', () => {
    const { rerender } = setup({ items: [item(1), item(2), item(3)], bulk: [{ success: true, updated: 2, total: 2, promoted: 2, rejected: 0 }] });
    fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
    expect(screen.getByText('3 selected')).toBeInTheDocument();
    refreshPending([item(2), item(3)], rerender);
    const dialog = openBulk('Approve', 2);
    expect(
      within(dialog).getByText(
        'This will try to approve all selected items. Approval is not guaranteed: any that cannot be admitted are rejected instead.',
        { exact: true },
      ),
    ).toBeInTheDocument();
    submitBulk('Approve', 2);
    expect((useBulkApproveQuarantine as jest.Mock)().mutate).toHaveBeenCalledWith([2, 3], expect.anything());
  });

  it('bulk approve of a memory-file finding whose companion left says only the memory-file outcome', () => {
    const { rerender } = setup({ items: [memoryFile(1), item(2)], bulk: [{ success: true, updated: 1, total: 1, promoted: 0, rejected: 0 }] });
    fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
    refreshPending([memoryFile(1)], rerender);
    expect(screen.queryByText('held note 2')).not.toBeInTheDocument();
    const dialog = openBulk('Approve', 1);
    expect(
      within(dialog).getByText('Memory-file findings will be marked reviewed without editing files.', { exact: true }),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/other selected items/i)).not.toBeInTheDocument();
    expect(within(dialog).queryByText(/re-scan/)).not.toBeInTheDocument();
    submitBulk('Approve', 1);
    expect((useBulkApproveQuarantine as jest.Mock)().mutate).toHaveBeenCalledWith([1], expect.anything());
  });

  it('bulk reject of a memory-file finding whose companion left does not mention other memories', () => {
    const { rerender } = setup({ items: [memoryFile(1), item(2)] });
    fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
    refreshPending([memoryFile(1)], rerender);
    const dialog = openBulk('Reject', 1);
    expect(
      within(dialog).getByText('Memory-file findings will be dismissed without editing files.', { exact: true }),
    ).toBeInTheDocument();
    expect(within(dialog).queryByText(/Other selected memories will be discarded\./)).not.toBeInTheDocument();
    submitBulk('Reject', 1);
    expect((useBulkRejectQuarantine as jest.Mock)().mutate).toHaveBeenCalledWith([1]);
  });

  it('bulk reject keeps the other-memories wording only while another selected memory is pending', () => {
    const { rerender } = setup({ items: [memoryFile(1), item(2), item(3)] });
    fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
    refreshPending([memoryFile(1), item(2)], rerender);
    const dialog = openBulk('Reject', 2);
    expect(
      within(dialog).getByText(
        'Memory-file findings will be dismissed without editing files. Other selected memories will be discarded.',
        { exact: true },
      ),
    ).toBeInTheDocument();
    submitBulk('Reject', 2);
    expect((useBulkRejectQuarantine as jest.Mock)().mutate).toHaveBeenCalledWith([1, 2]);
  });

  it('an item reviewed on its own drops out of the bulk selection', () => {
    const { rerender } = setup({ items: [item(1), item(2)] });
    fireEvent.click(screen.getByRole('button', { name: /Select all/ }));
    const card = screen.getByText('held note 1').closest('.glass-card') as HTMLElement;
    fireEvent.click(within(card).getByRole('button', { name: /Reject/ }));
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'YES' } });
    const single = screen.getByText('Reject quarantined item?').parentElement as HTMLElement;
    fireEvent.click(within(single).getByRole('button', { name: 'Reject' }));
    expect((useRejectQuarantine as jest.Mock)().mutate).toHaveBeenCalledWith({ id: 1 });
    refreshPending([item(2)], rerender);
    const dialog = openBulk('Reject', 1);
    expect(within(dialog).getByText('This will permanently discard all selected memories.', { exact: true })).toBeInTheDocument();
    submitBulk('Reject', 1);
    expect((useBulkRejectQuarantine as jest.Mock)().mutate).toHaveBeenCalledWith([2]);
  });
});
