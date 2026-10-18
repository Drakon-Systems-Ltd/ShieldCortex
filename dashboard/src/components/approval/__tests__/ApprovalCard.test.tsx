import { render, screen, within } from '@testing-library/react';
import { ApprovalCard, DISABLED_REASON, type ApprovalCardData } from '@/components/approval/ApprovalCard';
import { APPROVAL_CARD_FIXTURES } from '@/components/approval/ApprovalCard.fixtures';

const STATES = Object.keys(APPROVAL_CARD_FIXTURES) as ApprovalCardData['state'][];

describe('ApprovalCard (read-only, #648 What / Why / Who)', () => {
  it('renders What, Why and Who from the structured card, verbatim', () => {
    const card = APPROVAL_CARD_FIXTURES.waiting;
    render(<ApprovalCard card={card} />);
    const terms = screen.getAllByRole('term').map((t) => t.textContent);
    expect(terms.slice(0, 3)).toEqual(['What', 'Why', 'Who']);
    const defs = screen.getAllByRole('definition').map((d) => d.textContent);
    expect(defs.slice(0, 3)).toEqual([card.what, card.why, card.who]);
    expect(screen.getByText(card.footer)).toBeInTheDocument();
  });

  it.each(STATES)('%s: has no enabled approve control', (state) => {
    render(<ApprovalCard card={APPROVAL_CARD_FIXTURES[state]} />);
    for (const button of screen.queryAllByRole('button')) expect(button).toBeDisabled();
    expect(screen.queryByRole('button', { name: /always allow|approve all|allow all/i })).toBeNull();
    // Reject and Review approval are both present and equally weighted.
    const reject = screen.getByRole('button', { name: 'Reject' });
    const review = screen.getByRole('button', { name: 'Review approval' });
    expect(reject.className).toBe(review.className);
    // The reason is visible text, tied to both buttons.
    const reasonId = reject.getAttribute('aria-describedby')!;
    expect(review.getAttribute('aria-describedby')).toBe(reasonId);
    expect(document.getElementById(reasonId)!.textContent!.length).toBeGreaterThan(0);
  });

  it('waiting: points to the approval channel for now', () => {
    render(<ApprovalCard card={APPROVAL_CARD_FIXTURES.waiting} />);
    expect(screen.getByText('Answer this in your approval channel (Telegram/OpenClaw) for now.')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ShieldCortex needs a yes/ })).toBeInTheDocument();
  });

  it('after approval says the result is pending, never that the action completed', () => {
    render(<ApprovalCard card={APPROVAL_CARD_FIXTURES['approved-awaiting-result']} />);
    expect(screen.getByRole('heading', { name: 'Approval recorded; awaiting result' })).toBeInTheDocument();
    expect(screen.queryByText(/action completed/i)).toBeNull();
  });

  it('expired, resolved and disconnected each say why the decision is off', () => {
    const { unmount } = render(<ApprovalCard card={APPROVAL_CARD_FIXTURES.expired} />);
    expect(screen.getByText(DISABLED_REASON.expired)).toBeInTheDocument();
    unmount();
    const r = render(<ApprovalCard card={APPROVAL_CARD_FIXTURES.resolved} />);
    expect(screen.getByText(/already been answered: Rejected in Telegram/)).toBeInTheDocument();
    r.unmount();
    render(<ApprovalCard card={APPROVAL_CARD_FIXTURES.disconnected} />);
    expect(screen.getByText(DISABLED_REASON.disconnected)).toBeInTheDocument();
  });

  it('renders untrusted card text as text, not markup', () => {
    const hostile = '<img src=x onerror="alert(1)">';
    const { container } = render(<ApprovalCard card={{ ...APPROVAL_CARD_FIXTURES.waiting, what: hostile, details: { command: hostile } }} />);
    expect(container.querySelector('img')).toBeNull();
    expect(within(container).getAllByText(hostile).length).toBeGreaterThan(0);
  });
});
