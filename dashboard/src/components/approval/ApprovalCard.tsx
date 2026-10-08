'use client';

import { useId } from 'react';
import { CheckCircle2, Clock3, PlugZap, TimerOff } from 'lucide-react';
import { cn } from '@/lib/utils';

/**
 * The #648 approval card as data. The broker already builds these fields:
 * `what`, `why` and `who` are `ApprovalCardSummary.action / .reason / .who`
 * (src/defence/iron-dome/approval-card.ts) and `footer` is the last line of
 * `formatApprovalCardLines` ("Allow once or deny · expires in 10 min"). They
 * render exactly as given — this component never re-parses card text.
 */
export interface ApprovalCardData {
  what: string;
  why: string;
  who: string;
  footer: string;
  /**
   * Where the decision stands. Only `waiting` is answerable at all, and even
   * then not from the dashboard yet (no broker endpoint takes its answer).
   */
  state: 'waiting' | 'approved-awaiting-result' | 'expired' | 'resolved' | 'disconnected';
  /** For `resolved`: who answered and how, e.g. "Rejected in Telegram". */
  resolution?: string;
  /** Raw evidence, shown after the plain text, never instead of it. */
  details?: { tool?: string; command?: string; rule?: string };
}

/** Why the decision buttons are off, in plain words, per state (Astra §4). */
export const DISABLED_REASON: Record<ApprovalCardData['state'], string> = {
  waiting: 'Answer this in your approval channel (Telegram/OpenClaw) for now.',
  'approved-awaiting-result': 'Already approved once. There is nothing left to decide.',
  expired: 'This request expired, so it can no longer be answered. The agent has to ask again.',
  resolved: 'This request has already been answered.',
  disconnected: "The dashboard can't reach ShieldCortex right now, so it can't take an answer.",
};

const HEADER: Record<ApprovalCardData['state'], { text: string; icon: typeof Clock3 }> = {
  waiting: { text: 'ShieldCortex needs a yes', icon: Clock3 },
  'approved-awaiting-result': { text: 'Approval recorded; awaiting result', icon: CheckCircle2 },
  expired: { text: 'This request expired', icon: TimerOff },
  resolved: { text: 'Already answered', icon: CheckCircle2 },
  disconnected: { text: 'Not connected', icon: PlugZap },
};

/**
 * Read-only held-action card (Opus §4 layout, Astra §4 decision controls).
 * "Reject" and "Review approval" are equally weighted, never preselected, and
 * rendered disabled with the reason beside them: there is no bulk approve and
 * no "Always allow". Enabling them — "Review approval" opening a confirmation
 * of the exact scope whose final button is "Approve this action once" — waits
 * for a broker endpoint that accepts a dashboard answer.
 */
export function ApprovalCard({ card, className }: { card: ApprovalCardData; className?: string }) {
  const id = useId();
  const reasonId = `${id}-reason`;
  const header = HEADER[card.state];
  const HeaderIcon = header.icon;
  const waiting = card.state === 'waiting';
  const reason = card.state === 'resolved' && card.resolution
    ? `This request has already been answered: ${card.resolution}.`
    : DISABLED_REASON[card.state];

  return (
    <article
      aria-labelledby={`${id}-title`}
      className={cn(
        'overflow-hidden rounded-lg border bg-[var(--sc-surface)]',
        waiting ? 'border-[var(--sc-warn)]' : 'border-[var(--sc-border)]',
        className,
      )}
    >
      <header
        className={cn(
          'flex flex-wrap items-center justify-between gap-2 px-5 py-3',
          waiting ? 'bg-[var(--sc-warn-soft)]' : 'bg-[var(--sc-surface-2)]',
        )}
      >
        <h3 id={`${id}-title`} className={cn('flex items-center gap-2 text-base font-semibold', waiting ? 'text-[var(--sc-warn)]' : 'text-[var(--sc-text)]')}>
          <HeaderIcon size={18} aria-hidden />
          {header.text}
        </h3>
      </header>

      <div className="space-y-4 px-5 py-4">
        <dl className="grid grid-cols-[4rem_minmax(0,1fr)] gap-x-4 gap-y-2 text-base">
          <dt className="font-semibold text-[var(--sc-text-dim)]">What</dt>
          <dd className="text-[var(--sc-text)]">{card.what}</dd>
          <dt className="font-semibold text-[var(--sc-text-dim)]">Why</dt>
          <dd className="text-[var(--sc-text)]">{card.why}</dd>
          <dt className="font-semibold text-[var(--sc-text-dim)]">Who</dt>
          <dd className="text-[var(--sc-text)]">{card.who}</dd>
        </dl>

        <div className="flex flex-wrap items-center gap-3">
          {/* Equal weight: same size and outline style, neither filled. */}
          <DecisionButton describedBy={reasonId}>Reject</DecisionButton>
          <DecisionButton describedBy={reasonId}>Review approval</DecisionButton>
          <p id={reasonId} className="text-sm text-[var(--sc-text-dim)]">{reason}</p>
        </div>

        {card.details && (card.details.tool || card.details.command || card.details.rule) && (
          <details className="text-sm">
            <summary className="cursor-pointer text-[var(--sc-primary)] underline underline-offset-2">Show technical details</summary>
            <dl className="mt-2 grid grid-cols-[7rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-[var(--sc-text-dim)]">
              {card.details.tool && (<><dt>Tool</dt><dd className="font-mono text-[var(--sc-text)]">{card.details.tool}</dd></>)}
              {card.details.command && (<><dt>Command</dt><dd className="break-all font-mono text-[var(--sc-text)]">{card.details.command}</dd></>)}
              {card.details.rule && (<><dt>Matched rule</dt><dd className="text-[var(--sc-text)]">{card.details.rule}</dd></>)}
            </dl>
            <p className="mt-2 text-xs text-[var(--sc-text-muted)]">From the agent, shown as plain text. Secrets are withheld.</p>
          </details>
        )}
      </div>

      <footer className="border-t border-[var(--sc-border)] px-5 py-2.5 text-sm text-[var(--sc-text-muted)]">
        {card.footer}
      </footer>
    </article>
  );
}

function DecisionButton({ children, describedBy }: { children: React.ReactNode; describedBy: string }) {
  return (
    <button
      type="button"
      disabled
      aria-describedby={describedBy}
      className="h-10 min-w-32 rounded-md border border-[var(--sc-border-strong)] bg-transparent px-4 text-sm font-semibold text-[var(--sc-text-dim)] disabled:cursor-not-allowed"
    >
      {children}
    </button>
  );
}
