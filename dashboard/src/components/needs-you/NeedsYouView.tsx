'use client';

import Link from 'next/link';
import { ArrowRight, Clock3, FileSearch, Inbox, ShieldQuestion, Split } from 'lucide-react';
import { PageHeader } from '@/components/ds/PageHeader';
import { EmptyState } from '@/components/ds/EmptyState';
import { useNeedsYou, type NeedsYouSource } from '@/hooks/useNeedsYou';
import { useDashboardStore } from '@/lib/store';
import { sourceCountText } from '@/lib/needs-you';

/**
 * Needs you (Opus design §2, §5 step 4, phase A): one place for everything
 * waiting on a person. Real data only where a read endpoint already exists —
 * held-back items, memories to check and scanner findings — each linking to
 * the existing view where the decision is made. Held actions need a broker
 * read endpoint that does not exist yet, so that section says so plainly.
 *
 * Honesty rules (#692): "Nothing needs you" only when every list confirmed an
 * exact zero; stale counts are labelled last known; review counts are pairs and
 * may be floors; scanner findings are for the whole computer, not the project.
 */
export function NeedsYouView() {
  const project = useDashboardStore((s) => s.projectFilter);
  const n = useNeedsYou(project);
  const coverage = n.pairCoverage;

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto max-w-5xl space-y-6 p-6">
        <PageHeader
          title="Needs you"
          subtitle={
            project
              ? `Waiting for your decision. Held back and memories to check: project ${project}. Scanner findings: this whole computer.`
              : 'Everything waiting for your decision, in one list.'
          }
        />

        {n.allClear && (
          <EmptyState
            icon={Inbox}
            message="Nothing needs you in the lists the dashboard can check: held-back items, memories to check and scanner findings. Actions waiting for a yes are answered in your approval channel."
          />
        )}
        {!n.allClear && n.anyFailed && (
          <p className="text-sm text-[var(--sc-warn)]" role="status">
            Some lists couldn&apos;t be checked just now, so this may not be everything waiting for you.
          </p>
        )}
        {!n.allClear && !n.anyFailed && n.anyPending && n.confirmedTotal === 0 && (
          <p className="text-sm text-[var(--sc-text-muted)]" role="status">Checking what needs you…</p>
        )}
        {!n.anyFailed && !n.anyPending && !n.exact && n.confirmedTotal === 0 && (
          <p className="text-sm text-[var(--sc-text-muted)]" role="status">
            Nothing found so far, but not every memory was checked, so this is not a full all-clear.
          </p>
        )}

        <section aria-labelledby="ny-held-actions" className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-5">
          <div className="flex items-start gap-3">
            <Clock3 size={18} aria-hidden className="mt-0.5 shrink-0 text-[var(--sc-text-muted)]" />
            <div className="min-w-0 space-y-2">
              <h2 id="ny-held-actions" className="text-lg font-semibold text-[var(--sc-text)]">
                Actions waiting for a yes <span className="ml-1 text-sm font-normal text-[var(--sc-text-muted)]">coming soon</span>
              </h2>
              <p className="text-sm text-[var(--sc-text-dim)]">
                When an agent tries something that needs your approval, it will show here as a card that says
                what it wants to do, why ShieldCortex stopped it, and who is asking.
              </p>
              <p className="text-sm text-[var(--sc-text-dim)]">
                The dashboard cannot list or answer these yet. For now, answer them in your approval channel
                (Telegram or OpenClaw).
              </p>
            </div>
          </div>
        </section>

        <QueueSection
          id="ny-held-back"
          icon={<ShieldQuestion size={18} aria-hidden />}
          title="Held back"
          unit="waiting"
          source={n.heldBack}
          explain="Memory writes and file findings ShieldCortex kept out until you decide."
          href="/protection?tab=quarantine"
          cta="Review held-back items"
        >
          {n.heldBackItems.length > 0 && (
            <ul className="mt-3 divide-y divide-[var(--sc-border)] rounded-md border border-[var(--sc-border)]">
              {n.heldBackItems.slice(0, 5).map((item) => (
                <li key={item.id} className="flex items-baseline justify-between gap-3 px-3 py-2 text-sm">
                  <span className="min-w-0 truncate text-[var(--sc-text)]">{item.title || 'Untitled memory'}</span>
                  <span className="shrink-0 truncate text-xs text-[var(--sc-text-muted)]">{item.reason}</span>
                </li>
              ))}
            </ul>
          )}
        </QueueSection>

        <QueueSection
          id="ny-memories"
          icon={<Split size={18} aria-hidden />}
          title="Memories to check"
          unit={n.memories.count === 1 && !n.memories.atLeast ? 'pair' : 'pairs'}
          source={n.memories}
          explain={
            n.memories.count
              ? `${n.contradictions.toLocaleString()} pairs that disagree, ${n.duplicates.toLocaleString()} pairs that look like duplicates. One memory can be in more than one pair.`
              : 'Pairs of memories that disagree with each other, or look like duplicates.'
          }
          href="/memory?tab=review"
          cta="Check memories"
        >
          {coverage && (coverage.contradictions.capped || coverage.duplicates.capped) && (
            <p className="mt-2 text-sm text-[var(--sc-text-muted)]">
              Only the first {coverage.limit.toLocaleString()} pairs of each kind are counted, so there may be more.
            </p>
          )}
          {coverage?.contradictions.scanPartial && (
            <p className="mt-2 text-sm text-[var(--sc-text-muted)]">
              The disagreement check compares only the {coverage.contradictions.scanWindow.toLocaleString()} most important
              of {coverage.contradictions.candidates.toLocaleString()} memories.
            </p>
          )}
          {n.memories.status !== 'pending' && n.memories.status !== 'unavailable' && !coverage && (
            <p className="mt-2 text-sm text-[var(--sc-text-muted)]">This server did not say how many pairs it checked, so there may be more.</p>
          )}
        </QueueSection>

        <QueueSection
          id="ny-scanner"
          icon={<FileSearch size={18} aria-hidden />}
          title="Scanner findings"
          unit="new"
          source={n.scanner}
          explain="New findings from the skill & package scanner that nobody has looked at yet. These cover this whole computer: the project filter does not apply to them."
          href="/xray?tab=findings"
          cta="Look at findings"
        />
      </div>
    </div>
  );
}

function QueueSection({
  id, icon, title, unit, source, explain, href, cta, children,
}: {
  id: string;
  icon: React.ReactNode;
  title: string;
  unit: string;
  source: NeedsYouSource;
  explain: string;
  href: string;
  cta: string;
  children?: React.ReactNode;
}) {
  const waiting = (source.count ?? 0) > 0;
  // Keep the place you decide reachable whenever the list might not be empty.
  const showLink = waiting || source.status === 'unavailable' || source.status === 'stale' || source.atLeast;
  return (
    <section aria-labelledby={id} className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-5">
      <div className="flex items-start gap-3">
        <span className={waiting ? 'mt-0.5 shrink-0 text-[var(--sc-warn)]' : 'mt-0.5 shrink-0 text-[var(--sc-text-muted)]'}>{icon}</span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 id={id} className="text-lg font-semibold text-[var(--sc-text)]">
              {title}{' '}
              <span className="ml-1 text-sm font-normal tabular-nums text-[var(--sc-text-muted)]">
                {sourceCountText(source, unit)}
              </span>
            </h2>
            {showLink && (
              <Link href={href} className="flex items-center gap-1 text-sm font-medium text-[var(--sc-primary)] hover:underline">
                {cta} <ArrowRight size={14} aria-hidden />
              </Link>
            )}
          </div>
          <p className="mt-1 text-sm text-[var(--sc-text-dim)]">{explain}</p>
          {source.status === 'unavailable' && (
            <p className="mt-2 text-sm text-[var(--sc-warn)]">
              Couldn&apos;t load this list, so it may not be empty.{' '}
              {source.error && <span className="text-[var(--sc-text-dim)]">{source.error}{' '}</span>}
              <button type="button" onClick={source.refetch} className="text-[var(--sc-primary)] underline">Retry</button>
            </p>
          )}
          {source.status === 'stale' && (
            <p className="mt-2 text-sm text-[var(--sc-warn)]">
              Showing the last known count: the latest check failed, so it may have changed.{' '}
              <button type="button" onClick={source.refetch} className="text-[var(--sc-primary)] underline">Retry</button>
            </p>
          )}
          {source.status === 'confirmed' && source.count === 0 && !source.atLeast && (
            <p className="mt-2 text-sm text-[var(--sc-text-muted)]">Nothing here right now.</p>
          )}
          {children}
        </div>
      </div>
    </section>
  );
}
