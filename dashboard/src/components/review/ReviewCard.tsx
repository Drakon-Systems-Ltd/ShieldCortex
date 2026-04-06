'use client';

import { Archive, CloudOff, Globe, Pin, Star } from 'lucide-react';
import { Badge } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import type { Memory } from '@/types/memory';

function timeSince(value?: string | null) {
  if (!value) return null;
  const diffMs = Date.now() - new Date(value).getTime();
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  if (hours < 1) return 'just now';
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.floor(days / 7)}w ago`;
}

export type ReviewCardAction = 'keep' | 'suppress' | 'archive' | 'pin' | 'canonical' | 'global' | 'cloudExclude';

interface ReviewCardProps {
  memory: Memory;
  reasons: { label: string; variant: string }[];
  onAction: (action: ReviewCardAction) => void;
  busy?: boolean;
}

export function ReviewCard({ memory, reasons, onAction, busy = false }: ReviewCardProps) {
  const tags = memory.tags ?? [];
  const trustScore = memory.trustScore ?? 1;
  const age = timeSince(memory.createdAt);
  const project = memory.project?.trim();

  return (
    <div className="glass-card-strong flex flex-col">
      {/* Scrollable content region — fixed height so buttons don't shift */}
      <div className="max-h-[160px] overflow-y-auto p-6 pb-3">
        {/* Badge row */}
        <div className="flex flex-wrap gap-2">
          {reasons.map((r) => (
            <Badge key={r.label} variant={r.variant as Parameters<typeof Badge>[0]['variant']}>
              {r.label}
            </Badge>
          ))}
        </div>

        {/* Title */}
        <h3 className="mt-3 text-lg font-bold leading-tight text-[var(--sc-text-primary)]">{memory.title}</h3>

        {/* Content preview */}
        <div className="mt-2 text-sm leading-relaxed text-[var(--sc-text-secondary)]">
          {memory.content}
        </div>

        {/* Metadata row */}
        <div className="mt-2 flex flex-wrap items-center gap-1.5 text-xs text-[var(--sc-text-muted)]">
          {tags.length > 0 && <span>{tags.join(' · ')}</span>}
          {tags.length > 0 && <span>·</span>}
          {project && <><span>{project}</span><span>·</span></>}
          {age && <><span>{age}</span><span>·</span></>}
          <span>trust {trustScore.toFixed(2)}</span>
          {memory.captureMethod && <><span>·</span><span>{memory.captureMethod}</span></>}
        </div>
      </div>

      {/* Action buttons — always visible, never shift */}
      <div className="border-t border-[var(--sc-border)] px-6 py-4">
        <div className="flex flex-wrap items-center gap-3">
          <Button variant="cyan" size="sm" disabled={busy} onClick={() => onAction('keep')}>
            Keep
          </Button>
          <Button variant="coral" size="sm" disabled={busy} onClick={() => onAction('suppress')}>
            Suppress
          </Button>
          <Button variant="ghost" size="sm" disabled={busy} onClick={() => onAction('archive')}>
            <Archive className="h-3.5 w-3.5" />
            Archive
          </Button>

          <details className="ml-auto">
            <summary className="cursor-pointer text-xs text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)]">
              More actions
            </summary>
            <div className="mt-2 flex flex-wrap gap-2">
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => onAction('pin')}>
                <Pin className="h-3 w-3" />
                {memory.pinned ? 'Unpin' : 'Pin'}
              </Button>
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => onAction('canonical')}>
                <Star className="h-3 w-3" />
                Make canonical
              </Button>
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => onAction('global')}>
                <Globe className="h-3 w-3" />
                {memory.scope === 'global' ? 'Project scope' : 'Make global'}
              </Button>
              <Button variant="ghost" size="sm" disabled={busy} onClick={() => onAction('cloudExclude')}>
                <CloudOff className="h-3 w-3" />
                {memory.cloudExcluded ? 'Include in cloud' : 'Exclude from cloud'}
              </Button>
            </div>
          </details>
        </div>
      </div>
    </div>
  );
}
