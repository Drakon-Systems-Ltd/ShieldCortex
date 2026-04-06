'use client';

import { AnimatePresence, motion } from 'framer-motion';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import type { OpenClawSessionSummary } from '@/hooks/useMemories';

interface SessionCardProps {
  session: OpenClawSessionSummary;
  expanded: boolean;
  onToggle: () => void;
}

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  const weeks = Math.floor(days / 7);
  return `${weeks}w ago`;
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

export function SessionCard({ session, expanded, onToggle }: SessionCardProps) {
  const model = session.models[0] || 'model unknown';

  return (
    <GlassCard hover className="p-4">
      <button onClick={onToggle} className="w-full text-left">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 rounded-full ${session.threats > 0 ? 'bg-[var(--sc-coral)]' : 'bg-[var(--sc-cyan)]'}`} />
              <span className="truncate text-sm font-medium text-[var(--sc-text-primary)]">
                {session.sessionId}
              </span>
            </div>
            <div className="mt-1 pl-4 text-xs text-[var(--sc-text-muted)]">
              {relativeTime(session.lastSeenAt)} · {model}
            </div>
          </div>
          <span className="shrink-0 text-xs text-[var(--sc-text-muted)]">
            {expanded ? '▾' : '▸'}
          </span>
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <Badge variant="muted">Saved: {session.saved}</Badge>
          <Badge variant="muted">Skipped: {session.skipped}</Badge>
          <Badge variant={session.threats > 0 ? 'coral' : 'muted'}>
            Threats: {session.threats}
          </Badge>
          {session.autoExtracted > 0 && (
            <Badge variant="muted">Auto: {session.autoExtracted}</Badge>
          )}
          {session.quarantined > 0 && (
            <Badge variant="amber">Quarantined: {session.quarantined}</Badge>
          )}
        </div>
      </button>

      <AnimatePresence>
        {expanded && session.memories.length > 0 && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeInOut' }}
            className="overflow-hidden"
          >
            <div className="mt-3 border-t border-[var(--sc-border)] pt-3 space-y-2">
              {session.memories.map((memory) => (
                <div
                  key={memory.id}
                  className="flex items-center justify-between gap-3 rounded-lg bg-[var(--sc-bg-elevated)]/60 px-3 py-2"
                >
                  <div className="min-w-0">
                    <div className="truncate text-sm text-[var(--sc-text-primary)]">
                      {memory.title}
                    </div>
                    <div className="mt-0.5 flex items-center gap-2">
                      <Badge variant="muted">{memory.category}</Badge>
                      <span className="text-xs text-[var(--sc-text-muted)]">
                        {formatDate(memory.createdAt)}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </GlassCard>
  );
}
