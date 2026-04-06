'use client';

import { useState } from 'react';
import { Check, Eye, EyeOff, Shield, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ds/Button';
import {
  useUpdateFindingStatus,
  useQuarantineFinding,
  useDeleteFinding,
} from '@/hooks/useXRayFindings';

interface FindingActionsProps {
  findingId: string;
  status: string;
  hasFile: boolean;
  compact?: boolean;
}

export function FindingActions({ findingId, status, hasFile, compact = false }: FindingActionsProps) {
  const [showNote, setShowNote] = useState(false);
  const [note, setNote] = useState('');
  const [acted, setActed] = useState(false);
  const updateStatus = useUpdateFindingStatus();
  const quarantine = useQuarantineFinding();
  const deleteFinding = useDeleteFinding();

  const markActed = () => setActed(true);

  const handleAction = (action: string) => {
    switch (action) {
      case 'reviewed':
        updateStatus.mutate({ id: findingId, status: 'reviewed' }, {
          onSuccess: () => toast.success('Marked as reviewed'),
          onError: (err) => toast.error(`Failed to update: ${err.message}`),
        });
        break;
      case 'ignored':
        updateStatus.mutate({ id: findingId, status: 'ignored', note }, {
          onSuccess: () => { toast.info('Finding ignored — removed from active list'); setShowNote(false); setNote(''); markActed(); },
          onError: (err) => toast.error(`Failed to ignore: ${err.message}`),
        });
        break;
      case 'resolved':
        updateStatus.mutate({ id: findingId, status: 'resolved', note }, {
          onSuccess: () => { toast.success('Finding resolved — removed from active list'); setShowNote(false); setNote(''); markActed(); },
          onError: (err) => toast.error(`Failed to resolve: ${err.message}`),
        });
        break;
      case 'quarantine':
        quarantine.mutate({ id: findingId, note }, {
          onSuccess: (data) => { toast.warning(data.moved ? 'File quarantined and moved' : 'Marked quarantined (file not found)'); markActed(); },
          onError: (err) => toast.error(`Quarantine failed: ${err.message}`),
        });
        break;
      case 'delete':
        deleteFinding.mutate(findingId, {
          onSuccess: () => { toast.success('Finding deleted'); markActed(); },
          onError: (err) => toast.error(`Failed to delete: ${err.message}`),
        });
        break;
    }
  };

  // After acting, show a brief confirmation then the card will disappear on next query refresh
  if (acted) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--sc-cyan)] italic animate-pulse">
        <Check size={12} /> Done — removing from list...
      </span>
    );
  }

  if (status === 'resolved') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--sc-cyan)]">
        <Check size={12} /> Resolved
      </span>
    );
  }

  if (status === 'quarantined') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--sc-amber)]">
        <Shield size={12} /> Quarantined
      </span>
    );
  }

  if (status === 'ignored') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-[var(--sc-text-muted)]">
        <EyeOff size={12} /> Ignored
      </span>
    );
  }

  const size = compact ? 'sm' as const : 'md' as const;
  const busy = updateStatus.isPending || quarantine.isPending || deleteFinding.isPending;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-1.5">
        {status === 'new' && (
          <Button variant="ghost" size={size} onClick={() => handleAction('reviewed')} disabled={busy}>
            <Eye size={12} /> Mark reviewed
          </Button>
        )}
        <Button variant="cyan" size={size} onClick={() => setShowNote(!showNote)} disabled={busy}>
          <Check size={12} /> Resolve
        </Button>
        <Button variant="ghost" size={size} onClick={() => handleAction('ignored')} disabled={busy}>
          <EyeOff size={12} /> Safe to ignore
        </Button>
        {hasFile && (
          <Button variant="coral" size={size} onClick={() => handleAction('quarantine')} disabled={busy}>
            <Shield size={12} /> Quarantine file
          </Button>
        )}
        <Button variant="ghost" size={size} onClick={() => handleAction('delete')} disabled={busy}>
          <Trash2 size={12} />
        </Button>
      </div>
      {showNote && (
        <div className="flex gap-2">
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="What did you do about it? (optional)"
            className="flex-1 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-3 py-1.5 text-xs text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
            aria-label="Resolution note"
            onKeyDown={(e) => { if (e.key === 'Enter') handleAction('resolved'); }}
          />
          <Button variant="cyan" size="sm" onClick={() => handleAction('resolved')} disabled={busy}>
            Done
          </Button>
        </div>
      )}
    </div>
  );
}
