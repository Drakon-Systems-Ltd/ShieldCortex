'use client';

import { useEffect, useRef } from 'react';
import { Button } from '@/components/ds/Button';
import { cn } from '@/lib/utils';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  /** Must name the exact target of the action (brief §3.4). */
  description: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  pending?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Confirm dialog on the native <dialog> element: real focus trap, Esc closes,
 * backdrop click cancels. No new dependency (brief §3.8 / GPT review #8).
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  danger = false,
  pending = false,
  onConfirm,
  onCancel,
}: ConfirmDialogProps) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      onClose={onCancel}
      onMouseDown={(e) => { if (e.target === ref.current) onCancel(); }}
      className={cn(
        'm-auto w-full max-w-md rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-0 text-[var(--sc-text)] shadow-[var(--sc-shadow-drawer)]',
        'backdrop:bg-black/40',
      )}
    >
      <div className="p-5">
        <h2 className="text-sm font-semibold">{title}</h2>
        <div className="mt-2 text-sm text-[var(--sc-text-muted)]">{description}</div>
        <div className="mt-5 flex justify-end gap-2">
          <Button variant="ghost" onClick={onCancel} disabled={pending}>
            {cancelLabel}
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} disabled={pending}>
            {pending ? 'Working…' : confirmLabel}
          </Button>
        </div>
      </div>
    </dialog>
  );
}
