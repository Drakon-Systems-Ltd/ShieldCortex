'use client';

import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { cn } from '@/lib/utils';

interface DrawerProps {
  open: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  children: React.ReactNode;
  /** Width on ≥768px screens; below that the drawer is a full-screen sheet. */
  widthClass?: string;
  className?: string;
}

/**
 * Right-side detail drawer. ≥768px: fixed panel on the right; below: full
 * screen sheet. Esc closes, focus moves in on open. Native semantics — no
 * dialog dependency.
 */
export function Drawer({ open, onClose, title, children, widthClass = 'md:w-[400px]', className }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    // Move focus into the drawer so keyboard users land on the close button.
    panelRef.current?.querySelector<HTMLElement>('button, [href], input, select, textarea')?.focus();
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-40" role="presentation">
      <div
        className="absolute inset-0 bg-black/30"
        aria-hidden
        onMouseDown={onClose}
      />
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-label={typeof title === 'string' ? title : 'Details'}
        className={cn(
          'absolute inset-y-0 right-0 flex w-full flex-col border-l border-[var(--sc-border)] bg-[var(--sc-surface)] shadow-[var(--sc-shadow-drawer)]',
          widthClass,
          className,
        )}
      >
        <div className="flex h-12 shrink-0 items-center justify-between gap-2 border-b border-[var(--sc-border)] px-4">
          <div className="min-w-0 truncate text-sm font-medium text-[var(--sc-text)]">{title}</div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close details"
            className="rounded-md p-1.5 text-[var(--sc-text-muted)] transition-colors hover:bg-[var(--sc-surface-2)] hover:text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
          >
            <X size={16} aria-hidden />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto p-4">{children}</div>
      </div>
    </div>
  );
}
