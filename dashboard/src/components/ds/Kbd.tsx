import { cn } from '@/lib/utils';

/** Keyboard-shortcut chip. */
export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        'inline-flex items-center rounded border border-[var(--sc-border)] bg-[var(--sc-surface)] px-1.5 py-0.5 font-mono text-xs text-[var(--sc-text-muted)]',
        className,
      )}
    >
      {children}
    </kbd>
  );
}
