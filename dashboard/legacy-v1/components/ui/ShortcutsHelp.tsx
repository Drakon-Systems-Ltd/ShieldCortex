'use client';

import { useEffect, useRef } from 'react';

interface ShortcutsHelpProps {
  open: boolean;
  onClose: () => void;
}

interface Shortcut {
  keys: string[];
  description: string;
}

const navigationShortcuts: Shortcut[] = [
  { keys: ['g', 's'], description: 'Go to Shield view' },
  { keys: ['g', 'm'], description: 'Go to Memories view' },
  { keys: ['g', 't'], description: 'Go to Timeline view' },
  { keys: ['g', 'g'], description: 'Go to Graph view' },
  { keys: ['g', 'a'], description: 'Go to Audit view' },
  { keys: ['g', 'b'], description: 'Go to Brain view' },
  { keys: ['g', 'd'], description: 'Go to Dome view' },
];

const actionShortcuts: Shortcut[] = [
  { keys: ['/'], description: 'Focus search input' },
  { keys: ['Esc'], description: 'Close panel / blur search' },
  { keys: ['?'], description: 'Toggle this help overlay' },
];

function KeyBadge({ children }: { children: string }) {
  return (
    <kbd className="inline-flex items-center justify-center min-w-[1.5rem] h-6 px-2 bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded text-xs font-mono text-[var(--sc-text-primary)] shadow-sm">
      {children}
    </kbd>
  );
}

function ShortcutRow({ shortcut }: { shortcut: Shortcut }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <span className="text-sm text-[var(--sc-text-primary)]">{shortcut.description}</span>
      <div className="flex items-center gap-1 ml-4 shrink-0">
        {shortcut.keys.map((key, i) => (
          <span key={i} className="flex items-center gap-1">
            {i > 0 && <span className="text-[var(--sc-text-muted)] text-xs">then</span>}
            <KeyBadge>{key}</KeyBadge>
          </span>
        ))}
      </div>
    </div>
  );
}

export function ShortcutsHelp({ open, onClose }: ShortcutsHelpProps) {
  const overlayRef = useRef<HTMLDivElement>(null);

  // Close on click outside
  useEffect(() => {
    if (!open) return;

    const handleClick = (e: MouseEvent) => {
      if (overlayRef.current && e.target === overlayRef.current) {
        onClose();
      }
    };

    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm transition-opacity duration-150"
      style={{ opacity: open ? 1 : 0 }}
    >
      <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl shadow-2xl w-full max-w-md mx-4 p-6 backdrop-blur-md animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-semibold text-[var(--sc-text-primary)]">Keyboard Shortcuts</h2>
          <button
            onClick={onClose}
            className="text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] transition-colors text-sm"
          >
            <KeyBadge>Esc</KeyBadge>
          </button>
        </div>

        {/* Navigation */}
        <div className="mb-5">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--sc-text-muted)] mb-2">
            Navigation
          </h3>
          <div className="space-y-0.5">
            {navigationShortcuts.map((s, i) => (
              <ShortcutRow key={i} shortcut={s} />
            ))}
          </div>
        </div>

        {/* Actions */}
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--sc-text-muted)] mb-2">
            Actions
          </h3>
          <div className="space-y-0.5">
            {actionShortcuts.map((s, i) => (
              <ShortcutRow key={i} shortcut={s} />
            ))}
          </div>
        </div>

        <div className="mt-5 pt-4 border-t border-[var(--sc-border)] text-xs text-[var(--sc-text-muted)] text-center">
          Chords: press <KeyBadge>g</KeyBadge> then a letter within 500ms
        </div>
      </div>
    </div>
  );
}
