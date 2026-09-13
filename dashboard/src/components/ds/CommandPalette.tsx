'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { CornerDownLeft, SearchIcon, TerminalSquare } from 'lucide-react';
import { COMMANDS, runCommand } from '@/lib/commands/registry';
import { useCommandContext } from '@/hooks/useCommandContext';
import { NAV_ITEMS } from '@/components/layout/route-config';
import { useRouter } from 'next/navigation';
import { Kbd } from '@/components/ds/Kbd';
import { cn } from '@/lib/utils';

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface Suggestion {
  kind: 'route' | 'command';
  label: string;
  detail: string;
  value: string; // route href, or command text to insert/run
}

/**
 * Global search / command palette (⌘K). Two behaviours in one input:
 *  - plain text → filters navigation targets and command names;
 *  - a known command line (e.g. `recall "auth bug"`) → Enter runs it through
 *    the real command registry and prints the result below.
 * Native dialog semantics: focus moves in on open, Esc closes, arrows move the
 * selection, Enter activates.
 */
export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const router = useRouter();
  const ctx = useCommandContext();
  const [input, setInput] = useState('');
  const [selected, setSelected] = useState(0);
  const [output, setOutput] = useState<{ ok: boolean; lines: string[] } | null>(null);
  const [running, setRunning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);

  // Global ⌘K / Ctrl+K to open.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        onOpenChange(!open);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onOpenChange]);

  // Reset per-open state during render (React's "adjust state when props
  // change" pattern) so opening always starts from a blank input.
  const [prevOpen, setPrevOpen] = useState(open);
  if (open !== prevOpen) {
    setPrevOpen(open);
    if (open) {
      setInput('');
      setOutput(null);
      setSelected(0);
    }
  }

  useEffect(() => {
    if (open) {
      // Focus after the dialog paints (DOM side effect).
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const firstWord = input.trim().split(/\s+/)[0]?.toLowerCase() ?? '';
  const isCommandLine = firstWord in COMMANDS && input.trim().includes(' ');

  const suggestions = useMemo<Suggestion[]>(() => {
    const q = input.trim().toLowerCase();
    const routes: Suggestion[] = NAV_ITEMS
      .filter((n) => !q || n.label.toLowerCase().includes(q) || n.href.includes(q))
      .map((n) => ({ kind: 'route', label: n.label, detail: n.href, value: n.href }));
    const commands: Suggestion[] = Object.values(COMMANDS)
      .filter((c) => !q || c.name.startsWith(q))
      .map((c) => ({ kind: 'command', label: c.usage, detail: c.summary, value: c.name + ' ' }));
    return q && firstWord in COMMANDS ? [...commands, ...routes] : [...routes, ...commands];
  }, [input, firstWord]);

  const close = useCallback(() => onOpenChange(false), [onOpenChange]);

  const activate = useCallback(async (s: Suggestion | undefined) => {
    if (isCommandLine || (!s && firstWord in COMMANDS)) {
      setRunning(true);
      const result = await runCommand(input.trim(), ctx);
      setRunning(false);
      setOutput(result);
      return;
    }
    if (!s) return;
    if (s.kind === 'route') {
      router.push(s.value);
      close();
    } else {
      setInput(s.value);
      inputRef.current?.focus();
    }
  }, [isCommandLine, firstWord, input, ctx, router, close]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected((s) => Math.min(s + 1, suggestions.length - 1)); return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSelected((s) => Math.max(s - 1, 0)); return; }
    if (e.key === 'Enter') { e.preventDefault(); void activate(suggestions[selected]); }
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 bg-black/40 p-4 pt-[10vh]"
      onMouseDown={(e) => { if (e.target === e.currentTarget) close(); }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-label="Search and command palette"
        className="mx-auto w-full max-w-xl overflow-hidden rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] shadow-[var(--sc-shadow-drawer)]"
        onKeyDown={onKeyDown}
      >
        <div className="flex items-center gap-2 border-b border-[var(--sc-border)] px-3">
          {isCommandLine ? <TerminalSquare size={15} className="text-[var(--sc-primary)]" aria-hidden /> : <SearchIcon size={15} className="text-[var(--sc-text-muted)]" aria-hidden />}
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => { setInput(e.target.value); setSelected(0); setOutput(null); }}
            placeholder="Go to a page, or type a command (help lists them)…"
            aria-label="Search or command input"
            className="h-11 w-full bg-transparent text-sm text-[var(--sc-text)] placeholder:text-[var(--sc-text-muted)] focus:outline-none"
          />
          <Kbd>Esc</Kbd>
        </div>

        {output ? (
          <div className={cn('max-h-72 overflow-y-auto px-4 py-3 font-mono text-xs whitespace-pre-wrap', output.ok ? 'text-[var(--sc-text-dim)]' : 'text-[var(--sc-danger)]')}>
            {output.lines.join('\n') || (output.ok ? 'done' : 'failed')}
          </div>
        ) : (
          <ul role="listbox" aria-label="Suggestions" className="max-h-72 overflow-y-auto py-1">
            {suggestions.length === 0 && (
              <li className="px-4 py-3 text-xs text-[var(--sc-text-muted)]">No matches.</li>
            )}
            {suggestions.map((s, i) => (
              <li key={s.kind + s.value} role="option" aria-selected={i === selected}>
                <button
                  type="button"
                  onMouseEnter={() => setSelected(i)}
                  onClick={() => void activate(s)}
                  className={cn(
                    'flex w-full items-center gap-3 px-4 py-2 text-left text-sm',
                    i === selected ? 'bg-[var(--sc-primary-soft)] text-[var(--sc-text)]' : 'text-[var(--sc-text-dim)]',
                  )}
                >
                  <span className={cn('shrink-0 text-[10px] uppercase tracking-wide', s.kind === 'route' ? 'text-[var(--sc-primary)]' : 'text-[var(--sc-violet)]')}>
                    {s.kind === 'route' ? 'Go' : 'Cmd'}
                  </span>
                  <span className={cn('truncate', s.kind === 'command' && 'font-mono text-xs')}>{s.label}</span>
                  <span className="ml-auto truncate pl-3 text-xs text-[var(--sc-text-muted)]">{s.detail}</span>
                </button>
              </li>
            ))}
          </ul>
        )}

        <div className="flex items-center gap-3 border-t border-[var(--sc-border)] px-4 py-2 text-[10px] text-[var(--sc-text-muted)]">
          <span className="flex items-center gap-1"><Kbd>↑↓</Kbd> select</span>
          <span className="flex items-center gap-1"><Kbd><CornerDownLeft size={9} aria-label="Enter" /></Kbd> {isCommandLine ? 'run command' : 'open'}</span>
          {running && <span className="ml-auto text-[var(--sc-primary)]">running…</span>}
        </div>
      </div>
    </div>
  );
}
