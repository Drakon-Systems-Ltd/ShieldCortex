'use client';

import { cn } from '@/lib/utils';
import { useEffect } from 'react';
import { Pause, Play, SkipBack, SkipForward, ChevronFirst, ChevronLast } from 'lucide-react';
import { REPLAY_SPEEDS, type ReplayPlayback, type ReplaySpeed } from '@/hooks/useReplaySession';

interface PlayControlsProps {
  playback: ReplayPlayback;
  /** Optional total event count override for the progress label (rare). */
  totalOverride?: number;
}

/**
 * Transport controls — play/pause, step prev/next, jump to start/end,
 * speed segmented control. Keyboard:
 *   space        toggle play/pause
 *   ←  →         step back / forward
 *   shift+←/→    jump to start / end
 *   [   ]        cycle speed down / up
 *
 * The space/arrow shortcuts only fire when the user isn't typing in an
 * input — common foot-gun for replay UIs that share the page with a
 * search box.
 */
export function PlayControls({ playback, totalOverride }: PlayControlsProps) {
  const {
    playing,
    speed,
    currentIndex,
    events,
    toggle,
    stepBack,
    stepForward,
    setSpeed,
    cycleSpeed,
    jumpToStart,
    jumpToEnd,
  } = playback;

  const total = totalOverride ?? events.length;
  const atStart = currentIndex <= 0;
  const atEnd = currentIndex >= events.length - 1;

  // ── Keyboard shortcuts ────────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Skip when typing in an input/textarea/contenteditable element.
      const target = e.target as HTMLElement | null;
      if (target) {
        const tag = target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || target.isContentEditable) return;
      }

      switch (e.key) {
        case ' ': {
          e.preventDefault();
          toggle();
          break;
        }
        case 'ArrowLeft': {
          e.preventDefault();
          if (e.shiftKey) jumpToStart();
          else stepBack();
          break;
        }
        case 'ArrowRight': {
          e.preventDefault();
          if (e.shiftKey) jumpToEnd();
          else stepForward();
          break;
        }
        case '[': {
          e.preventDefault();
          cycleSpeed(-1);
          break;
        }
        case ']': {
          e.preventDefault();
          cycleSpeed(1);
          break;
        }
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [toggle, stepBack, stepForward, jumpToStart, jumpToEnd, cycleSpeed]);

  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] theme-glass:bg-[var(--sc-surface-glass)] px-3 py-2">
      {/* Transport */}
      <div className="flex items-center gap-1">
        <ControlButton ariaLabel="Jump to start (Shift+←)" disabled={atStart} onClick={jumpToStart}>
          <ChevronFirst className="h-3.5 w-3.5" aria-hidden />
        </ControlButton>
        <ControlButton ariaLabel="Step back (←)" disabled={atStart} onClick={stepBack}>
          <SkipBack className="h-3.5 w-3.5" aria-hidden />
        </ControlButton>
        <ControlButton
          ariaLabel={playing ? 'Pause (space)' : 'Play (space)'}
          onClick={toggle}
          primary
          disabled={events.length === 0}
        >
          {playing ? (
            <Pause className="h-4 w-4" aria-hidden />
          ) : (
            <Play className="h-4 w-4" aria-hidden />
          )}
          <span className="ml-1.5 text-[10px] uppercase tracking-wider">
            {playing ? 'Pause' : 'Play'}
          </span>
        </ControlButton>
        <ControlButton ariaLabel="Step forward (→)" disabled={atEnd} onClick={stepForward}>
          <SkipForward className="h-3.5 w-3.5" aria-hidden />
        </ControlButton>
        <ControlButton ariaLabel="Jump to end (Shift+→)" disabled={atEnd} onClick={jumpToEnd}>
          <ChevronLast className="h-3.5 w-3.5" aria-hidden />
        </ControlButton>
      </div>

      {/* Progress label */}
      <div className="text-[11px] font-mono text-[var(--term-text-muted)] tabular-nums">
        <span className="text-[var(--term-text)]">{Math.min(currentIndex + 1, total)}</span>
        <span className="text-[var(--term-text-dim)]"> / </span>
        <span>{total}</span>
      </div>

      {/* Speed segmented control */}
      <div className="flex items-center gap-1">
        <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--term-text-muted)]">
          speed
        </span>
        <div className="flex overflow-hidden rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)]">
          {REPLAY_SPEEDS.map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setSpeed(s as ReplaySpeed)}
              className={cn(
                'px-2 py-0.5 text-[10px] font-mono tabular-nums transition-colors',
                s === speed
                  ? 'bg-[var(--term-neon)]/15 text-[var(--term-neon-fg)] theme-glass:bg-[var(--sc-cyan)]/15 theme-glass:text-[var(--sc-cyan)]'
                  : 'text-[var(--term-text-dim)] hover:text-[var(--term-text)] theme-glass:text-[var(--sc-text-secondary)]',
              )}
              aria-pressed={s === speed}
              aria-label={`${s}× speed`}
            >
              {s}×
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

interface ControlButtonProps {
  ariaLabel: string;
  onClick: () => void;
  children: React.ReactNode;
  primary?: boolean;
  disabled?: boolean;
}

function ControlButton({ ariaLabel, onClick, children, primary, disabled }: ControlButtonProps) {
  return (
    <button
      type="button"
      aria-label={ariaLabel}
      title={ariaLabel}
      onClick={onClick}
      disabled={disabled}
      className={cn(
        'inline-flex items-center rounded px-2 py-1 text-xs font-mono transition-colors',
        'disabled:opacity-40 disabled:cursor-not-allowed',
        primary
          ? 'border border-[var(--term-electric)] text-[var(--term-electric-fg)] hover:bg-[var(--term-electric)]/10 theme-glass:bg-[var(--sc-cyan)] theme-glass:text-[var(--sc-bg-deep)] theme-glass:border-0 theme-glass:hover:bg-[var(--sc-cyan-mid)]'
          : 'border border-[var(--term-border)] text-[var(--term-text-dim)] hover:text-[var(--term-text)] hover:border-[var(--term-text-muted)] theme-glass:border-[var(--sc-border)]',
      )}
    >
      {children}
    </button>
  );
}
