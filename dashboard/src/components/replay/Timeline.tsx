'use client';

import { cn } from '@/lib/utils';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReplayEvent, ReplayKind } from '@/hooks/useReplaySession';

interface TimelineProps {
  events: readonly ReplayEvent[];
  currentIndex: number;
  onSeek(idx: number): void;
  playing: boolean;
}

/**
 * Horizontal SVG scrubber. Each event renders as a vertical tick coloured
 * by `kind`. The playhead is a brighter vertical line at the current index.
 * Click anywhere on the track to seek to the nearest event; drag the
 * playhead to scrub.
 *
 * Sizing is fluid — the SVG fills its container width and uses a 1:1
 * mapping from event index to x-position so visually-spaced ticks
 * always correspond to "one event apart" regardless of wall-clock gaps.
 * Time-proportional spacing would crush dense bursts and waste space
 * on long pauses; index-proportional is the right scale for a replay
 * scrubber.
 */

const KIND_COLOR: Record<ReplayKind, string> = {
  prompt: 'var(--term-electric)',
  response: 'var(--term-neon)',
  tool_call: 'var(--term-warn)',
  tool_result: 'var(--term-neon-fg)',
  tool_error: 'var(--term-danger)',
  hook_fire: 'var(--term-text-muted)',
};

const KIND_LABEL: Record<ReplayKind, string> = {
  prompt: 'Prompt',
  response: 'Response',
  tool_call: 'Tool call',
  tool_result: 'Tool result',
  tool_error: 'Tool error',
  hook_fire: 'Hook',
};

const TRACK_HEIGHT = 36;
const TICK_HEIGHT = 22;
const PLAYHEAD_HEIGHT = 30;
const PADDING_X = 12;

export function Timeline({ events, currentIndex, onSeek, playing }: TimelineProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const draggingRef = useRef(false);
  const [width, setWidth] = useState(800);

  const n = events.length;

  // Build a kind→count summary for the legend.
  const kindCounts = useMemo(() => {
    const counts: Partial<Record<ReplayKind, number>> = {};
    for (const e of events) counts[e.kind] = (counts[e.kind] ?? 0) + 1;
    return counts;
  }, [events]);

  // Track container width for proportional layout. ResizeObserver gives
  // us live updates without polling — the scrubber reflows when the user
  // resizes the window or splits panels.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => {
      const w = el.getBoundingClientRect().width;
      if (w > 0) setWidth(w);
    };
    update();
    const obs = new ResizeObserver(update);
    obs.observe(el);
    return () => obs.disconnect();
  }, []);

  const indexFromClientX = useCallback(
    (clientX: number): number => {
      const el = containerRef.current;
      if (!el || n === 0) return 0;
      const rect = el.getBoundingClientRect();
      const usable = rect.width - PADDING_X * 2;
      if (usable <= 0) return 0;
      const x = Math.max(0, Math.min(usable, clientX - rect.left - PADDING_X));
      const ratio = x / usable;
      return Math.round(ratio * (n - 1));
    },
    [n],
  );

  const handlePointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    draggingRef.current = true;
    (e.target as Element).setPointerCapture?.(e.pointerId);
    onSeek(indexFromClientX(e.clientX));
  };
  const handlePointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    if (!draggingRef.current) return;
    onSeek(indexFromClientX(e.clientX));
  };
  const handlePointerUp = (e: React.PointerEvent<SVGSVGElement>) => {
    draggingRef.current = false;
    (e.target as Element).releasePointerCapture?.(e.pointerId);
  };

  if (n === 0) {
    return (
      <div className="rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] p-4">
        <div className="text-xs font-mono text-[var(--term-text-muted)]">
          No events to scrub. Pick a session on the left.
        </div>
      </div>
    );
  }

  const playheadX = computeX(currentIndex, n, width);

  return (
    <div className="space-y-2">
      {/* Scrubber */}
      <div
        ref={containerRef}
        className={cn(
          'rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] theme-glass:bg-[var(--sc-surface-glass)] overflow-hidden',
        )}
      >
        <svg
          role="slider"
          aria-label="Replay scrubber"
          aria-valuemin={0}
          aria-valuemax={Math.max(0, n - 1)}
          aria-valuenow={Math.max(0, Math.min(currentIndex, n - 1))}
          aria-valuetext={`Event ${currentIndex + 1} of ${n}`}
          width="100%"
          height={TRACK_HEIGHT}
          viewBox={`0 0 ${Math.max(width, 1)} ${TRACK_HEIGHT}`}
          preserveAspectRatio="none"
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerUp}
          className="block w-full select-none cursor-ew-resize"
        >
          {/* Track */}
          <line
            x1={PADDING_X}
            y1={TRACK_HEIGHT / 2}
            x2={Math.max(width, PADDING_X * 2) - PADDING_X}
            y2={TRACK_HEIGHT / 2}
            stroke="var(--term-border)"
            strokeWidth="1"
          />
          {/* Ticks */}
          {events.map((event, i) => {
            const x = computeX(i, n, width);
            const isCurrent = i === currentIndex;
            return (
              <line
                key={event.id}
                x1={x}
                y1={(TRACK_HEIGHT - TICK_HEIGHT) / 2}
                x2={x}
                y2={(TRACK_HEIGHT + TICK_HEIGHT) / 2}
                stroke={KIND_COLOR[event.kind]}
                strokeWidth={isCurrent ? 2.5 : 1.5}
                opacity={isCurrent ? 1 : 0.7}
              />
            );
          })}
          {/* Playhead */}
          <g pointerEvents="none">
            <line
              x1={playheadX}
              y1={(TRACK_HEIGHT - PLAYHEAD_HEIGHT) / 2}
              x2={playheadX}
              y2={(TRACK_HEIGHT + PLAYHEAD_HEIGHT) / 2}
              stroke="var(--term-electric)"
              strokeWidth={2}
              className={playing ? 'animate-pulse' : ''}
            />
            <circle
              cx={playheadX}
              cy={TRACK_HEIGHT / 2}
              r={4}
              fill="var(--term-electric)"
              stroke="var(--term-bg)"
              strokeWidth={1.5}
            />
          </g>
        </svg>
      </div>

      {/* Legend / kind breakdown */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] font-mono">
        {(Object.keys(KIND_LABEL) as ReplayKind[]).map((k) => {
          const count = kindCounts[k];
          if (!count) return null;
          return (
            <span key={k} className="inline-flex items-center gap-1 text-[var(--term-text-muted)]">
              <span
                aria-hidden
                className="inline-block h-2 w-2"
                style={{ backgroundColor: KIND_COLOR[k] }}
              />
              {KIND_LABEL[k]} <span className="text-[var(--term-text-dim)] tabular-nums">({count})</span>
            </span>
          );
        })}
      </div>
    </div>
  );
}

function computeX(idx: number, n: number, width: number): number {
  if (n <= 1 || width <= 0) return PADDING_X;
  const usable = width - PADDING_X * 2;
  return PADDING_X + (idx / (n - 1)) * usable;
}
