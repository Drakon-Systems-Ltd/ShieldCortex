'use client';

import { cn } from '@/lib/utils';
import type { ReplayEvent, ReplayKind } from '@/hooks/useReplaySession';

interface EventDetailProps {
  event: ReplayEvent | null;
  indexLabel?: string;
}

/**
 * Right-rail focused event detail. Renders the payload pretty-printed
 * with a thin header strip showing kind + ts + actor + duration. Tool
 * calls and tool results pull out their structural fields (tool name,
 * args, content) into a friendlier layout instead of dumping raw JSON.
 */
const KIND_BG: Record<ReplayKind, string> = {
  prompt: 'bg-[var(--term-electric)]/15 text-[var(--term-electric-fg)] theme-glass:bg-[var(--sc-coral)]/15 theme-glass:text-[var(--sc-coral)]',
  response: 'bg-[var(--term-neon)]/15 text-[var(--term-neon-fg)] theme-glass:bg-[var(--sc-cyan)]/15 theme-glass:text-[var(--sc-cyan)]',
  tool_call: 'bg-[var(--term-warn)]/15 text-[var(--term-warn)] theme-glass:bg-amber-500/15 theme-glass:text-amber-400',
  tool_result: 'bg-[var(--term-neon)]/10 text-[var(--term-neon-fg)] theme-glass:bg-[var(--sc-cyan)]/10 theme-glass:text-[var(--sc-cyan)]',
  tool_error: 'bg-[var(--term-danger)]/15 text-[var(--term-danger)] theme-glass:bg-rose-500/15 theme-glass:text-rose-400',
  hook_fire: 'bg-[var(--term-border)] text-[var(--term-text-muted)] theme-glass:bg-[var(--sc-border)] theme-glass:text-[var(--sc-text-secondary)]',
};

export function EventDetail({ event, indexLabel }: EventDetailProps) {
  if (!event) {
    return (
      <div className="flex h-full items-center justify-center">
        <div className="max-w-xs space-y-2 px-6 text-center">
          <div className="text-xs font-mono uppercase tracking-wider text-[var(--term-text-muted)]">
            No event selected
          </div>
          <div className="text-[11px] font-mono text-[var(--term-text-dim)]">
            Click a tick on the scrubber, or press <kbd className="rounded border border-[var(--term-border)] px-1">space</kbd> to play.
          </div>
        </div>
      </div>
    );
  }

  const payload = event.payload as Record<string, unknown> | null;
  const text = typeof payload === 'object' && payload && typeof (payload as { text?: unknown }).text === 'string'
    ? (payload as { text: string }).text
    : null;

  return (
    <div className="flex h-full flex-col">
      {/* Header strip */}
      <div className="flex items-center justify-between gap-2 border-b border-[var(--term-border)] theme-glass:border-[var(--sc-border)] px-3 py-2">
        <div className="flex items-center gap-2 min-w-0">
          <span
            className={cn(
              'rounded px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wider',
              KIND_BG[event.kind],
            )}
          >
            {event.kind}
          </span>
          {indexLabel && (
            <span className="text-[10px] font-mono uppercase tracking-wider text-[var(--term-text-muted)]">
              {indexLabel}
            </span>
          )}
        </div>
        <div className="text-[10px] font-mono text-[var(--term-text-dim)] tabular-nums">
          {formatTs(event.ts)}
        </div>
      </div>

      {/* Meta line — actor, duration, audit link */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-[var(--term-border)] theme-glass:border-[var(--sc-border)] px-3 py-1.5 text-[10px] font-mono">
        {event.actor && (
          <span className="text-[var(--term-text-muted)]">
            actor: <span className="text-[var(--term-text)]">{event.actor}</span>
          </span>
        )}
        {event.duration_ms !== null && (
          <span className="text-[var(--term-text-muted)]">
            duration: <span className="text-[var(--term-text)] tabular-nums">{event.duration_ms}ms</span>
          </span>
        )}
        {event.project && (
          <span className="text-[var(--term-text-muted)]">
            project: <span className="text-[var(--term-text)]">{event.project}</span>
          </span>
        )}
        {event.audit_id !== null && (
          <span className="text-[var(--term-danger)]">
            audit: <span className="tabular-nums">#{event.audit_id}</span>
            <span className="ml-1 text-[var(--term-text-dim)]">(scanned)</span>
          </span>
        )}
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-3 text-xs font-mono">
        {renderBody(event, text)}
      </div>
    </div>
  );
}

function renderBody(event: ReplayEvent, text: string | null) {
  const payload = event.payload as Record<string, unknown> | null;

  // Tool call: highlight tool name + input
  if (event.kind === 'tool_call' && payload && typeof payload === 'object') {
    const name = typeof payload.name === 'string' ? payload.name : 'unknown';
    const toolUseId = typeof payload.tool_use_id === 'string' ? payload.tool_use_id : null;
    return (
      <div className="space-y-2">
        <div>
          <span className="text-[var(--term-text-muted)]">tool: </span>
          <span className="text-[var(--term-warn)]">{name}</span>
          {toolUseId && (
            <span className="ml-2 text-[var(--term-text-dim)]">{toolUseId}</span>
          )}
        </div>
        <div>
          <div className="text-[10px] uppercase tracking-wider text-[var(--term-text-muted)] mb-1">input</div>
          <pre className="whitespace-pre-wrap break-words text-[var(--term-text)] theme-glass:text-[var(--sc-text-primary)]">
            {prettyJson(payload.input)}
          </pre>
        </div>
      </div>
    );
  }

  // Tool result: show content (often string) + correlate to tool_use_id
  if (event.kind === 'tool_result' && payload && typeof payload === 'object') {
    const toolUseId = typeof payload.tool_use_id === 'string' ? payload.tool_use_id : null;
    const content = payload.content;
    return (
      <div className="space-y-2">
        {toolUseId && (
          <div className="text-[var(--term-text-dim)] text-[10px]">↳ {toolUseId}</div>
        )}
        <pre className="whitespace-pre-wrap break-words text-[var(--term-text)] theme-glass:text-[var(--sc-text-primary)]">
          {typeof content === 'string' ? content : prettyJson(content)}
        </pre>
      </div>
    );
  }

  // Prompt / response: the .text field is the headline; show it cleanly
  if (text) {
    return (
      <pre className="whitespace-pre-wrap break-words text-[var(--term-text)] theme-glass:text-[var(--sc-text-primary)]">
        {text}
      </pre>
    );
  }

  // Fallback: pretty-print the whole payload
  return (
    <pre className="whitespace-pre-wrap break-words text-[var(--term-text)] theme-glass:text-[var(--sc-text-primary)]">
      {prettyJson(payload)}
    </pre>
  );
}

function prettyJson(value: unknown): string {
  if (value === null || value === undefined) return 'null';
  if (typeof value === 'string') return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function formatTs(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    fractionalSecondDigits: 3,
  });
}
