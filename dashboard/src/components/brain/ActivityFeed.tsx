'use client';

/**
 * Activity Feed — Brain Tab Bottom Strip
 *
 * Reverse-chronological stream of memory system events.
 * Shows coloured dot indicators, relative timestamps, and event descriptions.
 * Supports filtering by event type and collapsible mode.
 */

import { useState, useMemo, useCallback } from 'react';
import { MemoryEvent } from '@/types/memory';

interface ActivityFeedProps {
  events: MemoryEvent[];
  onClickEvent?: (eventData: unknown) => void;
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

type EventType = MemoryEvent['type'];

type FilterKey = 'all' | 'creates' | 'updates' | 'deletes' | 'consolidation' | 'decay';

const FILTER_BUTTONS: { key: FilterKey; label: string; types: EventType[] }[] = [
  { key: 'all', label: 'All', types: [] },
  { key: 'creates', label: 'Creates', types: ['memory_created'] },
  { key: 'updates', label: 'Updates', types: ['memory_updated', 'memory_accessed'] },
  { key: 'deletes', label: 'Deletes', types: ['memory_deleted'] },
  { key: 'consolidation', label: 'Consolidation', types: ['consolidation_complete'] },
  { key: 'decay', label: 'Decay', types: ['decay_tick'] },
];

const EVENT_DOT_COLOUR: Record<EventType, string> = {
  memory_created: 'bg-[var(--sc-cyan)]',
  memory_accessed: 'bg-blue-400',
  memory_updated: 'bg-[var(--sc-amber)]',
  memory_deleted: 'bg-[var(--sc-coral)]',
  consolidation_complete: 'bg-purple-400',
  decay_tick: 'bg-[var(--sc-bg-elevated)]',
};

const EVENT_LABEL: Record<EventType, string> = {
  memory_created: 'Created',
  memory_accessed: 'Accessed',
  memory_updated: 'Updated',
  memory_deleted: 'Deleted',
  consolidation_complete: 'Consolidated',
  decay_tick: 'Decay Tick',
};

function relativeTime(dateStr: string): string {
  const ms = Date.now() - new Date(dateStr).getTime();
  const secs = Math.floor(ms / 1000);
  if (secs < 5) return 'Just now';
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

function extractDescription(data: unknown): string {
  if (!data || typeof data !== 'object') return '';
  const record = data as Record<string, unknown>;
  if (typeof record.title === 'string' && record.title) return record.title;
  if (typeof record.name === 'string' && record.name) return record.name;
  if (typeof record.summary === 'string' && record.summary) return record.summary;
  if (typeof record.message === 'string' && record.message) return record.message;
  if (typeof record.id === 'number') return `Memory #${record.id}`;
  return '';
}

export function ActivityFeed({
  events,
  onClickEvent,
  isCollapsed = false,
  onToggleCollapse,
}: ActivityFeedProps) {
  const [activeFilters, setActiveFilters] = useState<Set<FilterKey>>(new Set(['all']));

  const toggleFilter = useCallback((key: FilterKey) => {
    setActiveFilters((prev) => {
      const next = new Set(prev);

      if (key === 'all') {
        // Clicking "All" clears everything and selects only "All"
        return new Set(['all']);
      }

      // Remove "All" when selecting a specific filter
      next.delete('all');

      if (next.has(key)) {
        next.delete(key);
        // If nothing selected, revert to "All"
        if (next.size === 0) return new Set(['all']);
      } else {
        next.add(key);
      }

      return next;
    });
  }, []);

  const filteredEvents = useMemo(() => {
    if (activeFilters.has('all')) return events;

    const allowedTypes = new Set<EventType>();
    for (const filter of activeFilters) {
      const config = FILTER_BUTTONS.find((f) => f.key === filter);
      if (config) {
        for (const t of config.types) {
          allowedTypes.add(t);
        }
      }
    }

    return events.filter((e) => allowedTypes.has(e.type));
  }, [events, activeFilters]);

  const latestEvent = events.length > 0 ? events[0] : null;

  return (
    <div
      className={`bg-[var(--sc-bg-surface)] backdrop-blur-sm border-t border-[var(--sc-border)] transition-all duration-300 ease-in-out ${
        isCollapsed ? 'h-8' : 'h-32'
      }`}
    >
      {isCollapsed ? (
        /* Collapsed: single line with latest event and expand button */
        <div className="flex items-center h-8 px-3 gap-2">
          <button
            onClick={onToggleCollapse}
            className="flex items-center justify-center w-5 h-5 rounded hover:bg-[var(--sc-bg-elevated)] transition-colors text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] shrink-0"
            aria-label="Expand activity feed"
          >
            <svg
              className="w-3 h-3"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
              strokeWidth={2}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" />
            </svg>
          </button>

          {latestEvent ? (
            <div className="flex items-center gap-2 text-xs min-w-0">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${EVENT_DOT_COLOUR[latestEvent.type]}`} />
              <span className="text-[var(--sc-text-muted)]">{relativeTime(latestEvent.timestamp)}</span>
              <span className="text-[var(--sc-text-primary)]">{EVENT_LABEL[latestEvent.type]}</span>
              <span className="text-[var(--sc-text-muted)] truncate">{extractDescription(latestEvent.data)}</span>
            </div>
          ) : (
            <span className="text-xs text-[var(--sc-text-muted)]">No activity</span>
          )}
        </div>
      ) : (
        /* Expanded: filter bar + scrollable event list */
        <div className="flex flex-col h-full">
          {/* Header with filter bar and collapse button */}
          <div className="flex items-center h-7 px-3 gap-2 shrink-0 border-b border-[var(--sc-border)]/50">
            <button
              onClick={onToggleCollapse}
              className="flex items-center justify-center w-5 h-5 rounded hover:bg-[var(--sc-bg-elevated)] transition-colors text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)] shrink-0"
              aria-label="Collapse activity feed"
            >
              <svg
                className="w-3 h-3"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            </button>

            <div className="flex items-center gap-1">
              {FILTER_BUTTONS.map((filter) => (
                <button
                  key={filter.key}
                  onClick={() => toggleFilter(filter.key)}
                  className={`px-1.5 py-0.5 text-[10px] rounded transition-colors ${
                    activeFilters.has(filter.key)
                      ? 'bg-[var(--sc-cyan)] text-white'
                      : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] hover:bg-[var(--sc-bg-elevated)]'
                  }`}
                >
                  {filter.label}
                </button>
              ))}
            </div>
          </div>

          {/* Event list */}
          <div className="flex-1 overflow-y-auto min-h-0">
            {filteredEvents.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <span className="text-xs text-[var(--sc-text-muted)]">
                  No activity yet -- events will appear as the brain processes memories
                </span>
              </div>
            ) : (
              <div className="px-3 py-1">
                {filteredEvents.map((event, i) => {
                  const description = extractDescription(event.data);
                  return (
                    <button
                      key={`${event.type}-${event.timestamp}-${i}`}
                      onClick={() => onClickEvent?.(event.data)}
                      className="flex items-center gap-2 w-full text-left py-0.5 px-1 rounded hover:bg-[var(--sc-bg-elevated)] transition-colors group"
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full shrink-0 ${EVENT_DOT_COLOUR[event.type]}`}
                      />
                      <span className="text-[10px] text-[var(--sc-text-muted)] w-12 shrink-0 tabular-nums">
                        {relativeTime(event.timestamp)}
                      </span>
                      <span className="text-[10px] text-[var(--sc-text-primary)] w-16 shrink-0">
                        {EVENT_LABEL[event.type]}
                      </span>
                      {description && (
                        <span className="text-[10px] text-[var(--sc-text-muted)] truncate group-hover:text-[var(--sc-text-secondary)] transition-colors">
                          {description}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
