'use client';

/**
 * Activity Log Component
 *
 * Real-time event stream showing memory operations.
 * Uses WebSocket for live updates.
 */

import { useState, useEffect, useRef } from 'react';
import { useMemoryWebSocket, MemoryEventType } from '@/lib/websocket';

interface LogEntry {
  id: number;
  timestamp: Date;
  type: MemoryEventType;
  message: string;
  details?: Record<string, unknown>;
}

const EVENT_COLORS: Record<MemoryEventType, string> = {
  memory_created: 'text-[var(--sc-cyan)]',
  memory_accessed: 'text-blue-400',
  memory_updated: 'text-[var(--sc-amber)]',
  memory_deleted: 'text-[var(--sc-coral)]',
  consolidation_complete: 'text-purple-400',
  decay_tick: 'text-[var(--sc-text-muted)]',
  initial_state: 'text-[var(--sc-text-secondary)]',
  worker_light_tick: 'text-[var(--sc-text-muted)]',
  worker_medium_tick: 'text-[var(--sc-text-muted)]',
  link_discovered: 'text-[var(--sc-cyan)]',
  predictive_consolidation: 'text-purple-400',
  update_started: 'text-blue-400',
  update_complete: 'text-[var(--sc-cyan)]',
  update_failed: 'text-[var(--sc-coral)]',
  server_restarting: 'text-[var(--sc-coral)]',
  defence_event: 'text-[var(--sc-coral)]',
  kill_switch_activated: 'text-[var(--sc-coral)]',
  kill_switch_deactivated: 'text-[var(--sc-cyan)]',
  xray_detection: 'text-[var(--sc-amber)]',
};

const EVENT_ICONS: Record<MemoryEventType, string> = {
  memory_created: '+',
  memory_accessed: '👁',
  memory_updated: '✏',
  memory_deleted: '✕',
  consolidation_complete: '🔄',
  decay_tick: '⏱',
  initial_state: '📋',
  worker_light_tick: '⚡',
  worker_medium_tick: '🔋',
  link_discovered: '🔗',
  predictive_consolidation: '🔮',
  update_started: '⬆',
  update_complete: '✓',
  update_failed: '✗',
  server_restarting: '🔄',
  defence_event: '🛡',
  kill_switch_activated: '🛑',
  kill_switch_deactivated: '▶',
  xray_detection: '🔍',
};

export function ActivityLog() {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const [filters, setFilters] = useState<Record<MemoryEventType, boolean>>({
    memory_created: true,
    memory_accessed: true,
    memory_updated: true,
    memory_deleted: true,
    consolidation_complete: true,
    decay_tick: false, // Off by default (noisy)
    initial_state: false,
    worker_light_tick: false,
    worker_medium_tick: false,
    link_discovered: true,
    predictive_consolidation: true,
    update_started: true,
    update_complete: true,
    update_failed: true,
    server_restarting: true,
    defence_event: true,
    kill_switch_activated: true,
    kill_switch_deactivated: true,
    xray_detection: true,
  });

  const logContainerRef = useRef<HTMLDivElement>(null);
  const nextIdRef = useRef(1);

  // Connect to WebSocket
  const { lastEvent, isConnected } = useMemoryWebSocket();

  // Process incoming events
  useEffect(() => {
    if (!lastEvent) return;

    const entry: LogEntry = {
      id: nextIdRef.current++,
      timestamp: new Date(lastEvent.timestamp),
      type: lastEvent.type,
      message: formatEventMessage(lastEvent),
      details: lastEvent.data as Record<string, unknown>,
    };

    setLogs((prev) => {
      const updated = [...prev, entry];
      // Keep only last 500 entries
      return updated.slice(-500);
    });
  }, [lastEvent]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && logContainerRef.current) {
      logContainerRef.current.scrollTop = logContainerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const filteredLogs = logs.filter((log) => filters[log.type]);

  const toggleFilter = (type: MemoryEventType) => {
    setFilters((prev) => ({ ...prev, [type]: !prev[type] }));
  };

  const clearLogs = () => {
    setLogs([]);
  };

  const exportLogs = () => {
    const json = JSON.stringify(filteredLogs, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cortex-activity-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full flex flex-col">
      {/* Controls */}
      <div className="p-3 border-b border-[var(--sc-border)] flex items-center gap-3 flex-wrap">
        {/* Connection Status */}
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${isConnected ? 'bg-[var(--sc-cyan)]' : 'bg-[var(--sc-coral)]'}`}
          />
          <span className="text-[var(--sc-text-secondary)]">
            {isConnected ? 'Connected' : 'Disconnected'}
          </span>
        </div>

        <div className="w-px h-4 bg-[var(--sc-bg-elevated)]" />

        {/* Filters */}
        <div className="flex items-center gap-1 flex-wrap">
          {(Object.keys(filters) as MemoryEventType[]).map((type) => (
            <button
              key={type}
              onClick={() => toggleFilter(type)}
              className={`px-2 py-0.5 text-xs rounded transition-colors ${
                filters[type]
                  ? `${EVENT_COLORS[type]} bg-[var(--sc-bg-elevated)]`
                  : 'text-[var(--sc-text-muted)] bg-[var(--sc-bg-elevated)]'
              }`}
            >
              {type.replace(/_/g, ' ').replace('memory ', '')}
            </button>
          ))}
        </div>

        <div className="flex-1" />

        {/* Actions */}
        <label className="flex items-center gap-1 text-xs text-[var(--sc-text-secondary)] cursor-pointer">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="rounded border-[var(--sc-border)] bg-[var(--sc-bg-elevated)]"
          />
          Auto-scroll
        </label>

        <button
          onClick={exportLogs}
          className="text-xs text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]"
        >
          Export
        </button>

        <button
          onClick={clearLogs}
          className="text-xs text-[var(--sc-coral)] hover:text-[var(--sc-coral)]"
        >
          Clear
        </button>
      </div>

      {/* Log Entries */}
      <div
        ref={logContainerRef}
        className="flex-1 overflow-auto p-3 font-mono text-xs"
      >
        {filteredLogs.length === 0 ? (
          <div className="text-[var(--sc-text-muted)] text-center py-8">
            {isConnected ? 'Waiting for events...' : 'Not connected to server'}
          </div>
        ) : (
          <div className="space-y-1">
            {filteredLogs.map((log) => (
              <div key={log.id} className="flex gap-2 hover:bg-[var(--sc-bg-elevated)] px-1 rounded">
                <span className="text-[var(--sc-text-muted)] shrink-0">
                  {log.timestamp.toLocaleTimeString()}
                </span>
                <span className={`shrink-0 w-4 ${EVENT_COLORS[log.type]}`}>
                  {EVENT_ICONS[log.type]}
                </span>
                <span className={EVENT_COLORS[log.type]}>{log.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function formatEventMessage(event: { type: MemoryEventType; data?: unknown }): string {
  const data = event.data as Record<string, unknown> | undefined;

  switch (event.type) {
    case 'memory_created':
      return `Created: "${data?.title || 'Unknown'}" (${data?.type || 'unknown'})`;
    case 'memory_accessed':
      return `Accessed: "${data?.title || 'Unknown'}" → salience ${((data?.newSalience as number) * 100).toFixed(0)}%`;
    case 'memory_updated':
      return `Updated: "${data?.title || 'Unknown'}"`;
    case 'memory_deleted':
      return `Deleted: "${data?.title || 'Unknown'}" (ID: ${data?.memoryId})`;
    case 'consolidation_complete':
      return `Consolidation: ${data?.consolidated || 0} promoted, ${data?.decayed || 0} decayed, ${data?.deleted || 0} deleted`;
    case 'decay_tick':
      return `Decay tick: ${(data?.updates as unknown[])?.length || 0} memories updated`;
    case 'initial_state':
      return 'Connected - received initial state';
    case 'worker_light_tick':
      return 'Worker light tick completed';
    case 'worker_medium_tick':
      return 'Worker medium tick completed';
    case 'link_discovered':
      return `Link discovered: ${data?.sourceTitle || '?'} → ${data?.targetTitle || '?'}`;
    case 'predictive_consolidation':
      return `Predictive consolidation: ${data?.promoted || 0} promoted`;
    default:
      return `Event: ${event.type}`;
  }
}
