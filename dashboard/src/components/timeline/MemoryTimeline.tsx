'use client';

/**
 * MemoryTimeline — Chronological timeline view of memories
 *
 * Fetches memories from the local API and displays them as a vertical
 * timeline grouped by day, with category/type badges and client-side
 * filtering by category, memory type, and search text.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { authFetch } from '@/lib/auth';
import { Memory, MemoryType, MemoryCategory } from '@/types/memory';

// ── Constants ──────────────────────────────────────────────

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

const CATEGORY_COLOURS: Record<string, string> = {
  architecture: '#3b82f6',
  error: '#ef4444',
  pattern: '#8b5cf6',
  preference: '#f59e0b',
  learning: '#10b981',
  context: '#6366f1',
  todo: '#f97316',
  note: '#94a3b8',
  relationship: '#ec4899',
  custom: '#64748b',
};

const MEMORY_TYPE_LABELS: Record<MemoryType, string> = {
  short_term: 'STM',
  long_term: 'LTM',
  episodic: 'Episodic',
};

const MEMORY_TYPE_COLOURS: Record<MemoryType, string> = {
  short_term: '#22d3ee',
  long_term: '#a78bfa',
  episodic: '#f472b6',
};

const ALL_CATEGORIES: MemoryCategory[] = [
  'architecture',
  'pattern',
  'preference',
  'error',
  'context',
  'learning',
  'todo',
  'note',
  'relationship',
  'custom',
];

const TYPE_FILTER_OPTIONS: Array<{ label: string; value: MemoryType | 'all' }> = [
  { label: 'All', value: 'all' },
  { label: 'STM', value: 'short_term' },
  { label: 'LTM', value: 'long_term' },
  { label: 'Episodic', value: 'episodic' },
];

// ── Helpers ────────────────────────────────────────────────

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

function dayKey(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function dayLabel(dateKey: string): string {
  const today = new Date();
  const todayKey = dayKey(today.toISOString());

  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayKey = dayKey(yesterday.toISOString());

  if (dateKey === todayKey) return 'Today';
  if (dateKey === yesterdayKey) return 'Yesterday';

  const [y, m, d] = dateKey.split('-').map(Number);
  const date = new Date(y, m - 1, d);
  return date.toLocaleDateString(undefined, {
    month: 'long',
    day: 'numeric',
    year: date.getFullYear() !== today.getFullYear() ? 'numeric' : undefined,
  });
}

interface DayGroup {
  key: string;
  label: string;
  memories: Memory[];
}

function groupByDay(memories: Memory[]): DayGroup[] {
  const map = new Map<string, Memory[]>();
  for (const m of memories) {
    const k = dayKey(m.createdAt);
    if (!map.has(k)) map.set(k, []);
    map.get(k)!.push(m);
  }

  return Array.from(map.entries())
    .sort(([a], [b]) => b.localeCompare(a))
    .map(([key, mems]) => ({ key, label: dayLabel(key), memories: mems }));
}

function importanceIndicator(salience: number): { label: string; colour: string } {
  if (salience >= 0.8) return { label: 'Critical', colour: '#ef4444' };
  if (salience >= 0.6) return { label: 'High', colour: '#f59e0b' };
  if (salience >= 0.4) return { label: 'Medium', colour: '#3b82f6' };
  return { label: 'Low', colour: '#64748b' };
}

// ── Component ──────────────────────────────────────────────

export interface MemoryTimelineProps {
  /** Optional className for the outer container */
  className?: string;
}

export default function MemoryTimeline({ className }: MemoryTimelineProps) {
  const [memories, setMemories] = useState<Memory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedCategories, setSelectedCategories] = useState<Set<MemoryCategory>>(new Set());
  const [typeFilter, setTypeFilter] = useState<MemoryType | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Intersection observer for fade-in
  const observerRef = useRef<IntersectionObserver | null>(null);
  const cardRefs = useRef<Map<number, HTMLDivElement>>(new Map());
  const [visibleCards, setVisibleCards] = useState<Set<number>>(new Set());

  // ── Fetch memories ──────────────────────────────────────

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const res = await authFetch(
          `${API_BASE}/api/memories?limit=200&sort=created_at&order=desc`
        );
        if (!res.ok) throw new Error(`API returned ${res.status}`);
        const data = await res.json();
        if (!cancelled) {
          setMemories(Array.isArray(data) ? data : data.memories ?? []);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load memories');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  // ── Intersection observer setup ─────────────────────────

  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        setVisibleCards((prev) => {
          const next = new Set(prev);
          for (const entry of entries) {
            const id = Number(entry.target.getAttribute('data-memory-id'));
            if (entry.isIntersecting) next.add(id);
          }
          return next;
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px 50px 0px' }
    );

    return () => observerRef.current?.disconnect();
  }, []);

  const cardRef = useCallback(
    (id: number) => (el: HTMLDivElement | null) => {
      if (el) {
        cardRefs.current.set(id, el);
        observerRef.current?.observe(el);
      }
    },
    []
  );

  // ── Filtering ───────────────────────────────────────────

  const filtered = useMemo(() => {
    let result = memories;

    if (selectedCategories.size > 0) {
      result = result.filter((m) => selectedCategories.has(m.category));
    }

    if (typeFilter !== 'all') {
      result = result.filter((m) => m.type === typeFilter);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (m) =>
          m.title.toLowerCase().includes(q) ||
          m.content.toLowerCase().includes(q)
      );
    }

    return result;
  }, [memories, selectedCategories, typeFilter, searchQuery]);

  const groups = useMemo(() => groupByDay(filtered), [filtered]);

  // ── Category chip toggle ────────────────────────────────

  function toggleCategory(cat: MemoryCategory) {
    setSelectedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }

  // ── Render ──────────────────────────────────────────────

  if (loading) {
    return (
      <div className={`flex items-center justify-center h-full bg-[#0a0a0f] ${className ?? ''}`}>
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-[var(--sc-border)] border-t-cyan-500 rounded-full animate-spin" />
          <span className="text-sm text-[var(--sc-text-secondary)]">Loading timeline...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`flex items-center justify-center h-full bg-[#0a0a0f] ${className ?? ''}`}>
        <div className="text-center space-y-2">
          <p className="text-[var(--sc-coral)] text-sm">Failed to load memories</p>
          <p className="text-[var(--sc-text-muted)] text-xs">{error}</p>
        </div>
      </div>
    );
  }

  return (
    <div className={`h-full flex flex-col bg-[#0a0a0f] text-[var(--sc-text-primary)] ${className ?? ''}`}>
      {/* ── Filter bar ─────────────────────────────────────── */}
      <div className="shrink-0 border-b border-[var(--sc-border)]/60 px-4 py-3 space-y-3">
        {/* Search */}
        <input
          type="text"
          placeholder="Search memories..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-[var(--sc-bg-surface)] border border-[var(--sc-border)]/50 rounded-lg px-3 py-2 text-sm text-[var(--sc-text-primary)] placeholder-[var(--sc-text-muted)] focus:outline-none focus:ring-1 focus:ring-[var(--sc-cyan)]/40 focus:border-[var(--sc-cyan)]/40"
        />

        {/* Memory type filter */}
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--sc-text-muted)] uppercase tracking-wider mr-1">Type</span>
          {TYPE_FILTER_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              onClick={() => setTypeFilter(opt.value)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                typeFilter === opt.value
                  ? 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] border border-[var(--sc-cyan)]/30'
                  : 'bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] border border-[var(--sc-border)]/30 hover:bg-[var(--sc-bg-elevated)]'
              }`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Category chips */}
        <div className="flex flex-wrap gap-1.5">
          <span className="text-xs text-[var(--sc-text-muted)] uppercase tracking-wider mr-1 self-center">Category</span>
          {ALL_CATEGORIES.map((cat) => {
            const active = selectedCategories.has(cat);
            const colour = CATEGORY_COLOURS[cat] ?? '#64748b';
            return (
              <button
                key={cat}
                onClick={() => toggleCategory(cat)}
                className="px-2.5 py-1 rounded-md text-xs font-medium transition-all"
                style={{
                  backgroundColor: active ? `${colour}22` : 'rgba(30, 41, 59, 0.4)',
                  color: active ? colour : '#94a3b8',
                  border: `1px solid ${active ? `${colour}55` : 'rgba(51, 65, 85, 0.3)'}`,
                }}
              >
                {cat}
              </button>
            );
          })}
          {selectedCategories.size > 0 && (
            <button
              onClick={() => setSelectedCategories(new Set())}
              className="px-2 py-1 rounded-md text-xs text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* ── Timeline ───────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-4 py-6">
        {groups.length === 0 ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center space-y-2 max-w-sm">
              <div className="text-[var(--sc-text-muted)] text-4xl mb-3">--</div>
              <p className="text-[var(--sc-text-secondary)] text-sm">No memories yet.</p>
              <p className="text-[var(--sc-text-muted)] text-xs">
                Start a conversation and use <code className="text-[var(--sc-cyan)]/80 bg-[var(--sc-bg-elevated)] px-1.5 py-0.5 rounded text-xs">remember</code> to build your timeline.
              </p>
            </div>
          </div>
        ) : (
          <div className="relative">
            {/* Vertical timeline line */}
            <div className="absolute left-4 md:left-1/2 top-0 bottom-0 w-px bg-[var(--sc-bg-elevated)]" />

            {groups.map((group) => (
              <div key={group.key} className="mb-8">
                {/* Day header */}
                <div className="relative flex items-center mb-4">
                  <div className="absolute left-4 md:left-1/2 -translate-x-1/2 w-3 h-3 rounded-full bg-[var(--sc-bg-elevated)] border-2 border-[var(--sc-border)] z-10" />
                  <div className="ml-10 md:ml-0 md:absolute md:left-1/2 md:translate-x-4">
                    <span className="text-xs font-semibold text-[var(--sc-text-secondary)] uppercase tracking-wider bg-[#0a0a0f] px-2">
                      {group.label}
                    </span>
                  </div>
                </div>

                {/* Memory cards */}
                {group.memories.map((memory, idx) => {
                  const isLeft = idx % 2 === 0;
                  const importance = importanceIndicator(memory.salience);
                  const catColour = CATEGORY_COLOURS[memory.category] ?? '#64748b';
                  const typeColour = MEMORY_TYPE_COLOURS[memory.type] ?? '#94a3b8';
                  const typeLabel = MEMORY_TYPE_LABELS[memory.type] ?? memory.type;
                  const isVisible = visibleCards.has(memory.id);

                  return (
                    <div
                      key={memory.id}
                      ref={cardRef(memory.id)}
                      data-memory-id={memory.id}
                      className={`relative flex mb-4 ${
                        // Desktop: alternate sides. Mobile: always right of the line.
                        isLeft
                          ? 'md:justify-start justify-start'
                          : 'md:justify-end justify-start'
                      }`}
                      style={{
                        opacity: isVisible ? 1 : 0,
                        transform: isVisible ? 'translateY(0)' : 'translateY(12px)',
                        transition: 'opacity 0.4s ease-out, transform 0.4s ease-out',
                      }}
                    >
                      {/* Connector dot */}
                      <div className="absolute left-4 md:left-1/2 top-4 -translate-x-1/2 w-2 h-2 rounded-full z-10" style={{ backgroundColor: catColour }} />

                      {/* Card */}
                      <div
                        className={`ml-10 md:ml-0 w-full md:w-[calc(50%-2rem)] rounded-lg border border-[var(--sc-border)]/60 bg-[var(--sc-bg-surface)] backdrop-blur-sm p-3 hover:border-[var(--sc-border)]/80 transition-colors ${
                          isLeft ? 'md:mr-auto md:ml-0' : 'md:ml-auto md:mr-0'
                        }`}
                      >
                        {/* Header row */}
                        <div className="flex items-start justify-between gap-2 mb-1.5">
                          <h3 className="text-sm font-medium text-[var(--sc-text-primary)] leading-tight flex-1 line-clamp-1">
                            {memory.title}
                          </h3>
                          <span className="text-[10px] text-[var(--sc-text-muted)] whitespace-nowrap">
                            {formatTime(memory.createdAt)}
                          </span>
                        </div>

                        {/* Content (truncated to 2 lines) */}
                        <p className="text-xs text-[var(--sc-text-secondary)] line-clamp-2 mb-2 leading-relaxed">
                          {memory.content}
                        </p>

                        {/* Badge row */}
                        <div className="flex items-center flex-wrap gap-1.5">
                          {/* Category badge */}
                          <span
                            className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium"
                            style={{
                              backgroundColor: `${catColour}18`,
                              color: catColour,
                              border: `1px solid ${catColour}33`,
                            }}
                          >
                            {memory.category}
                          </span>

                          {/* Memory type badge */}
                          <span
                            className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium"
                            style={{
                              backgroundColor: `${typeColour}18`,
                              color: typeColour,
                              border: `1px solid ${typeColour}33`,
                            }}
                          >
                            {typeLabel}
                          </span>

                          {/* Importance indicator */}
                          <span
                            className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px]"
                            style={{ color: importance.colour }}
                          >
                            <span
                              className="w-1.5 h-1.5 rounded-full"
                              style={{ backgroundColor: importance.colour }}
                            />
                            {importance.label}
                          </span>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
