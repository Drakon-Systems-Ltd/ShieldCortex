'use client';

/**
 * Memory Inspector
 * Right-panel detail view shown when a memory node is selected in the 3D brain.
 *
 * Sections:
 * 1. Header (sticky) — title, category/type badges, salience meter, health dot, close
 * 2. Detail — full content, tags, metadata grid
 * 3. Connections — linked memories with relationship badges and strength bars
 * 4. Actions Toolbar (sticky bottom) — boost, demote, promote, delete, quarantine
 * 5. Empty State — shown when no memory is selected
 */

import { Memory, MemoryLink, MemoryCategory } from '@/types/memory';
import { CATEGORY_COLORS } from '@/lib/category-colors';

interface MemoryInspectorProps {
  memory: Memory | null;
  links: MemoryLink[];
  onClose: () => void;
  onBoost: (id: number) => void;
  onDemote: (id: number) => void;
  onPromote: (id: number) => void;
  onDelete: (id: number) => void;
  onQuarantine: (id: number) => void;
  onEdit: (id: number, updates: { title?: string; content?: string; tags?: string[]; category?: string }) => void;
  onNavigateToMemory: (id: number) => void;
  onCreateLink?: (sourceId: number, targetId: number, relationship: string) => void;
}

function relativeTime(dateStr: string): string {
  const ms = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(ms / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

const TYPE_LABELS: Record<string, string> = {
  short_term: 'STM',
  long_term: 'LTM',
  episodic: 'Episodic',
};

const RELATIONSHIP_COLORS: Record<string, string> = {
  references: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  extends: 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)] border-[var(--sc-cyan)]/30',
  contradicts: 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] border-[var(--sc-coral)]/30',
  related: 'bg-[var(--sc-bg-elevated)]/20 text-[var(--sc-text-secondary)] border-[var(--sc-border)]/30',
};

const RELATIONSHIP_BAR_COLORS: Record<string, string> = {
  references: '#3B82F6',
  extends: '#10B981',
  contradicts: '#EF4444',
  related: '#6B7280',
};

export function MemoryInspector({
  memory,
  links,
  onClose,
  onBoost,
  onDemote,
  onPromote,
  onDelete,
  onQuarantine,
  onNavigateToMemory,
}: MemoryInspectorProps) {
  // Empty state
  if (!memory) {
    return (
      <div className="w-80 shrink-0 h-full bg-[var(--sc-bg-surface)] backdrop-blur-sm border-l border-[var(--sc-border)] flex flex-col items-center justify-center">
        <div className="text-[var(--sc-text-muted)] mb-3">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2a7 7 0 0 1 7 7c0 2.38-1.19 4.47-3 5.74V17a1 1 0 0 1-1 1H9a1 1 0 0 1-1-1v-2.26C6.19 13.47 5 11.38 5 9a7 7 0 0 1 7-7z" />
            <path d="M9 21h6" />
            <path d="M10 21v1a1 1 0 0 0 1 1h2a1 1 0 0 0 1-1v-1" />
          </svg>
        </div>
        <p className="text-[var(--sc-text-muted)] text-sm">Click a memory node to inspect it</p>
      </div>
    );
  }

  const salience = memory.salience ?? 0;
  const decayedScore = memory.decayedScore ?? salience;
  const categoryColor = CATEGORY_COLORS[memory.category] || CATEGORY_COLORS.custom;

  // Health indicator based on decayedScore
  const healthClass =
    decayedScore > 0.7
      ? 'bg-[var(--sc-cyan)]'
      : decayedScore >= 0.4
        ? 'bg-[var(--sc-amber)]'
        : 'bg-[var(--sc-coral)]';

  // Resolve connections: find the other side of each link relative to this memory
  const connections = links.map((link) => {
    const isSource = link.source_id === memory.id;
    return {
      link,
      targetId: isSource ? link.target_id : link.source_id,
      targetTitle: isSource
        ? (link.target_title || `Memory #${link.target_id}`)
        : (link.source_title || `Memory #${link.source_id}`),
      targetCategory: isSource ? link.target_category : link.source_category,
      relationship: link.relationship,
      strength: link.strength,
    };
  });

  return (
    <div className="w-80 shrink-0 h-full bg-[var(--sc-bg-surface)] backdrop-blur-sm border-l border-[var(--sc-border)] flex flex-col">
      {/* ── Header (sticky top) ── */}
      <div className="sticky top-0 z-10 bg-[var(--sc-bg-surface)] backdrop-blur-sm border-b border-[var(--sc-border)] p-4 flex-shrink-0">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-3 right-3 text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors"
          aria-label="Close inspector"
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
            <path d="M4 4l8 8M12 4l-8 8" />
          </svg>
        </button>

        {/* Title */}
        <h3 className="text-[var(--sc-text-primary)] font-medium text-sm pr-6 leading-tight mb-2">
          {memory.title}
        </h3>

        {/* Category + Type badges */}
        <div className="flex items-center gap-1.5 mb-2.5">
          <span
            className="text-[10px] font-medium px-1.5 py-0.5 rounded-full border"
            style={{
              color: categoryColor,
              borderColor: `${categoryColor}40`,
              backgroundColor: `${categoryColor}15`,
            }}
          >
            {memory.category}
          </span>
          <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] border border-[var(--sc-border)]">
            {TYPE_LABELS[memory.type] || memory.type}
          </span>
        </div>

        {/* Salience meter */}
        <div className="mb-1.5">
          <div className="flex items-center justify-between mb-0.5">
            <span className="text-[10px] text-[var(--sc-text-muted)]">Salience</span>
            <span className="text-[10px] text-[var(--sc-text-secondary)] font-mono">{salience.toFixed(2)}</span>
          </div>
          <div className="h-1 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: `${Math.min(salience * 100, 100)}%`,
                backgroundColor: categoryColor,
              }}
            />
          </div>
        </div>

        {/* Health indicator */}
        <div className="flex items-center gap-1.5">
          <div className={`w-2 h-2 rounded-full ${healthClass}`} />
          <span className="text-[10px] text-[var(--sc-text-muted)]">
            Health {decayedScore.toFixed(2)}
          </span>
        </div>
      </div>

      {/* ── Scrollable content area ── */}
      <div className="flex-1 overflow-y-auto min-h-0">
        {/* ── Detail Section ── */}
        <div className="p-4 border-b border-[var(--sc-border)]">
          {/* Content */}
          <div className="mb-3">
            <div className="text-[10px] text-[var(--sc-text-muted)] uppercase tracking-wider mb-1">Content</div>
            <div className="max-h-48 overflow-y-auto rounded bg-[var(--sc-bg-deep)]/60 border border-[var(--sc-border)] p-2">
              <pre className="text-xs text-[var(--sc-text-primary)] whitespace-pre-wrap break-words font-mono leading-relaxed">
                {memory.content}
              </pre>
            </div>
          </div>

          {/* Tags */}
          {memory.tags && memory.tags.length > 0 && (
            <div className="mb-3">
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase tracking-wider mb-1">Tags</div>
              <div className="flex flex-wrap gap-1">
                {memory.tags.map((tag) => (
                  <span
                    key={tag}
                    className="text-[10px] px-1.5 py-0.5 rounded-full bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)] border border-[var(--sc-border)]"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Metadata grid */}
          <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Created</div>
              <div className="text-xs text-[var(--sc-text-primary)]">{relativeTime(memory.createdAt)}</div>
            </div>
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Last Accessed</div>
              <div className="text-xs text-[var(--sc-text-primary)]">{relativeTime(memory.lastAccessed)}</div>
            </div>
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Access Count</div>
              <div className="text-xs text-[var(--sc-text-primary)]">{memory.accessCount}</div>
            </div>
            <div>
              <div className="text-[10px] text-[var(--sc-text-muted)]">Project</div>
              <div className="text-xs text-[var(--sc-text-primary)] truncate" title={memory.project || 'Global'}>
                {memory.project || 'Global'}
              </div>
            </div>
          </div>
        </div>

        {/* ── Connections Section ── */}
        <div className="p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-[var(--sc-text-muted)] uppercase tracking-wider">
              Connections
            </span>
            <span className="text-[10px] text-[var(--sc-text-muted)] font-mono">
              {connections.length}
            </span>
          </div>

          {connections.length === 0 ? (
            <p className="text-xs text-[var(--sc-text-muted)] py-2">No connections yet</p>
          ) : (
            <div className="space-y-2">
              {connections.map((conn) => {
                const relColor = RELATIONSHIP_COLORS[conn.relationship] || RELATIONSHIP_COLORS.related;
                const barColor = RELATIONSHIP_BAR_COLORS[conn.relationship] || RELATIONSHIP_BAR_COLORS.related;
                const connCategoryColor = conn.targetCategory
                  ? CATEGORY_COLORS[conn.targetCategory] || CATEGORY_COLORS.custom
                  : '#6B7280';

                return (
                  <button
                    key={conn.link.id}
                    onClick={() => onNavigateToMemory(conn.targetId)}
                    className="w-full text-left rounded bg-[var(--sc-bg-elevated)] hover:bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] hover:border-[var(--sc-border)] p-2 transition-colors group"
                  >
                    {/* Target title with category dot */}
                    <div className="flex items-start gap-1.5 mb-1">
                      <div
                        className="w-1.5 h-1.5 rounded-full mt-1 flex-shrink-0"
                        style={{ backgroundColor: connCategoryColor }}
                      />
                      <span className="text-xs text-[var(--sc-text-primary)] group-hover:text-[var(--sc-text-primary)] leading-tight line-clamp-2">
                        {conn.targetTitle}
                      </span>
                    </div>

                    {/* Relationship badge */}
                    <div className="flex items-center gap-2 mt-1">
                      <span className={`text-[9px] px-1 py-0.5 rounded border ${relColor}`}>
                        {conn.relationship}
                      </span>

                      {/* Strength bar */}
                      <div className="flex-1 h-0.5 bg-[var(--sc-bg-elevated)] rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.min(conn.strength * 100, 100)}%`,
                            backgroundColor: barColor,
                          }}
                        />
                      </div>
                      <span className="text-[9px] text-[var(--sc-text-muted)] font-mono">
                        {conn.strength.toFixed(1)}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* ── Actions Toolbar (sticky bottom) ── */}
      <div className="sticky bottom-0 z-10 bg-[var(--sc-bg-surface)] backdrop-blur-sm border-t border-[var(--sc-border)] p-3 flex-shrink-0">
        <div className="flex items-center gap-1">
          {/* Boost */}
          <button
            onClick={() => onBoost(memory.id)}
            className="flex-1 flex flex-col items-center gap-0.5 py-1.5 px-1 rounded text-[var(--sc-text-secondary)] hover:text-[var(--sc-cyan)] hover:bg-[var(--sc-bg-elevated)] transition-colors"
            title="Boost salience"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M8 12V4M4 8l4-4 4 4" />
            </svg>
            <span className="text-[9px]">Boost</span>
          </button>

          {/* Demote */}
          <button
            onClick={() => onDemote(memory.id)}
            className="flex-1 flex flex-col items-center gap-0.5 py-1.5 px-1 rounded text-[var(--sc-text-secondary)] hover:text-[var(--sc-amber)] hover:bg-[var(--sc-bg-elevated)] transition-colors"
            title="Demote salience"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M8 4v8M4 8l4 4 4-4" />
            </svg>
            <span className="text-[9px]">Demote</span>
          </button>

          {/* Promote (only for short_term) */}
          {memory.type === 'short_term' && (
            <button
              onClick={() => onPromote(memory.id)}
              className="flex-1 flex flex-col items-center gap-0.5 py-1.5 px-1 rounded text-[var(--sc-text-secondary)] hover:text-blue-400 hover:bg-[var(--sc-bg-elevated)] transition-colors"
              title="Promote to LTM"
            >
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M4 12l4-8 4 8" />
                <path d="M5.5 9h5" />
              </svg>
              <span className="text-[9px]">Promote</span>
            </button>
          )}

          {/* Delete */}
          <button
            onClick={() => {
              if (window.confirm(`Delete memory "${memory.title}"? This cannot be undone.`)) {
                onDelete(memory.id);
              }
            }}
            className="flex-1 flex flex-col items-center gap-0.5 py-1.5 px-1 rounded text-[var(--sc-text-secondary)] hover:text-[var(--sc-coral)] hover:bg-[var(--sc-bg-elevated)] transition-colors"
            title="Delete memory"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M2 4h12M5 4V3a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v1M6 7v5M10 7v5" />
              <path d="M3 4l1 9a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1l1-9" />
            </svg>
            <span className="text-[9px]">Delete</span>
          </button>

          {/* Quarantine */}
          <button
            onClick={() => {
              if (window.confirm(`Quarantine memory "${memory.title}"? It will be flagged for review.`)) {
                onQuarantine(memory.id);
              }
            }}
            className="flex-1 flex flex-col items-center gap-0.5 py-1.5 px-1 rounded text-[var(--sc-text-secondary)] hover:text-[var(--sc-coral)] hover:bg-[var(--sc-bg-elevated)] transition-colors"
            title="Quarantine memory"
          >
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M8 1.5L1.5 5v6L8 14.5 14.5 11V5L8 1.5z" />
              <path d="M8 5v4M8 11h.01" />
            </svg>
            <span className="text-[9px]">Quarantine</span>
          </button>
        </div>
      </div>
    </div>
  );
}
