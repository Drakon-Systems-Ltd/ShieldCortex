'use client';

import { Memory } from '@/types/memory';
import { getCategoryColor, getTypeColor } from '@/lib/category-colors';

function relativeTime(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 7) return `${days}d ago`;
  const weeks = Math.floor(days / 7);
  return `${weeks}w ago`;
}

interface MemoryCardProps {
  memory: Memory;
  isSelected: boolean;
  onSelect: (m: Memory) => void;
  isChecked?: boolean;
  onCheck?: (id: number, checked: boolean) => void;
}

export function MemoryCard({ memory, isSelected, onSelect, isChecked, onCheck }: MemoryCardProps) {
  const catColor = getCategoryColor(memory.category);
  const typeColor = getTypeColor(memory.type);

  return (
    <div
      onClick={() => onSelect(memory)}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onSelect(memory);
        }
      }}
      role="button"
      tabIndex={0}
      className={`bg-[var(--sc-bg-surface)] border rounded-lg p-3 hover:border-[var(--sc-border)] cursor-pointer transition-colors relative ${
        isSelected ? 'border-[var(--sc-cyan)]' : 'border-[var(--sc-border)]'
      }`}
    >
      {/* Salience bar */}
      <div className="h-0.5 rounded-full bg-[var(--sc-bg-elevated)] mb-2 overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{ width: `${memory.salience * 100}%`, backgroundColor: catColor }}
        />
      </div>

      {/* Checkbox */}
      {onCheck && (
        <input
          type="checkbox"
          checked={isChecked ?? false}
          onChange={(e) => {
            e.stopPropagation();
            onCheck(memory.id, e.target.checked);
          }}
          onClick={(e) => e.stopPropagation()}
          className="absolute top-3 right-3 w-4 h-4 accent-blue-500"
        />
      )}

      {/* Title */}
      <h3 className="text-sm font-semibold text-[var(--sc-text-primary)] truncate pr-6">{memory.title}</h3>

      {/* Badges */}
      <div className="flex items-center gap-1.5 mt-1">
        <span
          className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
          style={{ backgroundColor: catColor + '22', color: catColor }}
        >
          {memory.category}
        </span>
        <span
          className="text-[10px] px-1.5 py-0.5 rounded-full font-medium"
          style={{ backgroundColor: typeColor + '22', color: typeColor }}
        >
          {memory.type.replace('_', '-')}
        </span>
        {memory.status && memory.status !== 'active' && (
          <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium bg-[var(--sc-amber)]/15 text-[var(--sc-amber)]">
            {memory.status}
          </span>
        )}
        {memory.pinned && (
          <span className="text-[10px] px-1.5 py-0.5 rounded-full font-medium bg-[var(--sc-cyan)]/15 text-[var(--sc-cyan)]">
            pinned
          </span>
        )}
      </div>

      <div className="flex items-center gap-1.5 mt-2 flex-wrap">
        {memory.sourceKind && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--sc-bg-elevated)] text-[var(--sc-text-primary)]">
            {memory.sourceKind}
          </span>
        )}
        {memory.captureMethod && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--sc-bg-elevated)] text-[var(--sc-text-primary)]">
            {memory.captureMethod}
          </span>
        )}
        {typeof memory.trustScore === 'number' && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${
            memory.trustScore < 0.7 ? 'bg-[var(--sc-coral)]/15 text-[var(--sc-coral)]' : 'bg-[var(--sc-cyan)]/15 text-[var(--sc-cyan)]'
          }`}>
            trust {memory.trustScore.toFixed(2)}
          </span>
        )}
        {memory.cloudExcluded && (
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--sc-amber)]/15 text-[var(--sc-amber)]">
            cloud excluded
          </span>
        )}
      </div>

      {/* Content preview */}
      <p className="text-[13px] text-[var(--sc-text-secondary)] mt-1.5 line-clamp-3 leading-snug">{memory.content}</p>

      {/* Tags */}
      {memory.tags.length > 0 && (
        <div className="flex items-center gap-1 mt-2 flex-wrap">
          {memory.tags.slice(0, 3).map((tag) => (
            <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-[var(--sc-bg-elevated)] text-[var(--sc-text-secondary)]">
              {tag}
            </span>
          ))}
          {memory.tags.length > 3 && (
            <span className="text-[10px] text-[var(--sc-text-muted)]">+{memory.tags.length - 3} more</span>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between mt-2 text-[11px] text-[var(--sc-text-muted)]">
        <span>Created {relativeTime(memory.createdAt)}</span>
        <span>Accessed {relativeTime(memory.lastAccessed)}</span>
      </div>
    </div>
  );
}
