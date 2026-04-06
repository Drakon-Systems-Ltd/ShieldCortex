'use client';

/**
 * Memory Detail
 * Shows detailed information about a selected memory
 * including related memories, decay visualization, edit and delete actions
 */

import { useMemo, useState, useEffect } from 'react';
import { Memory, MemoryLink } from '@/types/memory';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { getCategoryColor, getTypeColor } from '@/lib/category-colors';
import { calculateDecayFactor } from '@/lib/position-algorithm';
import { useEditMemory, useDeleteMemory } from '@/hooks/useMemories';
import { Pencil, Check } from 'lucide-react';

interface MemoryDetailProps {
  memory: Memory;
  links?: MemoryLink[];
  memories?: Memory[];
  onClose: () => void;
  onReinforce?: (id: number) => void;
  onSelectMemory?: (id: number) => void;
  isReinforcing?: boolean;
  reinforceSuccess?: boolean;
}

// Relationship styling
const RELATIONSHIP_STYLES: Record<string, { color: string; label: string; icon: string }> = {
  references: { color: '#60a5fa', label: 'References', icon: '→' },
  extends: { color: '#34d399', label: 'Extends', icon: '⊃' },
  contradicts: { color: '#f87171', label: 'Contradicts', icon: '⊗' },
  related: { color: '#a78bfa', label: 'Related', icon: '~' },
};

const CATEGORIES = ['architecture', 'pattern', 'preference', 'error', 'context', 'learning', 'todo', 'note', 'relationship', 'custom'] as const;
type Category = typeof CATEGORIES[number];

// Get health status based on decay
function getHealthStatus(decayFactor: number): { label: string; color: string; bgColor: string } {
  if (decayFactor > 0.7) {
    return { label: 'Healthy', color: '#22C55E', bgColor: 'rgba(34, 197, 94, 0.15)' };
  }
  if (decayFactor > 0.4) {
    return { label: 'Fading', color: '#EAB308', bgColor: 'rgba(234, 179, 8, 0.15)' };
  }
  return { label: 'Critical', color: '#EF4444', bgColor: 'rgba(239, 68, 68, 0.15)' };
}

export function MemoryDetail({
  memory,
  links = [],
  memories = [],
  onClose,
  onReinforce,
  onSelectMemory,
  isReinforcing = false,
  reinforceSuccess = false,
}: MemoryDetailProps) {
  const [showSuccessFlash, setShowSuccessFlash] = useState(false);
  const [showSaveSuccess, setShowSaveSuccess] = useState(false);
  const [lastReinforcedId, setLastReinforcedId] = useState<number | null>(null);

  // Edit state
  const [isEditing, setIsEditing] = useState(false);
  const [editTitle, setEditTitle] = useState(memory.title);
  const [editContent, setEditContent] = useState(memory.content);
  const [editCategory, setEditCategory] = useState<Category>(memory.category as Category);
  const [editTags, setEditTags] = useState((memory.tags || []).join(', '));

  // Delete confirmation
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  // Mutations
  const editMutation = useEditMemory();
  const deleteMutation = useDeleteMemory();

  // Reset edit state when memory changes (React-recommended pattern for
  // adjusting state based on prop changes — avoids cascading renders from effects)
  const [prevMemoryId, setPrevMemoryId] = useState(memory.id);
  if (prevMemoryId !== memory.id) {
    setPrevMemoryId(memory.id);
    setIsEditing(false);
    setShowDeleteConfirm(false);
    setEditTitle(memory.title);
    setEditContent(memory.content);
    setEditCategory(memory.category as Category);
    setEditTags((memory.tags || []).join(', '));
  }

  // Show success flash when reinforcement completes
  useEffect(() => {
    if (reinforceSuccess && lastReinforcedId === memory.id) {
      const flashTimer = setTimeout(() => setShowSuccessFlash(true), 0);
      const hideTimer = setTimeout(() => setShowSuccessFlash(false), 1500);
      return () => {
        clearTimeout(flashTimer);
        clearTimeout(hideTimer);
      };
    }
  }, [reinforceSuccess, lastReinforcedId, memory.id]);

  const handleReinforce = () => {
    setLastReinforcedId(memory.id);
    onReinforce?.(memory.id);
  };

  const handleSaveEdit = () => {
    const tags = editTags
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);

    // Only send changed fields
    const updates: Record<string, unknown> = {};
    if (editTitle !== memory.title) updates.title = editTitle;
    if (editContent !== memory.content) updates.content = editContent;
    if (editCategory !== memory.category) updates.category = editCategory;
    const currentTags = (memory.tags || []).join(', ');
    if (editTags !== currentTags) updates.tags = tags;

    // Nothing changed — just exit edit mode
    if (Object.keys(updates).length === 0) {
      setIsEditing(false);
      return;
    }

    editMutation.mutate(
      {
        id: memory.id,
        updates: updates as { title?: string; content?: string; category?: string; tags?: string[] },
      },
      {
        onSuccess: () => {
          setIsEditing(false);
          setShowSaveSuccess(true);
          setTimeout(() => setShowSaveSuccess(false), 1500);
        },
      }
    );
  };

  const handleCancelEdit = () => {
    setIsEditing(false);
    setEditTitle(memory.title);
    setEditContent(memory.content);
    setEditCategory(memory.category as Category);
    setEditTags((memory.tags || []).join(', '));
  };

  const handleDelete = () => {
    deleteMutation.mutate(memory.id, {
      onSuccess: () => {
        onClose();
      },
    });
  };

  const decayFactor = calculateDecayFactor(memory);
  const categoryColor = getCategoryColor(memory.category);
  const typeColor = getTypeColor(memory.type);
  const healthStatus = getHealthStatus(decayFactor);

  // Find related memories through links
  const relatedMemories = useMemo(() => {
    const related: Array<{
      memory: Memory;
      relationship: string;
      strength: number;
      direction: 'from' | 'to';
    }> = [];

    for (const link of links) {
      if (link.source_id === memory.id) {
        const target = memories.find(m => m.id === link.target_id);
        if (target) {
          related.push({
            memory: target,
            relationship: link.relationship,
            strength: link.strength,
            direction: 'to',
          });
        }
      } else if (link.target_id === memory.id) {
        const source = memories.find(m => m.id === link.source_id);
        if (source) {
          related.push({
            memory: source,
            relationship: link.relationship,
            strength: link.strength,
            direction: 'from',
          });
        }
      }
    }

    return related.sort((a, b) => b.strength - a.strength);
  }, [memory.id, links, memories]);

  const formatDate = (dateStr: string | Date) => {
    const date = new Date(dateStr);
    return date.toLocaleString();
  };

  const timeSince = (dateStr: string | Date) => {
    const date = new Date(dateStr);
    const now = new Date();
    const hours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));

    if (hours < 1) return 'Just now';
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    return `${Math.floor(days / 7)}w ago`;
  };

  const reviewStatusLabel =
    memory.status === 'canonical'
      ? 'Canonical'
      : memory.status === 'archived'
        ? 'Archived'
        : memory.status === 'suppressed'
          ? 'Suppressed'
          : memory.pinned
            ? 'Pinned and active'
            : 'Active';

  return (
    <Card className={`bg-[var(--sc-bg-surface)] border-[var(--sc-border)] overflow-auto transition-all duration-300 ${showSuccessFlash ? 'ring-2 ring-green-500 ring-opacity-75' : ''} ${showSaveSuccess ? 'ring-2 ring-emerald-500 ring-opacity-75' : ''}`}>
      <CardHeader className="border-b border-[var(--sc-border)] pb-3">
        <div className="flex items-start justify-between gap-2">
          {isEditing ? (
            <Input
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
              className="bg-[var(--sc-bg-elevated)] border-[var(--sc-border)] text-[var(--sc-text-primary)] text-lg font-semibold"
            />
          ) : (
            <CardTitle className="text-lg font-semibold text-[var(--sc-text-primary)] leading-tight flex items-center gap-2">
              {showSaveSuccess && <Check className="w-4 h-4 text-[var(--sc-cyan)] shrink-0" />}
              {memory.title}
            </CardTitle>
          )}
          <div className="flex items-center gap-1 shrink-0 -mt-1">
            {!isEditing && (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setIsEditing(true)}
                className="text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]"
                title="Edit memory"
              >
                <Pencil className="w-4 h-4" />
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              className="text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]"
            >
              ✕
            </Button>
          </div>
        </div>
        <div className="flex items-center gap-2 mt-2">
          {isEditing ? (
            <select
              value={editCategory}
              onChange={(e) => setEditCategory(e.target.value as Category)}
              className="bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] text-[var(--sc-text-primary)] text-xs rounded-lg px-2 py-1"
            >
              {CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          ) : (
            <span
              className="px-2 py-0.5 rounded text-xs font-medium"
              style={{
                backgroundColor: categoryColor + '20',
                color: categoryColor,
              }}
            >
              {memory.category}
            </span>
          )}
          <span
            className="px-2 py-0.5 rounded text-xs font-medium"
            style={{
              backgroundColor: typeColor + '20',
              color: typeColor,
            }}
          >
            {memory.type.replace('_', '-')}
          </span>
        </div>
      </CardHeader>

      <CardContent className="p-4 space-y-4">
        {/* Content */}
        <div>
          <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-1">Content</h4>
          {isEditing ? (
            <textarea
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              rows={6}
              className="w-full bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] text-sm text-[var(--sc-text-primary)] rounded-lg p-3 resize-y focus:ring-[var(--sc-cyan)] focus:border-[var(--sc-cyan)]"
            />
          ) : (
            <p className="text-sm text-[var(--sc-text-primary)] whitespace-pre-wrap leading-relaxed">
              {memory.content}
            </p>
          )}
        </div>

        {/* Tags (edit mode) */}
        {isEditing && (
          <div>
            <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-1">Tags (comma-separated)</h4>
            <Input
              value={editTags}
              onChange={(e) => setEditTags(e.target.value)}
              placeholder="tag1, tag2, tag3"
              className="bg-[var(--sc-bg-elevated)] border-[var(--sc-border)] text-[var(--sc-text-primary)] text-sm"
            />
          </div>
        )}

        {/* Edit/Save buttons */}
        {isEditing ? (
          <div className="flex gap-2">
            <Button
              variant="default"
              size="sm"
              onClick={handleSaveEdit}
              disabled={editMutation.isPending}
              className="flex-1 bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan)]"
            >
              {editMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleCancelEdit}
              className="flex-1 border-[var(--sc-border)] text-[var(--sc-text-primary)] hover:text-[var(--sc-text-primary)]"
            >
              Cancel
            </Button>
          </div>
        ) : null}

        {/* Health Status Banner */}
        {!isEditing && (
          <div
            className="rounded-lg p-3 flex items-center gap-3"
            style={{ backgroundColor: healthStatus.bgColor }}
          >
            <div
              className="w-3 h-3 rounded-full animate-pulse"
              style={{ backgroundColor: healthStatus.color }}
            />
            <div>
              <div className="text-sm font-medium" style={{ color: healthStatus.color }}>
                {healthStatus.label}
              </div>
              <div className="text-xs text-[var(--sc-text-secondary)]">
                {decayFactor > 0.7
                  ? 'Memory is strong and stable'
                  : decayFactor > 0.4
                  ? 'Memory is fading - reinforce to preserve'
                  : 'Memory at risk of deletion - reinforce now'}
              </div>
            </div>
          </div>
        )}

        {/* Metrics */}
        {!isEditing && (
          <div className="grid grid-cols-2 gap-3">
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
              <div className="text-xs text-[var(--sc-text-secondary)]">Salience</div>
              <div className="text-lg font-bold text-[var(--sc-text-primary)]">
                {(memory.salience * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-[var(--sc-border)] rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 rounded-full transition-all"
                  style={{ width: `${memory.salience * 100}%` }}
                />
              </div>
            </div>

            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-3">
              <div className="text-xs text-[var(--sc-text-secondary)]">Decay Factor</div>
              <div className="text-lg font-bold text-[var(--sc-text-primary)]">
                {(decayFactor * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-[var(--sc-border)] rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all"
                  style={{
                    width: `${decayFactor * 100}%`,
                    backgroundColor: healthStatus.color,
                  }}
                />
              </div>
            </div>
          </div>
        )}

        {/* Access info */}
        {!isEditing && (
          <div className={`bg-[var(--sc-bg-elevated)] rounded-lg p-3 space-y-2 transition-all duration-300 ${showSuccessFlash ? 'ring-1 ring-green-500/50' : ''}`}>
            <div className="flex justify-between items-center">
              <span className="text-xs text-[var(--sc-text-secondary)]">Access Count</span>
              <span className={`text-sm font-medium transition-all duration-300 ${showSuccessFlash ? 'text-[var(--sc-cyan)] scale-110' : 'text-[var(--sc-text-primary)]'}`}>
                {memory.accessCount} times
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-[var(--sc-text-secondary)]">Last Accessed</span>
              <span className={`text-sm transition-all duration-300 ${showSuccessFlash ? 'text-[var(--sc-cyan)]' : 'text-[var(--sc-text-primary)]'}`}>
                {showSuccessFlash ? 'Just now' : timeSince(memory.lastAccessed)}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-[var(--sc-text-secondary)]">Created</span>
              <span className="text-sm text-[var(--sc-text-primary)]">
                {formatDate(memory.createdAt)}
              </span>
            </div>
          </div>
        )}

        {!isEditing && (
          <div className="grid gap-3 md:grid-cols-1">
            <div className="rounded-lg bg-[var(--sc-bg-elevated)] p-3 space-y-2">
              <h4 className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Provenance</h4>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Source kind</span>
                <span className="text-[var(--sc-text-primary)]">{memory.sourceKind || 'user'}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Capture</span>
                <span className="text-[var(--sc-text-primary)]">{memory.captureMethod || 'manual'}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Trust</span>
                <span className="text-[var(--sc-text-primary)]">{(memory.trustScore ?? 1).toFixed(2)}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Origin</span>
                <span className="truncate text-right text-[var(--sc-text-primary)]">{memory.source || 'user:direct'}</span>
              </div>
            </div>

            <div className="rounded-lg bg-[var(--sc-bg-elevated)] p-3 space-y-2">
              <h4 className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Review state</h4>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Status</span>
                <span className="text-[var(--sc-text-primary)]">{reviewStatusLabel}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Pinned</span>
                <span className="text-[var(--sc-text-primary)]">{memory.pinned ? 'Yes' : 'No'}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Reviewed</span>
                <span className="text-[var(--sc-text-primary)]">
                  {memory.reviewedAt ? `${timeSince(memory.reviewedAt)} by ${memory.reviewedBy || 'operator'}` : 'Not reviewed'}
                </span>
              </div>
            </div>

            <div className="rounded-lg bg-[var(--sc-bg-elevated)] p-3 space-y-2">
              <h4 className="text-xs font-medium uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Sync state</h4>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Scope</span>
                <span className="text-[var(--sc-text-primary)]">{memory.scope || 'project'}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Cloud</span>
                <span className="text-[var(--sc-text-primary)]">{memory.cloudExcluded ? 'Excluded' : 'Eligible'}</span>
              </div>
              <div className="flex justify-between gap-3 text-sm">
                <span className="text-[var(--sc-text-secondary)]">Sensitivity</span>
                <span className="text-[var(--sc-text-primary)]">{memory.sensitivityLevel || 'INTERNAL'}</span>
              </div>
            </div>
          </div>
        )}

        {/* Related Memories */}
        {!isEditing && relatedMemories.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2 flex items-center gap-2">
              <span className="inline-block w-4 h-4">🔗</span>
              Related Memories ({relatedMemories.length})
            </h4>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {relatedMemories.map(({ memory: related, relationship, strength, direction }) => {
                const style = RELATIONSHIP_STYLES[relationship] || RELATIONSHIP_STYLES.related;
                const relatedCategoryColor = getCategoryColor(related.category);

                return (
                  <button
                    key={`${related.id}-${direction}`}
                    onClick={() => onSelectMemory?.(related.id)}
                    className="w-full text-left p-2 bg-[var(--sc-bg-elevated)] hover:bg-[var(--sc-surface-interactive)] rounded-lg transition-colors group"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className="w-1.5 h-1.5 rounded-full"
                        style={{ backgroundColor: style.color }}
                      />
                      <span
                        className="text-[10px] font-medium"
                        style={{ color: style.color }}
                      >
                        {direction === 'to' ? `${style.icon} ${style.label}` : `${style.label} ${style.icon}`}
                      </span>
                      <span className="text-[10px] text-[var(--sc-text-muted)] ml-auto">
                        {(strength * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="text-sm text-[var(--sc-text-primary)] truncate group-hover:text-blue-400 transition-colors">
                      {related.title}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span
                        className="px-1.5 py-0.5 rounded text-[10px]"
                        style={{
                          backgroundColor: relatedCategoryColor + '20',
                          color: relatedCategoryColor,
                        }}
                      >
                        {related.category}
                      </span>
                      <span className="text-[10px] text-[var(--sc-text-muted)]">
                        {(related.salience * 100).toFixed(0)}% salience
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Tags (view mode) */}
        {!isEditing && memory.tags && memory.tags.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Tags</h4>
            <div className="flex flex-wrap gap-1">
              {memory.tags.map((tag, i) => (
                <span
                  key={i}
                  className="px-2 py-0.5 bg-[var(--sc-bg-elevated)] text-[var(--sc-text-primary)] rounded text-xs"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        {!isEditing && (
          <div className="space-y-2 pt-2">
            {onReinforce && (
              <Button
                variant="default"
                size="sm"
                onClick={handleReinforce}
                disabled={isReinforcing}
                className={`w-full transition-all duration-300 ${
                  showSuccessFlash
                    ? 'bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan)]'
                    : 'bg-blue-600 hover:bg-blue-700'
                }`}
              >
                {isReinforcing ? (
                  <>
                    <span className="animate-spin mr-2">⟳</span>
                    Reinforcing...
                  </>
                ) : showSuccessFlash ? (
                  <>✓ Reinforced!</>
                ) : (
                  <>⚡ Reinforce</>
                )}
              </Button>
            )}

            {/* Delete */}
            {showDeleteConfirm ? (
              <div className="bg-[var(--sc-coral)]/10 border border-[var(--sc-coral)]/30 rounded-lg p-3">
                <p className="text-xs text-[var(--sc-coral)] mb-2">Delete this memory permanently?</p>
                <div className="flex gap-2">
                  <Button
                    variant="default"
                    size="sm"
                    onClick={handleDelete}
                    disabled={deleteMutation.isPending}
                    className="flex-1 bg-[var(--sc-coral)] hover:bg-[var(--sc-coral)]"
                  >
                    {deleteMutation.isPending ? 'Deleting...' : 'Confirm Delete'}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowDeleteConfirm(false)}
                    className="flex-1 border-[var(--sc-border)] text-[var(--sc-text-primary)] hover:text-[var(--sc-text-primary)]"
                  >
                    Cancel
                  </Button>
                </div>
              </div>
            ) : (
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setShowDeleteConfirm(true)}
                className="w-full text-[var(--sc-text-muted)] hover:text-[var(--sc-coral)] hover:bg-[var(--sc-coral)]/10"
              >
                Delete Memory
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
