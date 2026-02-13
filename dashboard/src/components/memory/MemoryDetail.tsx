'use client';

/**
 * Memory Detail
 * Shows detailed information about a selected memory
 * including related memories, decay visualization, edit and delete actions
 */

import { useMemo, useState, useEffect, useCallback } from 'react';
import { Memory, MemoryLink } from '@/types/memory';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { getCategoryColor, getTypeColor } from '@/lib/category-colors';
import { calculateDecayFactor } from '@/lib/position-algorithm';
import { useEditMemory, useDeleteMemory } from '@/hooks/useMemories';

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

  // Reset edit state when memory changes
  useEffect(() => {
    setIsEditing(false);
    setShowDeleteConfirm(false);
    setEditTitle(memory.title);
    setEditContent(memory.content);
    setEditCategory(memory.category as Category);
    setEditTags((memory.tags || []).join(', '));
  }, [memory.id, memory.title, memory.content, memory.category, memory.tags]);

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

  const handleSaveEdit = useCallback(() => {
    const tags = editTags
      .split(',')
      .map(t => t.trim())
      .filter(Boolean);

    editMutation.mutate(
      {
        id: memory.id,
        updates: {
          title: editTitle,
          content: editContent,
          category: editCategory,
          tags,
        },
      },
      {
        onSuccess: () => {
          setIsEditing(false);
        },
      }
    );
  }, [memory.id, editTitle, editContent, editCategory, editTags, editMutation]);

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

  const formatDate = (dateStr: string) => {
    const date = new Date(dateStr);
    return date.toLocaleString();
  };

  const timeSince = (dateStr: string) => {
    const date = new Date(dateStr);
    const now = new Date();
    const hours = Math.floor((now.getTime() - date.getTime()) / (1000 * 60 * 60));

    if (hours < 1) return 'Just now';
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    if (days < 7) return `${days}d ago`;
    return `${Math.floor(days / 7)}w ago`;
  };

  return (
    <Card className={`bg-slate-900 border-slate-700 h-full overflow-auto transition-all duration-300 ${showSuccessFlash ? 'ring-2 ring-green-500 ring-opacity-75' : ''}`}>
      <CardHeader className="border-b border-slate-700 pb-3">
        <div className="flex items-start justify-between gap-2">
          {isEditing ? (
            <Input
              value={editTitle}
              onChange={(e) => setEditTitle(e.target.value)}
              className="bg-slate-800 border-slate-600 text-white text-lg font-semibold"
            />
          ) : (
            <CardTitle className="text-lg font-semibold text-white leading-tight">
              {memory.title}
            </CardTitle>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="text-slate-400 hover:text-white -mt-1 shrink-0"
          >
            ✕
          </Button>
        </div>
        <div className="flex items-center gap-2 mt-2">
          {isEditing ? (
            <select
              value={editCategory}
              onChange={(e) => setEditCategory(e.target.value as Category)}
              className="bg-slate-800 border border-slate-600 text-white text-xs rounded-lg px-2 py-1"
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
          <h4 className="text-xs font-medium text-slate-400 mb-1">Content</h4>
          {isEditing ? (
            <textarea
              value={editContent}
              onChange={(e) => setEditContent(e.target.value)}
              rows={6}
              className="w-full bg-slate-800 border border-slate-600 text-sm text-slate-200 rounded-lg p-3 resize-y focus:ring-cyan-500 focus:border-cyan-500"
            />
          ) : (
            <p className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">
              {memory.content}
            </p>
          )}
        </div>

        {/* Tags (edit mode) */}
        {isEditing && (
          <div>
            <h4 className="text-xs font-medium text-slate-400 mb-1">Tags (comma-separated)</h4>
            <Input
              value={editTags}
              onChange={(e) => setEditTags(e.target.value)}
              placeholder="tag1, tag2, tag3"
              className="bg-slate-800 border-slate-600 text-white text-sm"
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
              className="flex-1 bg-emerald-600 hover:bg-emerald-700"
            >
              {editMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleCancelEdit}
              className="flex-1 border-slate-600 text-slate-300 hover:text-white"
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
              <div className="text-xs text-slate-400">
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
            <div className="bg-slate-800 rounded-lg p-3">
              <div className="text-xs text-slate-400">Salience</div>
              <div className="text-lg font-bold text-white">
                {(memory.salience * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 rounded-full transition-all"
                  style={{ width: `${memory.salience * 100}%` }}
                />
              </div>
            </div>

            <div className="bg-slate-800 rounded-lg p-3">
              <div className="text-xs text-slate-400">Decay Factor</div>
              <div className="text-lg font-bold text-white">
                {(decayFactor * 100).toFixed(0)}%
              </div>
              <div className="mt-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
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
          <div className={`bg-slate-800 rounded-lg p-3 space-y-2 transition-all duration-300 ${showSuccessFlash ? 'ring-1 ring-green-500/50' : ''}`}>
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Access Count</span>
              <span className={`text-sm font-medium transition-all duration-300 ${showSuccessFlash ? 'text-green-400 scale-110' : 'text-white'}`}>
                {memory.accessCount} times
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Last Accessed</span>
              <span className={`text-sm transition-all duration-300 ${showSuccessFlash ? 'text-green-400' : 'text-white'}`}>
                {showSuccessFlash ? 'Just now' : timeSince(memory.lastAccessed)}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Created</span>
              <span className="text-sm text-white">
                {formatDate(memory.createdAt)}
              </span>
            </div>
          </div>
        )}

        {/* Related Memories */}
        {!isEditing && relatedMemories.length > 0 && (
          <div>
            <h4 className="text-xs font-medium text-slate-400 mb-2 flex items-center gap-2">
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
                    className="w-full text-left p-2 bg-slate-800 hover:bg-slate-750 rounded-lg transition-colors group"
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
                      <span className="text-[10px] text-slate-500 ml-auto">
                        {(strength * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="text-sm text-white truncate group-hover:text-blue-400 transition-colors">
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
                      <span className="text-[10px] text-slate-500">
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
            <h4 className="text-xs font-medium text-slate-400 mb-2">Tags</h4>
            <div className="flex flex-wrap gap-1">
              {memory.tags.map((tag, i) => (
                <span
                  key={i}
                  className="px-2 py-0.5 bg-slate-700 text-slate-300 rounded text-xs"
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
            <div className="flex gap-2">
              {onReinforce && (
                <Button
                  variant="default"
                  size="sm"
                  onClick={handleReinforce}
                  disabled={isReinforcing}
                  className={`flex-1 transition-all duration-300 ${
                    showSuccessFlash
                      ? 'bg-green-600 hover:bg-green-600'
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
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsEditing(true)}
                className="flex-1 border-slate-600 text-slate-300 hover:text-white hover:bg-slate-700"
              >
                Edit
              </Button>
            </div>

            {/* Delete */}
            {showDeleteConfirm ? (
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                <p className="text-xs text-red-400 mb-2">Delete this memory permanently?</p>
                <div className="flex gap-2">
                  <Button
                    variant="default"
                    size="sm"
                    onClick={handleDelete}
                    disabled={deleteMutation.isPending}
                    className="flex-1 bg-red-600 hover:bg-red-700"
                  >
                    {deleteMutation.isPending ? 'Deleting...' : 'Confirm Delete'}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowDeleteConfirm(false)}
                    className="flex-1 border-slate-600 text-slate-300 hover:text-white"
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
                className="w-full text-slate-500 hover:text-red-400 hover:bg-red-500/10"
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
