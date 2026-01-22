'use client';

/**
 * Memory Detail
 * Shows detailed information about a selected memory
 */

import { Memory } from '@/types/memory';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { getCategoryColor, getTypeColor } from '@/lib/category-colors';
import { calculateDecayFactor } from '@/lib/position-algorithm';

interface MemoryDetailProps {
  memory: Memory;
  onClose: () => void;
  onReinforce?: (id: number) => void;
}

export function MemoryDetail({
  memory,
  onClose,
  onReinforce,
}: MemoryDetailProps) {
  const decayFactor = calculateDecayFactor(memory);
  const categoryColor = getCategoryColor(memory.category);
  const typeColor = getTypeColor(memory.type);

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
    <Card className="bg-slate-900 border-slate-700 h-full">
      <CardHeader className="border-b border-slate-700 pb-3">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-lg font-semibold text-white leading-tight">
            {memory.title}
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="text-slate-400 hover:text-white -mt-1"
          >
            ✕
          </Button>
        </div>
        <div className="flex items-center gap-2 mt-2">
          <span
            className="px-2 py-0.5 rounded text-xs font-medium"
            style={{
              backgroundColor: categoryColor + '20',
              color: categoryColor,
            }}
          >
            {memory.category}
          </span>
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
          <p className="text-sm text-slate-200 whitespace-pre-wrap leading-relaxed">
            {memory.content}
          </p>
        </div>

        {/* Metrics */}
        <div className="grid grid-cols-2 gap-3">
          <div className="bg-slate-800 rounded-lg p-3">
            <div className="text-xs text-slate-400">Salience</div>
            <div className="text-lg font-bold text-white">
              {(memory.salience * 100).toFixed(0)}%
            </div>
            <div className="mt-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-red-500 via-yellow-500 to-green-500 rounded-full"
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
                className="h-full rounded-full"
                style={{
                  width: `${decayFactor * 100}%`,
                  backgroundColor:
                    decayFactor > 0.7
                      ? '#22C55E'
                      : decayFactor > 0.4
                      ? '#EAB308'
                      : '#EF4444',
                }}
              />
            </div>
          </div>
        </div>

        {/* Access info */}
        <div className="bg-slate-800 rounded-lg p-3 space-y-2">
          <div className="flex justify-between items-center">
            <span className="text-xs text-slate-400">Access Count</span>
            <span className="text-sm font-medium text-white">
              {memory.accessCount} times
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-xs text-slate-400">Last Accessed</span>
            <span className="text-sm text-white">
              {timeSince(memory.lastAccessed)}
            </span>
          </div>
          <div className="flex justify-between items-center">
            <span className="text-xs text-slate-400">Created</span>
            <span className="text-sm text-white">
              {formatDate(memory.createdAt)}
            </span>
          </div>
        </div>

        {/* Tags */}
        {memory.tags && memory.tags.length > 0 && (
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
        <div className="flex gap-2 pt-2">
          {onReinforce && (
            <Button
              variant="default"
              size="sm"
              onClick={() => onReinforce(memory.id)}
              className="flex-1 bg-blue-600 hover:bg-blue-700"
            >
              Reinforce Memory
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
