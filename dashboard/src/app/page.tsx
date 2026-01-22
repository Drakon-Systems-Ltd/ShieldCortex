'use client';

/**
 * Main Dashboard Page
 * Brain-like visualization of the Claude Memory system
 */

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { useMemories, useStats, useAccessMemory, useConsolidate } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { StatsPanel } from '@/components/dashboard/StatsPanel';
import { MemoryDetail } from '@/components/memory/MemoryDetail';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Memory } from '@/types/memory';

// Dynamic import for 3D scene (avoid SSR issues)
const BrainScene = dynamic(
  () => import('@/components/brain/BrainScene').then((mod) => mod.BrainScene),
  {
    ssr: false,
    loading: () => (
      <div className="w-full h-full flex items-center justify-center bg-slate-950">
        <div className="text-slate-400 animate-pulse">Loading 3D Brain...</div>
      </div>
    ),
  }
);

export default function DashboardPage() {
  const [searchQuery, setSearchQuery] = useState('');

  // Zustand store
  const { selectedMemory, setSelectedMemory } = useDashboardStore();

  // Data fetching
  const { data: memories = [], isLoading: memoriesLoading } = useMemories({
    limit: 200,
    query: searchQuery || undefined,
    mode: searchQuery ? 'search' : 'recent',
  });
  const { data: stats, isLoading: statsLoading } = useStats();

  // Mutations
  const accessMutation = useAccessMemory();
  const consolidateMutation = useConsolidate();

  const handleSelectMemory = (memory: Memory | null) => {
    setSelectedMemory(memory);
  };

  const handleReinforce = (id: number) => {
    accessMutation.mutate(id);
  };

  const handleConsolidate = () => {
    consolidateMutation.mutate();
  };

  return (
    <div className="h-screen w-screen bg-slate-950 text-white overflow-hidden flex flex-col">
      {/* Top Bar */}
      <header className="h-14 border-b border-slate-800 flex items-center justify-between px-4 bg-slate-900/50 backdrop-blur-sm shrink-0">
        <div className="flex items-center gap-4">
          <h1 className="text-xl font-bold bg-gradient-to-r from-blue-400 via-purple-500 to-pink-500 bg-clip-text text-transparent">
            Claude Memory Brain
          </h1>
          <div className="relative">
            <Input
              type="text"
              placeholder="Search memories..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-64 bg-slate-800 border-slate-700 text-white placeholder:text-slate-400 focus:ring-blue-500"
            />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleConsolidate}
            disabled={consolidateMutation.isPending}
            className="border-slate-600 text-slate-300 hover:text-white hover:bg-slate-700"
          >
            {consolidateMutation.isPending ? 'Processing...' : 'Consolidate'}
          </Button>
          <div className="text-xs text-slate-400 px-2">
            {memories.length} memories
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Sidebar - Stats */}
        <div className="w-64 border-r border-slate-800 overflow-y-auto p-4 bg-slate-900/30 shrink-0">
          <StatsPanel stats={stats} isLoading={statsLoading} />
        </div>

        {/* Center - Brain Visualization */}
        <div className="flex-1 relative">
          {memoriesLoading ? (
            <div className="w-full h-full flex items-center justify-center">
              <div className="text-slate-400 animate-pulse">Loading memories...</div>
            </div>
          ) : (
            <BrainScene
              memories={memories}
              selectedMemory={selectedMemory}
              onSelectMemory={handleSelectMemory}
            />
          )}
        </div>

        {/* Right Sidebar - Details (conditional) */}
        {selectedMemory && (
          <div className="w-80 border-l border-slate-800 overflow-y-auto shrink-0">
            <MemoryDetail
              memory={selectedMemory}
              onClose={() => setSelectedMemory(null)}
              onReinforce={handleReinforce}
            />
          </div>
        )}
      </div>
    </div>
  );
}
