'use client';

/**
 * Main Dashboard Page
 * Brain-like visualization of the Claude Memory system
 */

import { useState, useRef, useEffect } from 'react';
import dynamic from 'next/dynamic';
import { useMemoriesWithRealtime, useStats, useAccessMemory, useConsolidate } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { useDebouncedValue } from '@/hooks/useDebouncedValue';
import { useSuggestions } from '@/hooks/useSuggestions';
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
  const [showSuggestions, setShowSuggestions] = useState(false);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const suggestionsRef = useRef<HTMLDivElement>(null);

  // Debounce search to avoid API calls on every keystroke
  const debouncedSearch = useDebouncedValue(searchQuery, 300);

  // Zustand store
  const { selectedMemory, setSelectedMemory } = useDashboardStore();

  // Search suggestions
  const { data: suggestions = [] } = useSuggestions(searchQuery);

  // Close suggestions when clicking outside
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        suggestionsRef.current &&
        !suggestionsRef.current.contains(event.target as Node) &&
        searchInputRef.current &&
        !searchInputRef.current.contains(event.target as Node)
      ) {
        setShowSuggestions(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleSelectSuggestion = (text: string) => {
    setSearchQuery(text);
    setShowSuggestions(false);
    searchInputRef.current?.focus();
  };

  // Data fetching with real-time WebSocket updates
  const {
    data: memories = [],
    isLoading: memoriesLoading,
    isConnected,
  } = useMemoriesWithRealtime({
    limit: 200,
    query: debouncedSearch || undefined,
    mode: debouncedSearch ? 'search' : 'recent',
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
              ref={searchInputRef}
              type="text"
              placeholder="Search memories..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                setShowSuggestions(true);
              }}
              onFocus={() => setShowSuggestions(true)}
              onKeyDown={(e) => {
                if (e.key === 'Escape') {
                  setShowSuggestions(false);
                }
              }}
              className="w-64 bg-slate-800 border-slate-700 text-white placeholder:text-slate-400 focus:ring-blue-500"
            />
            {/* Suggestions dropdown */}
            {showSuggestions && suggestions.length > 0 && (
              <div
                ref={suggestionsRef}
                className="absolute top-full left-0 right-0 mt-1 bg-slate-800 border border-slate-700 rounded-lg shadow-xl overflow-hidden z-50"
              >
                {suggestions.map((suggestion, index) => (
                  <button
                    key={`${suggestion.type}-${suggestion.text}-${index}`}
                    onClick={() => handleSelectSuggestion(suggestion.text)}
                    className="w-full px-3 py-2 text-left hover:bg-slate-700 transition-colors flex items-center gap-2"
                  >
                    <span className="text-white text-sm truncate flex-1">
                      {suggestion.text}
                    </span>
                    <span className="text-xs px-1.5 py-0.5 rounded bg-slate-600 text-slate-300">
                      {suggestion.type}
                    </span>
                  </button>
                ))}
              </div>
            )}
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
          <div className="flex items-center gap-2 text-xs text-slate-400 px-2">
            <span
              className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-500' : 'bg-yellow-500'}`}
              title={isConnected ? 'Real-time connected' : 'Polling mode'}
            />
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
