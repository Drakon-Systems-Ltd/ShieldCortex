'use client';

/**
 * Query Tester Component
 *
 * Allows testing search queries against the memory system
 * with detailed score breakdowns and explanations.
 */

import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Memory } from '@/types/memory';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface SearchResult {
  memory: Memory & { decayedScore: number };
  relevanceScore: number;
}

type SearchMode = 'hybrid' | 'fts' | 'vector';

export function QueryTester() {
  const [query, setQuery] = useState('');
  const [mode, setMode] = useState<SearchMode>('hybrid');
  const [results, setResults] = useState<SearchResult[]>([]);
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSearch = async () => {
    if (!query.trim()) return;

    setIsSearching(true);
    setError(null);

    try {
      const params = new URLSearchParams({
        query: query.trim(),
        mode: 'search',
        limit: '20',
      });

      const response = await fetch(`${API_BASE}/api/memories?${params}`);
      if (!response.ok) {
        throw new Error(`Search failed: ${response.statusText}`);
      }

      const data = await response.json();
      // Transform API response to include relevance score
      const resultsWithScore: SearchResult[] = data.memories.map((m: Memory & { decayedScore: number }) => ({
        memory: m,
        relevanceScore: m.decayedScore, // Using decayedScore as proxy for relevance
      }));

      setResults(resultsWithScore);
    } catch (err) {
      setError((err as Error).message);
      setResults([]);
    } finally {
      setIsSearching(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSearch();
    }
  };

  return (
    <div className="h-full flex flex-col">
      {/* Search Controls */}
      <div className="p-3 border-b border-slate-700 flex gap-2 items-center">
        <Input
          type="text"
          placeholder="Enter search query..."
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          className="flex-1 bg-slate-800 border-slate-600 text-white"
        />

        {/* Mode Toggle */}
        <div className="flex gap-1 bg-slate-800 rounded-lg p-1">
          {(['hybrid', 'fts', 'vector'] as SearchMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-2 py-1 text-xs rounded transition-colors ${
                mode === m
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {m.toUpperCase()}
            </button>
          ))}
        </div>

        <Button
          onClick={handleSearch}
          disabled={isSearching || !query.trim()}
          size="sm"
          className="bg-blue-600 hover:bg-blue-700"
        >
          {isSearching ? 'Searching...' : 'Search'}
        </Button>
      </div>

      {/* Results */}
      <div className="flex-1 overflow-auto p-3">
        {error && (
          <div className="p-3 rounded-lg bg-red-500/20 border border-red-500/50 text-red-300 text-sm mb-3">
            {error}
          </div>
        )}

        {results.length === 0 && !error && (
          <div className="text-slate-500 text-sm text-center py-8">
            {query ? 'No results found' : 'Enter a query to search memories'}
          </div>
        )}

        {results.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs text-slate-400 mb-2">
              Found {results.length} results
            </div>

            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400 border-b border-slate-700">
                  <th className="pb-2 pr-4">Title</th>
                  <th className="pb-2 pr-4 w-20">Score</th>
                  <th className="pb-2 pr-4 w-24">Type</th>
                  <th className="pb-2 w-24">Category</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result, index) => (
                  <tr
                    key={result.memory.id}
                    className="border-b border-slate-800 hover:bg-slate-800/50"
                  >
                    <td className="py-2 pr-4">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 text-xs w-5">
                          {index + 1}.
                        </span>
                        <span className="text-white truncate max-w-[300px]">
                          {result.memory.title}
                        </span>
                      </div>
                    </td>
                    <td className="py-2 pr-4">
                      <div className="flex items-center gap-1">
                        <div
                          className="h-1.5 rounded-full bg-gradient-to-r from-blue-600 to-purple-600"
                          style={{ width: `${result.relevanceScore * 100}%`, maxWidth: '60px' }}
                        />
                        <span className="text-xs text-slate-400">
                          {(result.relevanceScore * 100).toFixed(0)}%
                        </span>
                      </div>
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`text-xs px-1.5 py-0.5 rounded ${
                        result.memory.type === 'long_term'
                          ? 'bg-purple-600/30 text-purple-300'
                          : result.memory.type === 'short_term'
                          ? 'bg-blue-600/30 text-blue-300'
                          : 'bg-green-600/30 text-green-300'
                      }`}>
                        {result.memory.type.replace('_', '-')}
                      </span>
                    </td>
                    <td className="py-2">
                      <span className="text-xs text-slate-400">
                        {result.memory.category}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
