/**
 * Search Suggestions Hook
 *
 * Fetches autocomplete suggestions for the search input.
 */

import { useQuery } from '@tanstack/react-query';
import { useDebouncedValue } from './useDebouncedValue';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface Suggestion {
  text: string;
  type: 'title' | 'category' | 'project';
  count: number;
}

async function fetchSuggestions(query: string): Promise<Suggestion[]> {
  if (!query || query.length < 2) {
    return [];
  }

  const response = await fetch(
    `${API_URL}/api/suggestions?q=${encodeURIComponent(query)}&limit=8`
  );

  if (!response.ok) {
    throw new Error('Failed to fetch suggestions');
  }

  const data = await response.json();
  return data.suggestions;
}

export function useSuggestions(query: string) {
  // Debounce the query to avoid too many requests
  const debouncedQuery = useDebouncedValue(query, 200);

  return useQuery({
    queryKey: ['suggestions', debouncedQuery],
    queryFn: () => fetchSuggestions(debouncedQuery),
    enabled: debouncedQuery.length >= 2,
    staleTime: 30000, // Cache for 30 seconds
    refetchOnWindowFocus: false,
  });
}
