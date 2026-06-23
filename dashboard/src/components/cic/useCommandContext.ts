'use client';

import { useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { authFetch, readApiError } from '@/lib/auth';
import { useTheme } from '@/hooks/useTheme';
import { useXRayScan } from '@/hooks/useXRay';
import { useDeleteMemory, useConsolidate } from '@/hooks/useMemories';
import { NAV_ITEMS } from '@/components/layout/route-config';
import type { CommandContext } from '@/lib/commands/registry';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

/**
 * Binds the command registry's {@link CommandContext} to the dashboard's real
 * hooks/endpoints. This is what makes the command rail actually do things; the
 * rail component itself stays presentational + testable (it mocks this hook).
 */
export function useCommandContext(): CommandContext {
  const router = useRouter();
  const [, setTheme] = useTheme();
  const xray = useXRayScan();
  const del = useDeleteMemory();
  const cons = useConsolidate();

  return useMemo<CommandContext>(
    () => ({
      navigate: (path) => router.push(path),
      setTheme,
      recall: async (query, project) => {
        const params = new URLSearchParams({ mode: 'search', query, limit: '10' });
        if (project) params.set('project', project);
        const res = await authFetch(`${API_BASE}/api/memories?${params.toString()}`);
        if (!res.ok) throw new Error(await readApiError(res, 'recall failed'));
        const data = (await res.json()) as { memories?: { id: number; title: string }[] };
        return (data.memories ?? []).map((m) => ({ id: m.id, title: m.title }));
      },
      scan: async (target, deep) => {
        const { result } = await xray.mutateAsync({ target, deep });
        return {
          target: result.target,
          riskLevel: result.riskLevel,
          trustScore: result.trustScore,
          filesScanned: result.filesScanned,
          findingsCount: result.findings.length,
        };
      },
      forget: async (id) => {
        await del.mutateAsync(id);
      },
      consolidate: async () => {
        const r = await cons.mutateAsync();
        return { consolidated: r.consolidated, decayed: r.decayed, deleted: r.deleted };
      },
      routes: NAV_ITEMS.map((n) => ({ label: n.label, href: n.href })),
    }),
    [router, setTheme, xray, del, cons],
  );
}
