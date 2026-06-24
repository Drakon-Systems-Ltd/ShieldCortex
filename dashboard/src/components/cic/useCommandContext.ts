'use client';

import { useMemo } from 'react';
import { useRouter } from 'next/navigation';
import { authFetch, readApiError } from '@/lib/auth';
import { useTheme } from '@/hooks/useTheme';
import { useXRayScan } from '@/hooks/useXRay';
import { useDeleteMemory, useConsolidate } from '@/hooks/useMemories';
import { useApproveQuarantine, useRejectQuarantine } from '@/hooks/useDefence';
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
  const approveQ = useApproveQuarantine();
  const rejectQ = useRejectQuarantine();

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
      quarantineList: async () => {
        const res = await authFetch(`${API_BASE}/api/v1/quarantine?status=pending&limit=20`);
        if (!res.ok) throw new Error(await readApiError(res, 'quarantine list failed'));
        const data = (await res.json()) as { items?: { id: number; original_title?: string; title?: string }[] };
        return (data.items ?? []).map((i) => ({ id: i.id, title: i.original_title ?? i.title ?? `item ${i.id}` }));
      },
      quarantineReview: async (id, action) => {
        if (action === 'approve') await approveQ.mutateAsync(id);
        else await rejectQ.mutateAsync({ id });
      },
      ironDome: async (action) => {
        if (action === 'status') {
          const res = await authFetch(`${API_BASE}/api/iron-dome/status`);
          if (!res.ok) throw new Error(await readApiError(res, 'iron dome status failed'));
          const data = (await res.json()) as { enabled?: boolean };
          return `iron dome: ${data.enabled ? 'ACTIVE' : 'inactive'}`;
        }
        const path = action === 'on' ? 'activate' : 'deactivate';
        const res = await authFetch(`${API_BASE}/api/iron-dome/${path}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: '{}',
        });
        if (!res.ok) throw new Error(await readApiError(res, `iron dome ${action} failed`));
        return `▸ iron dome ${action === 'on' ? 'ACTIVE' : 'disabled'}`;
      },
      remember: async (text) => {
        const res = await authFetch(`${API_BASE}/api/memories`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ title: text.slice(0, 80), content: text }),
        });
        if (!res.ok) throw new Error(await readApiError(res, 'remember failed'));
        const data = (await res.json()) as { id?: number };
        return { id: data.id ?? 0 };
      },
      routes: NAV_ITEMS.map((n) => ({ label: n.label, href: n.href })),
    }),
    [router, setTheme, xray, del, cons, approveQ, rejectQ],
  );
}
