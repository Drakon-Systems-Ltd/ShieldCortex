'use client';

import { useMutation } from '@tanstack/react-query';
import { gatedFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export function useAuditExport() {
  return useMutation({
    mutationFn: async ({ format, startTime, endTime }: { format: 'json' | 'csv'; startTime?: string; endTime?: string }) => {
      const params = new URLSearchParams({ format });
      if (startTime) params.set('startTime', startTime);
      if (endTime) params.set('endTime', endTime);

      const response = await gatedFetch(`${API_BASE}/api/audit/export?${params}`);
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || 'Export failed');
      }

      // Trigger file download
      const blob = await response.blob();
      const ext = format === 'csv' ? 'csv' : 'json';
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `shieldcortex-audit-${Date.now()}.${ext}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      return { success: true };
    },
  });
}
