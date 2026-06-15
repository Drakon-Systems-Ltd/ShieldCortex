'use client';

import { useCallback } from 'react';
import { toast } from 'sonner';
import { useWebSocketEvent } from '@/components/MemoryWebSocketProvider';

interface DefenceEventData {
  source_type?: string;
  source_identifier?: string;
  firewall_result?: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  trust_score?: number;
  reason?: string | null;
  threat_indicators?: string[] | string | null;
  timestamp?: string;
}

const SUPPRESSION_WINDOW_MS = 2000;
const recentKeys = new Map<string, number>();

function shouldSuppress(key: string): boolean {
  const now = Date.now();
  const last = recentKeys.get(key);
  if (last && now - last < SUPPRESSION_WINDOW_MS) return true;
  recentKeys.set(key, now);
  if (recentKeys.size > 50) {
    const cutoff = now - SUPPRESSION_WINDOW_MS;
    for (const [k, t] of recentKeys) if (t < cutoff) recentKeys.delete(k);
  }
  return false;
}

function normaliseIndicators(indicators: DefenceEventData['threat_indicators']): string[] {
  if (Array.isArray(indicators)) return indicators.filter((item): item is string => typeof item === 'string');
  if (typeof indicators !== 'string' || !indicators.trim()) return [];

  try {
    const parsed = JSON.parse(indicators) as unknown;
    if (Array.isArray(parsed)) return parsed.filter((item): item is string => typeof item === 'string');
  } catch {
    return [indicators];
  }

  return [];
}

function summariseIndicators(indicators: DefenceEventData['threat_indicators']): string {
  const normalised = normaliseIndicators(indicators);
  if (!normalised.length) return '';
  return normalised
    .slice(0, 3)
    .map((i) => i.replace(/_/g, ' '))
    .join(', ');
}

export function BlockToastBridge() {
  const handleMessage = useCallback((event: { type: string; data?: unknown }) => {
    if (event.type !== 'defence_event') return;
    const data = event.data as DefenceEventData | undefined;
    if (!data || data.firewall_result === 'ALLOW') return;

    const isBlock = data.firewall_result === 'BLOCK';
    const source = data.source_identifier || data.source_type || 'unknown source';
    const indicators = summariseIndicators(data.threat_indicators);
    const reason = data.reason?.trim() || (indicators ? `Threats: ${indicators}` : 'See audit log for details');

    const key = `${data.firewall_result}:${source}:${(data.reason || '').slice(0, 80)}`;
    if (shouldSuppress(key)) return;

    const title = isBlock
      ? `\u{1F6E1} Blocked attack from ${source}`
      : `\u{26A0}\u{FE0F} Quarantined input from ${source}`;

    const opts = {
      description: reason,
      duration: isBlock ? 8000 : 5000,
    } as const;

    if (isBlock) toast.error(title, opts);
    else toast.warning(title, opts);
  }, []);

  useWebSocketEvent(handleMessage);
  return null;
}
