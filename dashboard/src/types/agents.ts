export interface AgentInfo {
  source_type: string;
  source_identifier: string;
  operation_count: number;
  last_seen: string;
  avg_trust_score: number;
  min_trust_score: number;
  max_trust_score: number;
  flagged_count: number;
}

export interface AgentTimelinePoint {
  timestamp: string;
  trust_score: number;
  firewall_result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  anomaly_score: number;
}

export type TrustTier = 'full' | 'limited' | 'restricted';

export function getTrustTier(score: number): TrustTier {
  if (score >= 0.7) return 'full';
  if (score >= 0.5) return 'limited';
  return 'restricted';
}

export const trustTierColors = {
  full: 'text-green-400',
  limited: 'text-yellow-400',
  restricted: 'text-red-400',
} as const;

export const trustTierBg = {
  full: 'bg-green-500/10',
  limited: 'bg-yellow-500/10',
  restricted: 'bg-red-500/10',
} as const;

export const trustTierLabels = {
  full: 'Full Access',
  limited: 'Limited',
  restricted: 'Restricted',
} as const;
