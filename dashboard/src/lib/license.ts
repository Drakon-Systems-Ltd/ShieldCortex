import type { LicenseTier } from '@/hooks/useLicense';

/** Dashboard-side feature keys (mirrors GatedFeature from gate.ts) */
export type GatedFeature =
  | 'custom_injection_patterns'
  | 'custom_iron_dome_policies'
  | 'custom_firewall_rules'
  | 'audit_export'
  | 'skill_scanner_deep'
  | 'cloud_sync'
  | 'team_management'
  | 'shared_patterns';

export const TIER_LABELS: Record<LicenseTier, string> = {
  free: 'Free',
  pro: 'Pro',
  team: 'Team',
  enterprise: 'Enterprise',
};

export const TIER_COLOURS: Record<LicenseTier, string> = {
  free: 'text-[var(--sc-text-muted)]',
  pro: 'text-[var(--sc-cyan)]',
  team: 'text-[var(--sc-coral)]',
  enterprise: 'text-[var(--sc-amber)]',
};

export const TIER_BG: Record<LicenseTier, string> = {
  free: 'bg-[var(--sc-surface-interactive)]',
  pro: 'bg-[var(--sc-cyan)]/10',
  team: 'bg-[var(--sc-coral)]/10',
  enterprise: 'bg-[var(--sc-amber)]/10',
};

export const PLAN_PRICING: Record<'pro' | 'team', { label: string; price: string }> = {
  pro: { label: 'Pro', price: '£29/mo' },
  team: { label: 'Team', price: '£99/mo' },
};
