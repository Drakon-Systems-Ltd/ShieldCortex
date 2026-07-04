/**
 * Feature gating — the central guard for licence-gated features.
 *
 * Under the Free + Enterprise model every LOCAL feature is Free. Only
 * genuinely cloud/org-side features stay gated (team-rank in TIER_RANK, so
 * Enterprise keys and grandfathered Team keys both unlock them).
 *
 * Usage:
 *   requireFeature('cloud_sync');     // throws FeatureGatedError if not licensed
 *   isFeatureEnabled('cloud_sync');   // returns boolean (soft check)
 */

import { getLicenseTier } from './store.js';
import { TIER_RANK, type LicenseTier } from './keys.js';

// ── Gated features ───────────────────────────────────────

export type GatedFeature =
  | 'custom_injection_patterns'
  | 'custom_iron_dome_policies'
  | 'custom_firewall_rules'
  | 'audit_export'
  | 'skill_scanner_deep'
  | 'cloud_audit_sync'
  | 'cloud_sync'
  | 'team_management'
  | 'shared_patterns'
  | 'cortex_learning'
  | 'deps_quarantine'
  | 'deps_clean'
  | 'deps_auto_protect'
  | 'deps_global_scan'
  | 'memory_types'
  | 'memory_scopes'
  | 'dream_mode'
  | 'llm_reranking'
  | 'positive_feedback'
  | 'local_ai_explainer'
  | 'memory_file_scan'
  | 'review_copilot'
  | 'xray_deep';

// Every LOCAL feature is 'free' (D1 of the Free + Enterprise repricing).
// The four 'team'-rank entries are genuinely cloud/org-side — full memory/graph
// replication, team management, shared patterns, and team memory scopes — and
// are unlocked by Enterprise licences (and grandfathered Team keys).
const FEATURE_TIERS: Record<GatedFeature, LicenseTier> = {
  custom_injection_patterns: 'free',
  custom_iron_dome_policies: 'free',
  custom_firewall_rules: 'free',
  audit_export: 'free',
  skill_scanner_deep: 'free',
  cloud_audit_sync: 'free',
  cloud_sync: 'team',
  team_management: 'team',
  shared_patterns: 'team',
  cortex_learning: 'free',
  deps_quarantine: 'free',
  deps_clean: 'free',
  deps_auto_protect: 'free',
  deps_global_scan: 'free',
  memory_types: 'free',
  memory_scopes: 'team',
  dream_mode: 'free',
  llm_reranking: 'free',
  positive_feedback: 'free',
  local_ai_explainer: 'free',
  memory_file_scan: 'free',
  review_copilot: 'free',
  xray_deep: 'free',
};

const FEATURE_DESCRIPTIONS: Record<GatedFeature, string> = {
  custom_injection_patterns: 'Define up to 50 custom regex patterns for detecting domain-specific threats.',
  custom_iron_dome_policies: 'Create custom Iron Dome policies with tailored action gates and trust levels.',
  custom_firewall_rules: 'Add custom firewall rules to block or allow specific content patterns.',
  audit_export: 'Export your full audit trail as JSON or CSV for compliance reporting.',
  skill_scanner_deep: 'Deep skill scanning with multi-file analysis and semantic intent detection.',
  cloud_audit_sync: 'Sync audit metadata (no content) to ShieldCortex Cloud for centralised visibility — included on Free tier (500 scans/month, 7-day retention).',
  cloud_sync: 'Full bi-directional cloud sync — memories, knowledge graph, and quarantine content. Required for cross-device team workflows.',
  team_management: 'Manage team members, invites, and shared security policies.',
  shared_patterns: 'Share custom injection patterns and policies across your team.',
  cortex_learning: 'Systematic mistake learning with pre-flight checks, pattern detection, and rule graduation.',
  deps_quarantine: 'Quarantine malicious packages — move threats to a safe holding area.',
  deps_clean: 'Permanently remove known malicious packages from your project.',
  deps_auto_protect: 'Automated scan + quarantine of critical threats on every install.',
  deps_global_scan: 'Scan global npm installations for supply chain threats.',
  memory_types: 'Typed memories (user/feedback/project/reference) for structured knowledge.',
  memory_scopes: 'Private vs team memory scopes for multi-agent deployments.',
  dream_mode: 'Background memory consolidation — merge duplicates, archive stale, detect contradictions.',
  llm_reranking: 'LLM-powered memory reranking for precision recall.',
  positive_feedback: 'Capture what worked, not just what failed — learn from success.',
  local_ai_explainer: 'Local AI explanations for memories, X-Ray findings, and quarantine review without sending content to the cloud.',
  memory_file_scan: 'Scan persistent agent memory files for poisoned instructions and credential leaks.',
  review_copilot: 'Local AI quarantine review annotations, grouping, and batch triage.',
  xray_deep: 'Deep X-Ray scanning: npm registry analysis, binary file inspection, dependency graph risk, and AI-directive detection in metadata and filenames.',
};

// ── Error class ──────────────────────────────────────────

export class FeatureGatedError extends Error {
  constructor(
    public feature: GatedFeature,
    public requiredTier: LicenseTier,
  ) {
    const desc = FEATURE_DESCRIPTIONS[feature];
    // The only remaining gated features are cloud/org-side, and the only tier
    // sold is Enterprise — grandfathered Pro/Team keys keep working via
    // TIER_RANK, but the message never advertises a purchasable self-serve tier.
    super(
      `This feature requires an Enterprise licence.\n\n` +
      `${desc}\n\n` +
      `  Contact:  sales@drakonsystems.com\n` +
      `  Activate: shieldcortex license activate <key>`,
    );
    this.name = 'FeatureGatedError';
  }
}

// ── Guards ────────────────────────────────────────────────

/**
 * Check if a feature is enabled under the current licence tier.
 * Use for soft checks (e.g. hiding UI elements, silent returns).
 */
export function isFeatureEnabled(feature: GatedFeature): boolean {
  const requiredTier = FEATURE_TIERS[feature];
  const currentTier = getLicenseTier();
  return TIER_RANK[currentTier] >= TIER_RANK[requiredTier];
}

/**
 * Require a feature — throws FeatureGatedError if the current licence
 * doesn't include it. Use at the entry point of gated features.
 */
export function requireFeature(feature: GatedFeature): void {
  if (!isFeatureEnabled(feature)) {
    throw new FeatureGatedError(feature, FEATURE_TIERS[feature]);
  }
}

/**
 * Get the minimum tier required for a feature.
 */
export function getRequiredTier(feature: GatedFeature): LicenseTier {
  return FEATURE_TIERS[feature];
}

/**
 * List all features with their required tier and current availability.
 */
export function listFeatures(): Array<{
  feature: GatedFeature;
  requiredTier: LicenseTier;
  enabled: boolean;
  description: string;
}> {
  const currentTier = getLicenseTier();
  const currentRank = TIER_RANK[currentTier];

  return (Object.keys(FEATURE_TIERS) as GatedFeature[]).map((feature) => ({
    feature,
    requiredTier: FEATURE_TIERS[feature],
    enabled: currentRank >= TIER_RANK[FEATURE_TIERS[feature]],
    description: FEATURE_DESCRIPTIONS[feature],
  }));
}
