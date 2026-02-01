/**
 * Recall filter — filters recall results by trust score and sensitivity.
 */

export function filterByTrust<
  T extends {
    trust_score?: number;
    sensitivity_level?: string;
    content?: string;
    metadata?: Record<string, unknown>;
  },
>(results: T[], minTrust: number, context?: string): T[] {
  return results
    .filter((item) => {
      const score = item.trust_score ?? 0;

      // Never return quarantined items
      if (score === 0) return false;

      // Filter below minimum trust
      if (score < minTrust) return false;

      // CONFIDENTIAL: only include if context matches
      if (item.sensitivity_level === 'CONFIDENTIAL') {
        if (!context || item.metadata?.context !== context) return false;
      }

      return true;
    })
    .map((item) => {
      const score = item.trust_score ?? 0;
      let result = item;

      // RESTRICTED: redact content
      if (item.sensitivity_level === 'RESTRICTED') {
        result = { ...result, content: '[REDACTED - RESTRICTED]' };
      }

      // Low trust: mark as unverified
      if (score < 0.5) {
        result = {
          ...result,
          metadata: { ...result.metadata, unverified: true },
        };
      }

      return result;
    });
}
