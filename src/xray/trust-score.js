/**
 * Trust Score Calculator
 *
 * Computes a 0–100 trust score from X-Ray findings and maps it to a risk level.
 */
// ── Penalty weights ─────────────────────────────────────────
const SEVERITY_PENALTY = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 0,
};
// ── Risk level thresholds ───────────────────────────────────
function riskLevelFromScore(score) {
    if (score >= 80)
        return 'SAFE';
    if (score >= 60)
        return 'LOW';
    if (score >= 40)
        return 'MEDIUM';
    if (score >= 20)
        return 'HIGH';
    return 'CRITICAL';
}
// ── Public API ──────────────────────────────────────────────
export function calculateTrustScore(findings) {
    let score = 100;
    for (const finding of findings) {
        score -= SEVERITY_PENALTY[finding.severity];
    }
    score = Math.max(0, score);
    return {
        score,
        riskLevel: riskLevelFromScore(score),
    };
}
