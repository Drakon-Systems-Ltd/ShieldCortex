// plugins/openclaw/cloud-sync.ts
//
// Network egress for SC threat events. See CHANGELOG.md v4.12.8 / v4.12.9.
export function cloudSync(threat, cfg) {
    if (!cfg.cloudApiKey)
        return;
    const url = `${cfg.cloudBaseUrl || 'https://api.shieldcortex.ai'}/v1/threats`;
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${cfg.cloudApiKey}`,
        },
        body: JSON.stringify(threat),
        signal: AbortSignal.timeout(5000),
    }).catch(() => {
        // Fire-and-forget — never block on cloud sync failure
    });
}
