// plugins/openclaw/cloud-sync.ts
//
// Network egress for SC threat events. See CHANGELOG.md v4.12.8 / v4.12.9.
export function cloudSync(threat, cfg) {
    // Consent gate: require cloud explicitly enabled AND an API key — matching every
    // other egress sender (intercept-ingest.ts, src/cloud/*). Previously this checked
    // the key alone, so events could leave the machine with a key present even when
    // cloud sync was "off" (ClawScan finding: external scanning without a local-only
    // default).
    if (!cfg.cloudEnabled || !cfg.cloudApiKey)
        return;
    // Privacy: never transmit raw LLM input. Strip any input content/preview snippet —
    // forward threat METADATA only (ClawScan finding: previews may contain credentials
    // or confidential data). The local audit log keeps fuller detail for triage.
    const metadata = { ...threat };
    delete metadata.content;
    delete metadata.preview;
    const url = `${cfg.cloudBaseUrl || 'https://api.shieldcortex.ai'}/v1/threats`;
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${cfg.cloudApiKey}`,
        },
        body: JSON.stringify(metadata),
        signal: AbortSignal.timeout(5000),
    }).catch(() => {
        // Fire-and-forget — never block on cloud sync failure
    });
}
