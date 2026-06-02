export function syncInterceptEvent(event, config) {
    if (!config.cloudEnabled || !config.cloudApiKey)
        return;
    const url = `${config.cloudBaseUrl}/v1/audit/ingest`;
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${config.cloudApiKey}`,
        },
        body: JSON.stringify({
            events: [{ ...event, source: 'openclaw-interceptor' }],
        }),
        signal: AbortSignal.timeout(5_000),
    }).catch(() => {
        // Fire-and-forget — never block on cloud sync failure
    });
}
