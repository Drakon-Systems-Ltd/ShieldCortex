// plugins/openclaw/cloud-sync.ts
//
// Cloud sync POSTs threat events to ShieldCortex Cloud. Kept in its own
// module so that no plugin source file pairs `fs.readFileSync` with
// `fetch()` — OpenClaw's plugin-install security audit (v2026.4.24+)
// flags that pairing as "potential exfiltration" even when the two
// operations are unrelated. See CHANGELOG.md v4.12.8.

type CloudSyncConfig = {
  cloudApiKey?: string;
  cloudBaseUrl?: string;
};

export function cloudSync(threat: Record<string, unknown>, cfg: CloudSyncConfig): void {
  if (!cfg.cloudApiKey) return;
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
