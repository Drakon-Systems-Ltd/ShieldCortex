// plugins/openclaw/cloud-sync.ts
//
// Network egress for SC realtime input-scan threat events. See CHANGELOG.md
// v4.12.8 / v4.12.9. Posts canonical audit entries to /v1/audit/ingest — the
// only ingest route the SaaS exposes (the old /v1/threats route never existed
// server-side, so these events were silently 404'd and dropped).

import { toAuditEntry } from './audit-entry.js';

type CloudSyncConfig = {
  cloudEnabled?: boolean;
  cloudApiKey?: string;
  cloudBaseUrl?: string;
};

export function cloudSync(threat: Record<string, unknown>, cfg: CloudSyncConfig): void {
  // Consent gate: require cloud explicitly enabled AND an API key — matching every
  // other egress sender (intercept-ingest.ts, src/cloud/*). Previously this checked
  // the key alone, so events could leave the machine with a key present even when
  // cloud sync was "off" (ClawScan finding: external scanning without a local-only
  // default).
  if (!cfg.cloudEnabled || !cfg.cloudApiKey) return;
  // Privacy: never transmit raw LLM input. We build a fresh canonical entry from
  // named METADATA fields only — content/preview are never read or copied, so they
  // cannot leak even though the caller's `threat` object carries them (ClawScan
  // finding: previews may contain credentials or confidential data). The explicit
  // field-passing below IS the privacy boundary. The local audit log keeps fuller
  // detail for triage.
  const entry = toAuditEntry({
    kind: 'realtime',
    hook: typeof threat.hook === 'string' ? threat.hook : undefined,
    sessionId: typeof threat.sessionId === 'string' ? threat.sessionId : undefined,
    model: typeof threat.model === 'string' ? threat.model : undefined,
    reason: typeof threat.reason === 'string' ? threat.reason : undefined,
    ts: typeof threat.ts === 'string' ? threat.ts : undefined,
  });
  if (!entry) return;
  const url = `${cfg.cloudBaseUrl || 'https://api.shieldcortex.ai'}/v1/audit/ingest`;
  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${cfg.cloudApiKey}`,
    },
    body: JSON.stringify({ entries: [entry] }),
    signal: AbortSignal.timeout(5000),
  }).catch(() => {
    // Fire-and-forget — never block on cloud sync failure
  });
}
