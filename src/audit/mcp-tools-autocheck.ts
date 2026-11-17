/**
 * Automatic MCP tool-description check (#915).
 *
 * Runs the existing tool-description scan (mcp-tools-scanner.ts) once per
 * session start, in a detached background process, so a rug-pull or a poisoned
 * description is surfaced without anyone having to remember to run
 * `shieldcortex mcp scan`.
 *
 * Contract:
 *  - NEVER blocks or breaks the host: every failure (connect, timeout, store,
 *    notify, ledger) is swallowed; a failed server leaves one ledger row.
 *  - Quiet when nothing happened: an unchanged run notifies and records nothing.
 *  - The notification is plain and values-free (see buildMcpToolChangeNotification);
 *    the detail (field names, indicator categories) goes to the audit ledger only,
 *    and neither carries the raw description text.
 *  - Servers checked within `intervalHours` are skipped unless their launch
 *    config changed.
 */

import { createHash } from 'crypto';
import {
  fetchServerTools,
  scanToolList,
  type McpToolDescriptor,
  type ToolHashStore,
} from './mcp-tools-scanner.js';
import { scopeHashStore } from './mcp-tool-hash-store.js';
import type { DiscoveredMcpServer } from './mcp-config-scanner.js';
import { buildMcpToolChangeNotification, type McpToolChangeNotification } from '../defence/iron-dome/operator-notify.js';

export const DEFAULT_INTERVAL_HOURS = 6;
export const DEFAULT_SERVER_TIMEOUT_MS = 5_000;
export const DEFAULT_TOTAL_BUDGET_MS = 20_000;
/**
 * How long a delivery checkpoint is honoured (#926). Past this, an alert that is
 * still stuck behind a failing sibling is sent again rather than staying silent.
 */
export const DELIVERY_CHECKPOINT_TTL_MS = 7 * 24 * 3_600_000;

/**
 * One delivered alert member (#926): a single tool version, from one config
 * source, reported under one alert kind. The entry existing means the operator
 * notification that carried it was accepted by the transport. `recorded` is a
 * separate fact: whether the final findings row for it was durably written.
 */
export interface AutoCheckDeliveryCheckpoint {
  server: string;
  /** Config source the server came from; `null` when unknown (unscoped baseline). */
  source: string | null;
  deliveredAt: number;
  recorded: boolean;
}

export interface AutoCheckState {
  servers: Record<string, { checkedAt: number; configHash: string }>;
  /**
   * Alerts that could not be delivered, keyed by server + kind + finding hash.
   * Exists only to dedupe the durable `pending` ledger row across failed runs;
   * cleared for a server (and config source) once its alerts are delivered.
   * Markers written before #926 carry no `source` and are cleared server-wide.
   */
  pending?: Record<string, { server: string; source?: string | null }>;
  /**
   * Per-alert delivery checkpoints (#926), keyed by server + kind + a hash of
   * [source, tool, content hash]. Lets a retry skip what was already delivered
   * while a sibling alert is still failing. Dropped for a server (and source)
   * once all of its alerts are delivered and recorded.
   */
  checkpoints?: Record<string, AutoCheckDeliveryCheckpoint>;
}

/** Structured finding carried by `pending` rows so the finding survives an undeliverable alert. */
export interface AutoCheckFinding {
  alertKind: 'changed' | 'suspicious';
  source?: string;
  severity: string;
  tools: { tool: string; field?: string; indicators: string[] }[];
}

export interface AutoCheckLedgerRow {
  server: string;
  /** `pending` = finding detected but the alert could not be delivered; re-sent next run. */
  kind: 'changed' | 'suspicious' | 'error' | 'pending';
  /** Detail for the ledger: tool names, fields and indicator categories. Never raw description text. */
  detail: string;
  finding?: AutoCheckFinding;
}

export interface AutoCheckDeps {
  servers: (Pick<DiscoveredMcpServer, 'name' | 'command' | 'args' | 'env'> & { sourcePath?: string })[];
  store: ToolHashStore;
  fetchTools?: (server: AutoCheckDeps['servers'][number], timeoutMs: number) => Promise<McpToolDescriptor[]>;
  notify: (n: McpToolChangeNotification) => Promise<void> | void;
  /**
   * Record one ledger row. Returns `false` (or throws) when the durable findings
   * write failed; any other return means it was written. The runner commits a
   * dedupe marker / hash drift only AFTER a successful write.
   */
  ledger: (row: AutoCheckLedgerRow) => boolean | void;
  loadState: () => AutoCheckState;
  saveState: (s: AutoCheckState) => void;
  now?: () => number;
  intervalHours?: number;
  serverTimeoutMs?: number;
  totalBudgetMs?: number;
}

export interface AutoCheckResult {
  checked: number;
  skippedCached: number;
  notified: number;
  errors: number;
}

export function configHashOf(s: Pick<DiscoveredMcpServer, 'command' | 'args' | 'env'>): string {
  return createHash('sha256')
    .update(JSON.stringify([s.command, s.args, Object.entries(s.env ?? {}).sort()]))
    .digest('hex');
}

/** Coarse, fixed-vocabulary reason from scanner indicator prefixes. */
function reasonFromIndicators(indicators: string[]): string {
  const all = indicators.join(' ');
  const parts: string[] = [];
  if (all.includes('instruction:')) parts.push('instruction-like text');
  if (all.includes('skill:')) parts.push('risky command pattern');
  if (all.includes('encoding:')) parts.push('hidden or encoded content');
  return parts.join(' and ') || 'unusual content';
}

async function withDeadline<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error(`timed out after ${ms}ms`)), ms);
    timer.unref?.();
  });
  try { return await Promise.race([p, t]); } finally { if (timer) clearTimeout(timer); }
}

export async function runAutoToolCheck(deps: AutoCheckDeps): Promise<AutoCheckResult> {
  const now = deps.now ?? Date.now;
  const started = now();
  const intervalMs = (deps.intervalHours ?? DEFAULT_INTERVAL_HOURS) * 3_600_000;
  const serverTimeout = deps.serverTimeoutMs ?? DEFAULT_SERVER_TIMEOUT_MS;
  const budget = deps.totalBudgetMs ?? DEFAULT_TOTAL_BUDGET_MS;
  const fetchTools = deps.fetchTools ?? ((s, ms) => fetchServerTools(s, ms));
  const result: AutoCheckResult = { checked: 0, skippedCached: 0, notified: 0, errors: 0 };

  let state: AutoCheckState = { servers: {} };
  try { state = deps.loadState(); } catch { /* fresh state */ }
  if (!state || typeof state.servers !== 'object') state = { servers: {} };

  // A ledger failure never escapes the check, but it is OBSERVABLE: false = not
  // recorded. Callers must not commit a marker or advance hashes on false.
  const safeLedger = (row: AutoCheckLedgerRow): boolean => {
    try { return deps.ledger(row) !== false; } catch { return false; }
  };

  for (const server of deps.servers) {
    const remaining = budget - (now() - started);
    const cfgHash = configHashOf(server);
    const prior = state.servers[server.name];
    if (prior && prior.configHash === cfgHash && now() - prior.checkedAt >= 0 && now() - prior.checkedAt < intervalMs) {
      result.skippedCached++;
      continue;
    }
    try {
      if (remaining <= 0) throw new Error('total time budget exhausted');
      const tools = await withDeadline(fetchTools(server, Math.min(serverTimeout, remaining)), Math.min(serverTimeout, remaining) + 250);
      result.checked++;
      // Buffer hash writes: drift is only persisted once every notification for
      // this server was delivered, so a failed delivery is retried next run.
      // Per-source baseline (#925); a server without a known source stays unscoped.
      const baseline = server.sourcePath === undefined ? deps.store : scopeHashStore(deps.store, server.sourcePath);
      const pending = new Map<string, { server: string; tool: string; hash: string; changed: boolean }>();
      const bufferedStore: ToolHashStore = {
        get: (s, t) => pending.get(`${s}\u0000${t}`)?.hash ?? baseline.get(s, t),
        set: (s, t, h, c) => { pending.set(`${s}\u0000${t}`, { server: s, tool: t, hash: h, changed: c }); },
      };
      const { findings, drift } = scanToolList(server.name, tools, bufferedStore);

      const changed = new Set(drift.filter((d) => d.status === 'changed').map((d) => d.tool));
      const fresh = new Set(drift.filter((d) => d.status === 'new').map((d) => d.tool));
      // A suspicious tool is reported when it is new or changed; an unchanged
      // suspicious tool was already reported when it first appeared.
      const suspiciousByTool = new Map<string, string[]>();
      const suspiciousIndicators = new Map<string, string[]>();
      for (const f of findings) {
        // Structured fields only: never parse the display title (#925).
        if (f.toolName === undefined || f.field === undefined) continue;
        const tool = f.toolName;
        if (!changed.has(tool) && !fresh.has(tool)) continue;
        const list = suspiciousByTool.get(tool) ?? [];
        list.push(`${f.field} [${(f.indicators ?? ['flagged']).join(', ')}]`);
        suspiciousByTool.set(tool, list);
        const inds = suspiciousIndicators.get(tool) ?? [];
        inds.push(...(f.indicators ?? []));
        suspiciousIndicators.set(tool, inds);
      }
      const changedOnly = [...changed].filter((t) => !suspiciousByTool.has(t));

      const SEV = ['info', 'low', 'medium', 'high', 'critical'];
      const sevOf = (tool: string): string => findings
        .filter((f) => f.toolName === tool)
        .map((f) => f.severity as string)
        .reduce((m, v) => (SEV.indexOf(v) > SEV.indexOf(m) ? v : m), 'medium');
      const maxSev = (tools: string[]): string => tools.map(sevOf).reduce((m, v) => (SEV.indexOf(v) > SEV.indexOf(m) ? v : m), 'medium');

      interface Alert { kind: 'suspicious' | 'changed'; tools: string[]; notification: McpToolChangeNotification; detail: string; finding: AutoCheckFinding }
      const buildAlert = (kind: Alert['kind'], names: string[]): Alert => {
        if (kind === 'suspicious') {
          const members = new Set(names);
          return {
            kind, tools: names,
            notification: buildMcpToolChangeNotification({
              kind: 'suspicious', server: server.name, tools: names,
              reason: reasonFromIndicators(names.flatMap((t) => suspiciousIndicators.get(t) ?? [])),
            }),
            detail: names.map((t) => `${t}: ${(suspiciousByTool.get(t) ?? []).join(', ')}`).join('; '),
            finding: {
              alertKind: 'suspicious', source: server.sourcePath, severity: maxSev(names),
              tools: findings
                .filter((f) => f.toolName !== undefined && f.field !== undefined && members.has(f.toolName))
                .map((f) => ({ tool: f.toolName as string, field: f.field, indicators: f.indicators ?? ['flagged'] })),
            },
          };
        }
        return {
          kind, tools: names,
          notification: buildMcpToolChangeNotification({ kind: 'changed', server: server.name, tools: names }),
          detail: `tools=${names.join(',')}; hash changed since last check`,
          finding: {
            alertKind: 'changed', source: server.sourcePath, severity: maxSev(names),
            tools: names.map((t) => ({ tool: t, field: 'description', indicators: ['hash-changed'] })),
          },
        };
      };

      // ── Per-alert delivery checkpoints (#926) ──
      // One notification can carry several tools, and one server can produce two
      // notifications (suspicious, then changed-only). If the first is delivered
      // and the second fails, the retry rebuilds both from the old baseline. A
      // checkpoint per alert MEMBER stops the delivered one being sent and
      // recorded twice. Identity = server + kind + [source, tool, content hash]:
      // the scanner's per-tool hash, never the display text or the list order, so
      // a reordered list is the same alert and a tool that changes again is not.
      //
      // Three separate facts are kept, and none stands in for another:
      //   pending   - `state.pending`: an undelivered finding has its `pending` row
      //   delivered - a checkpoint exists: the transport accepted the notification
      //   recorded  - checkpoint.recorded: the final findings row was written
      // A delivered-but-unrecorded member is not re-sent, but its findings row is
      // still owed: the retry writes it, and hashes stay uncommitted until it lands.
      //
      // Limits (this is bounded dedupe for the ordinary partial retry, NOT
      // exactly-once delivery):
      //  - Crash windows. The transport has no idempotency key and the checkpoint
      //    is a JSON file, separate from the findings table. Dying after the
      //    transport accepted an alert but before the state file is saved re-sends
      //    it next run; dying after the findings INSERT but before the save writes
      //    a second findings row (no second notification). Same if the state file
      //    cannot be written at all. Every window errs towards a repeat, never
      //    towards a finding with no alert or no record.
      //  - Concurrency. Two checks that overlap (two sessions starting together)
      //    each load the state before the other saves, so both may send, and the
      //    last save wins. Nothing here locks the state file.
      //  - Time. A checkpoint is honoured for DELIVERY_CHECKPOINT_TTL_MS; an alert
      //    still stuck behind a failing sibling after that is repeated.
      const source = server.sourcePath ?? null;
      const hashOf = new Map(drift.map((d) => [d.tool, d.hash]));
      const cpKey = (kind: Alert['kind'], tool: string): string =>
        `${server.name}\u0000${kind}\u0000${createHash('sha256').update(JSON.stringify([source, tool, hashOf.get(tool) ?? null])).digest('hex')}`;
      const checkedNow = now();
      const live = (cp: AutoCheckDeliveryCheckpoint | undefined): cp is AutoCheckDeliveryCheckpoint =>
        !!cp && typeof cp.deliveredAt === 'number' && cp.deliveredAt <= checkedNow && checkedNow - cp.deliveredAt < DELIVERY_CHECKPOINT_TTL_MS;
      const mine = (cp: AutoCheckDeliveryCheckpoint | undefined): boolean => !!cp && cp.server === server.name && (cp.source ?? null) === source;
      const groups: [Alert['kind'], string[]][] = [['suspicious', [...suspiciousByTool.keys()]], ['changed', changedOnly]];
      if (state.checkpoints === null || typeof state.checkpoints !== 'object') delete state.checkpoints;
      if (state.checkpoints) {
        // Keep only checkpoints for tool versions still waiting on this baseline:
        // an expired one, or one for content that has since moved on, is dropped
        // so it cannot suppress a later recurrence.
        const current = new Set(groups.flatMap(([kind, names]) => names.map((t) => cpKey(kind, t))));
        for (const [k, v] of Object.entries(state.checkpoints)) {
          if (mine(v) && (!current.has(k) || !live(v))) delete state.checkpoints[k];
        }
      }
      const phaseOf = (kind: Alert['kind'], tool: string): 'undelivered' | 'unrecorded' | 'recorded' => {
        const cp = state.checkpoints?.[cpKey(kind, tool)];
        if (!live(cp) || !mine(cp)) return 'undelivered';
        return cp.recorded === true ? 'recorded' : 'unrecorded';
      };
      const toSend: Alert[] = [];
      const toRecord: Alert[] = []; // delivered on an earlier run, findings row still owed
      for (const [kind, names] of groups) {
        const undelivered = names.filter((t) => phaseOf(kind, t) === 'undelivered');
        const unrecorded = names.filter((t) => phaseOf(kind, t) === 'unrecorded');
        if (undelivered.length > 0) toSend.push(buildAlert(kind, undelivered));
        if (unrecorded.length > 0) toRecord.push(buildAlert(kind, unrecorded));
      }
      // Saved straight away, not at the end of the run, to keep the crash window small.
      const checkpoint = (al: Alert, recorded: boolean): void => {
        const cps = (state.checkpoints = state.checkpoints ?? {});
        for (const t of al.tools) {
          const k = cpKey(al.kind, t);
          cps[k] = { server: server.name, source, deliveredAt: live(cps[k]) ? cps[k].deliveredAt : checkedNow, recorded };
        }
        try { deps.saveState(state); } catch { /* fail open: an unsaved checkpoint means a repeat, not a miss */ }
      };
      let recordOwed = false;
      const record = (al: Alert): void => {
        if (safeLedger({ server: server.name, kind: al.kind, detail: al.detail, finding: al.finding })) checkpoint(al, true);
        else recordOwed = true;
      };

      for (const al of toRecord) record(al);

      // Alerts are delivered in order. If one fails, the finding must not be lost
      // just because notification is unavailable: record every undelivered alert
      // as a deduped `pending` row (full finding), then fail the server so hashes
      // stay uncommitted and the undelivered alerts are re-sent next run.
      for (let i = 0; i < toSend.length; i++) {
        const al = toSend[i];
        try {
          await Promise.resolve(deps.notify(al.notification));
        } catch (err) {
          state.pending = state.pending ?? {};
          for (const un of toSend.slice(i)) {
            const key = `${server.name}\u0000${un.kind}\u0000${createHash('sha256').update(JSON.stringify([server.sourcePath ?? null, un.detail])).digest('hex')}`;
            if (state.pending[key]) continue;
            // Dedupe marker only AFTER the full finding is durably written: if the
            // INSERT failed, the next run must try to record it again.
            const written = safeLedger({
              server: server.name, kind: 'pending',
              detail: `undelivered ${un.kind} alert (source=${server.sourcePath ?? 'unknown'}, severity=${un.finding.severity}): ${un.detail}`,
              finding: un.finding,
            });
            if (written) state.pending[key] = { server: server.name, source };
          }
          throw err;
        }
        result.notified++;
        // Delivered first, recorded second: the final row is written only after a
        // successful delivery, and a failed write leaves the checkpoint at
        // "delivered, not recorded" so the retry writes the row without re-sending.
        checkpoint(al, false);
        record(al);
      }
      // A findings row is still owed: do not commit hashes/state, retry the write next run.
      if (recordOwed) throw new Error('findings ledger write failed after delivery');

      if (state.pending) {
        for (const [k, v] of Object.entries(state.pending)) {
          if (v.server === server.name && (v.source === undefined || v.source === source)) delete state.pending[k];
        }
      }
      // Complete: the baseline advances below, so these versions will read as
      // unchanged. Dropping the checkpoints means a later recurrence alerts again.
      if (state.checkpoints) {
        for (const [k, v] of Object.entries(state.checkpoints)) if (mine(v)) delete state.checkpoints[k];
      }
      // Delivery succeeded (or nothing needed delivering): now persist drift + state.
      for (const p of pending.values()) baseline.set(p.server, p.tool, p.hash, p.changed);
      state.servers[server.name] = { checkedAt: now(), configHash: cfgHash };
    } catch (err) {
      result.errors++;
      try {
        deps.ledger({ server: server.name, kind: 'error', detail: `tool check or alert delivery did not complete (will retry): ${err instanceof Error ? err.message : String(err)}`.slice(0, 200) });
      } catch { /* fail open */ }
    }
  }

  if (state.checkpoints && Object.keys(state.checkpoints).length === 0) delete state.checkpoints;
  try { deps.saveState(state); } catch { /* fail open */ }
  return result;
}
