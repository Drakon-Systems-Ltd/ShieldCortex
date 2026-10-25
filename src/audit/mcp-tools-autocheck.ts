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
import type { DiscoveredMcpServer } from './mcp-config-scanner.js';
import { buildMcpToolChangeNotification, type McpToolChangeNotification } from '../defence/iron-dome/operator-notify.js';

export const DEFAULT_INTERVAL_HOURS = 6;
export const DEFAULT_SERVER_TIMEOUT_MS = 5_000;
export const DEFAULT_TOTAL_BUDGET_MS = 20_000;

export interface AutoCheckState {
  servers: Record<string, { checkedAt: number; configHash: string }>;
}

export interface AutoCheckLedgerRow {
  server: string;
  kind: 'changed' | 'suspicious' | 'error';
  /** Detail for the ledger: tool names, fields and indicator categories. Never raw description text. */
  detail: string;
}

export interface AutoCheckDeps {
  servers: Pick<DiscoveredMcpServer, 'name' | 'command' | 'args' | 'env'>[];
  store: ToolHashStore;
  fetchTools?: (server: AutoCheckDeps['servers'][number], timeoutMs: number) => Promise<McpToolDescriptor[]>;
  notify: (n: McpToolChangeNotification) => Promise<void> | void;
  ledger: (row: AutoCheckLedgerRow) => void;
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
function reasonFromIndicators(descriptions: string[]): string {
  const all = descriptions.join(' ');
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
      const { findings, drift } = scanToolList(server.name, tools, deps.store);

      const changed = new Set(drift.filter((d) => d.status === 'changed').map((d) => d.tool));
      const fresh = new Set(drift.filter((d) => d.status === 'new').map((d) => d.tool));
      // A suspicious tool is reported when it is new or changed; an unchanged
      // suspicious tool was already reported when it first appeared.
      const suspiciousByTool = new Map<string, string[]>();
      for (const f of findings) {
        const m = /^Suspicious content in MCP tool "(.*)" \((.*)\)$/.exec(f.title);
        if (!m) continue;
        const [, tool, field] = m;
        if (!changed.has(tool) && !fresh.has(tool)) continue;
        const list = suspiciousByTool.get(tool) ?? [];
        const ind = /containing (.+?)\. Tool descriptions/.exec(f.description)?.[1] ?? 'flagged';
        list.push(`${field} [${ind}]`);
        suspiciousByTool.set(tool, list);
      }
      const changedOnly = [...changed].filter((t) => !suspiciousByTool.has(t));

      if (suspiciousByTool.size > 0) {
        const toolNames = [...suspiciousByTool.keys()];
        const notification = buildMcpToolChangeNotification({
          kind: 'suspicious', server: server.name, tools: toolNames,
          reason: reasonFromIndicators([...suspiciousByTool.values()].flat()),
        });
        deps.ledger({ server: server.name, kind: 'suspicious', detail: [...suspiciousByTool.entries()].map(([t, d]) => `${t}: ${d.join(', ')}`).join('; ') });
        await Promise.resolve(deps.notify(notification)).catch(() => undefined);
        result.notified++;
      }
      if (changedOnly.length > 0) {
        const notification = buildMcpToolChangeNotification({ kind: 'changed', server: server.name, tools: changedOnly });
        deps.ledger({ server: server.name, kind: 'changed', detail: `tools=${changedOnly.join(',')}; hash changed since last check` });
        await Promise.resolve(deps.notify(notification)).catch(() => undefined);
        result.notified++;
      }
      state.servers[server.name] = { checkedAt: now(), configHash: cfgHash };
    } catch (err) {
      result.errors++;
      try {
        deps.ledger({ server: server.name, kind: 'error', detail: `tool check did not complete: ${err instanceof Error ? err.message : String(err)}`.slice(0, 200) });
      } catch { /* fail open */ }
    }
  }

  try { deps.saveState(state); } catch { /* fail open */ }
  return result;
}
