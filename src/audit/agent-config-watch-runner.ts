/**
 * Detached entry point for the agent configuration watch (#916). Spawned
 * (unref'd, stdio ignored) by scripts/session-start-hook.mjs so session start
 * never waits on it. Exits 0 on every path.
 */

import fs from 'fs';
import path from 'path';
import {
  agentConfigWatchEnabled,
  agentConfigWatchHome,
  resolveProjectRoots,
  runAgentConfigWatch,
  type AgentConfigLedgerRow,
  type AgentConfigNotification,
} from './agent-config-watch.js';
import type { NotifyChannel } from '../defence/iron-dome/operator-notify.js';

export function makeAgentConfigLedger(log: (entry: Parameters<typeof import('../defence/audit/logger.js').logAudit>[0]) => number): (row: AgentConfigLedgerRow) => boolean {
  return (row) => {
    try {
      log({
        memory_id: null,
        project: null,
        timestamp: new Date().toISOString(),
        source_type: 'agent-config',
        source_identifier: row.file,
        trust_score: row.outcome === 'error' ? 1 : row.severity === 'high' ? 0.1 : 0.4,
        sensitivity_level: 'internal',
        firewall_result: 'ALLOW',
        operation: 'review',
        anomaly_score: row.outcome === 'error' ? 0 : row.severity === 'high' ? 0.9 : 0.6,
        threat_indicators: JSON.stringify(row.outcome === 'error' ? [] : row.severity === 'high' ? ['agent_config_change', 'agent_config_high_severity'] : ['agent_config_change']),
        blocked_patterns: '[]',
        reason: `agent config watch (${row.kind}${row.severity === 'high' ? ', high severity' : ''}): file=${row.file} key=${row.keyPath || '-'} ${row.detail}`.slice(0, 500),
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
      return true;
    } catch {
      return false;
    }
  };
}

/**
 * The session's project root arrives as `--project-root <abs path>` from the
 * session-start launcher (the hook payload cwd, which can differ from the
 * launcher's own process cwd). Relative or missing values are ignored.
 */
export function projectRootFromArgv(argv: readonly string[]): string | undefined {
  const i = argv.indexOf('--project-root');
  const v = i >= 0 ? argv[i + 1] : undefined;
  return typeof v === 'string' && path.isAbsolute(v) ? v : undefined;
}

/**
 * Whole-child deadline: the 5s check budget only covers the check body, so the
 * detached child also gets a hard stop covering imports, DB init and channel
 * setup. A hung child can never linger past this.
 */
export const CHILD_DEADLINE_MS = 20_000;
export function armChildDeadline(ms: number = CHILD_DEADLINE_MS, exit: () => void = () => process.exit(0)): NodeJS.Timeout {
  const t = setTimeout(exit, ms);
  t.unref?.();
  return t;
}

/**
 * `channels` replaces the configured notification channels (test seam for the
 * transport only); `projectRoot` / `home` replace the argv root and agentConfigWatchHome().
 */
export async function main(overrides: { channels?: NotifyChannel[]; projectRoot?: string; home?: string; argv?: readonly string[] } = {}): Promise<void> {
  const home = overrides.home ?? agentConfigWatchHome();
  let config: Record<string, unknown> = {};
  try { config = JSON.parse(fs.readFileSync(path.join(home, '.shieldcortex', 'config.json'), 'utf-8')); } catch { /* defaults */ }
  if (!agentConfigWatchEnabled(config)) return;

  const { initDatabase } = await import('../database/init.js');
  initDatabase();
  const { logAudit } = await import('../defence/audit/logger.js');
  const { deliverOperatorNotification, buildAgentConfigChangeNotification } = await import('../defence/iron-dome/operator-notify.js');
  const { configuredChannels } = await import('../cli/maintain.js');
  const { makeAutoCheckNotify } = await import('./mcp-tools-autocheck-runner.js');
  const channels = overrides.channels ?? await configuredChannels();
  const send = makeAutoCheckNotify(channels, deliverOperatorNotification);
  const root = overrides.projectRoot ?? projectRootFromArgv(overrides.argv ?? process.argv) ?? process.cwd();

  await runAgentConfigWatch({
    home,
    projectRoots: resolveProjectRoots(config, root),
    notify: (n: AgentConfigNotification) => send(buildAgentConfigChangeNotification(n)),
    ledger: makeAgentConfigLedger(logAudit),
  });
}

if (process.argv[1] && /agent-config-watch-runner\.js$/.test(process.argv[1])) {
  armChildDeadline();
  main().catch(() => undefined).finally(() => process.exit(0));
}
