import {
  getCloudConfig,
  setCloudConfig,
  getCloudSyncControls,
  setCloudSyncControls,
  getDefenceMode,
  setDefenceMode,
  getVerifyConfig,
  setVerifyConfig,
  getReviewCopilotConfig,
  getOpenClawAutoMemory,
  setOpenClawAutoMemory,
  isProactiveRecallEnabled,
  setProactiveRecall,
  setSelfHeal,
  restore410Defaults,
  getRankerConfig,
  setRankerConfig,
  getToolResponseScanConfig,
  setToolResponseScanConfig,
  isRevokeBySourceEnabled,
  setRevokeBySourceEnabled,
  getActionGuardNotifyConfig,
  setActionGuardNotifyConfig,
  getActionGuardCoreConfig,
  setActionGuardCoreConfig,
  setMemoryInjectContract,
  setMemoryPlane,
  setAutoMemorySamplingTurns,
  NATIVE_INJECT_CONTRACTS,
  MEMORY_PLANE_VALUES,
  type DefenceMode,
} from './config.js';
import type { RankerEngine } from '../memory/types.js';

const VALID_RANKER_ENGINES: RankerEngine[] = ['rrf', 'legacy'];
import { syncAllGraphToCloud } from './graph-sync.js';
import { syncAllMemoriesToCloud } from './memory-sync.js';
import { isFeatureEnabled } from '../license/gate.js';
import { initDatabase } from '../database/init.js';
import { reconcileSyncQueue } from './sync-queue.js';
import { setUpsellState } from '../cli/upsell-state.js';

const VALID_MODES: DefenceMode[] = ['strict', 'balanced', 'permissive'];
const VALID_VERIFY_MODES = ['advisory', 'enforce'] as const;

export function handleCloudConfig(args: string[]): void {
  if (args.includes('--cloud-status')) {
    const config = getCloudConfig();
    const mode = getDefenceMode();
    const verify = getVerifyConfig();
    const reviewCopilot = getReviewCopilotConfig();
    const openclawAutoMemory = getOpenClawAutoMemory();
    const ranker = getRankerConfig();
    const syncControls = getCloudSyncControls();
    const toolFirewall = getToolResponseScanConfig();
    const rankerOverridden = !!process.env.SHIELDCORTEX_RANKER;
    console.log('\nShieldCortex Configuration:');
    const agNotify = getActionGuardNotifyConfig();
    const agNotifyChannels = [agNotify.openclaw ? 'openclaw' : null, agNotify.webhookUrl ? 'webhook' : null]
      .filter(Boolean)
      .join(' + ');
    const agCore = getActionGuardCoreConfig();
    const agStatus = !agCore.enabled ? 'Off' : agCore.enforce ? 'Enforce' : 'Advisory (warn-mode)';
    console.log(`  Defence Mode: ${mode}`);
    console.log(`  Tool-Output Firewall: ${toolFirewall.scanToolResponses ? toolFirewall.toolResponseMode : 'Off'}`);
    console.log(`  Action Guard: ${agStatus}`);
    console.log(`  Action Guard Notify: ${agNotify.enabled ? (agNotifyChannels || 'Enabled (no channel configured!)') : 'Off'}`);
    console.log(`  Revoke-by-source: ${isRevokeBySourceEnabled() ? 'Enabled (destructive)' : 'Disabled (default)'}`);
    console.log(`  Cloud Enabled:  ${config.cloudEnabled ? 'Yes' : 'No'}`);
    console.log(`  API Key:  ${config.cloudApiKey ? config.cloudApiKey.substring(0, 12) + '...' : 'Not set'}`);
    console.log(`  Base URL: ${config.cloudBaseUrl}`);
    console.log(`  Sensitive Memories: ${syncControls.excludeSensitive ? 'Excluded from sync (safe default)' : 'Included in sync'}`);
    console.log(`  LLM Verify:   ${verify.verifyEnabled ? 'Enabled' : 'Disabled'} (${verify.verifyMode}, ${verify.verifyTimeoutMs}ms timeout)`);
    console.log(`  Verify Triggers: ${verify.verifyTriggers.join(', ')}`);
    console.log(`  Local AI Explainer: ${reviewCopilot.enabled ? 'Enabled' : 'Disabled'} (${reviewCopilot.modelId})`);
    console.log(`  OpenClaw Auto-Memory: ${openclawAutoMemory ? 'Enabled' : 'Disabled'}`);
    console.log(`  Proactive Recall: ${isProactiveRecallEnabled() ? 'Enabled' : 'Disabled'}`);
    console.log(`  Retrieval Ranker: ${ranker.engine}${rankerOverridden ? ' (env override)' : ''} (k=${ranker.rrfK}, weights fts=${ranker.weights.fts} vector=${ranker.weights.vector} graph=${ranker.weights.graph})`);
    console.log('');
    return;
  }

  let changed = false;

  const modeIdx = args.indexOf('--mode');
  if (modeIdx !== -1 && args[modeIdx + 1]) {
    const mode = args[modeIdx + 1] as DefenceMode;
    if (!VALID_MODES.includes(mode)) {
      console.error(`Invalid mode: ${args[modeIdx + 1]}. Must be one of: ${VALID_MODES.join(', ')}`);
      process.exit(1);
    }
    setDefenceMode(mode);
    console.log(`Defence mode set to: ${mode}`);
    changed = true;
  }

  const keyIdx = args.indexOf('--cloud-api-key');
  if (keyIdx !== -1 && args[keyIdx + 1]) {
    setCloudConfig({ cloudApiKey: args[keyIdx + 1] });
    console.log('Cloud API key set.');
    changed = true;
  }

  const urlIdx = args.indexOf('--cloud-url');
  if (urlIdx !== -1 && args[urlIdx + 1]) {
    setCloudConfig({ cloudBaseUrl: args[urlIdx + 1] });
    console.log(`Cloud base URL set to: ${args[urlIdx + 1]}`);
    changed = true;
  }

  if (args.includes('--cloud-enable')) {
    setCloudConfig({ cloudEnabled: true });
    console.log('Cloud sync enabled.');
    changed = true;
  }

  if (args.includes('--cloud-disable')) {
    setCloudConfig({ cloudEnabled: false });
    console.log('Cloud sync disabled.');
    changed = true;
  }

  // ── Sensitive-content opt-in/opt-out ──
  // Default since v4.27: CONFIDENTIAL+ memories are NOT shipped to the cloud.
  // Users who genuinely want to mirror sensitive content (e.g. self-hosted
  // backend on their own network) can opt back in here.

  if (args.includes('--cloud-include-sensitive')) {
    setCloudSyncControls({ excludeSensitive: false });
    console.log('Cloud sync will now include CONFIDENTIAL+ memories.');
    console.log('Note: content is sent to your configured cloudBaseUrl in full.');
    changed = true;
  }

  if (args.includes('--cloud-exclude-sensitive')) {
    setCloudSyncControls({ excludeSensitive: true });
    console.log('Cloud sync will skip CONFIDENTIAL+ memories (default).');
    changed = true;
  }

  // ── Verify flags ──

  if (args.includes('--verify-enable')) {
    const config = getCloudConfig();
    if (!config.cloudEnabled || !config.cloudApiKey) {
      console.error('Error: Cloud sync must be enabled with an API key before enabling verification.');
      console.error('Note: Your cloud API key must include the "verify" scope.');
      process.exit(1);
    }
    setVerifyConfig({ verifyEnabled: true });
    console.log('LLM verification enabled.');
    console.log('Note: Your cloud API key must include the "verify" scope.');
    changed = true;
  }

  if (args.includes('--verify-disable')) {
    setVerifyConfig({ verifyEnabled: false });
    console.log('LLM verification disabled.');
    changed = true;
  }

  const verifyModeIdx = args.indexOf('--verify-mode');
  if (verifyModeIdx !== -1 && args[verifyModeIdx + 1]) {
    const vm = args[verifyModeIdx + 1];
    if (!VALID_VERIFY_MODES.includes(vm as typeof VALID_VERIFY_MODES[number])) {
      console.error(`Invalid verify mode: ${vm}. Must be one of: ${VALID_VERIFY_MODES.join(', ')}`);
      process.exit(1);
    }
    setVerifyConfig({ verifyMode: vm as 'advisory' | 'enforce' });
    console.log(`Verify mode set to: ${vm}`);
    changed = true;
  }

  const verifyTimeoutIdx = args.indexOf('--verify-timeout');
  if (verifyTimeoutIdx !== -1 && args[verifyTimeoutIdx + 1]) {
    const ms = parseInt(args[verifyTimeoutIdx + 1], 10);
    if (isNaN(ms) || ms < 1000 || ms > 30000) {
      console.error('Invalid verify timeout. Must be between 1000 and 30000 ms.');
      process.exit(1);
    }
    setVerifyConfig({ verifyTimeoutMs: ms });
    console.log(`Verify timeout set to: ${ms}ms`);
    changed = true;
  }

  const openclawAutoMemoryIdx = args.indexOf('--openclaw-auto-memory');
  if (openclawAutoMemoryIdx !== -1) {
    const value = args[openclawAutoMemoryIdx + 1];
    if (!value) {
      console.error('Missing value for --openclaw-auto-memory. Use true or false.');
      process.exit(1);
    }
    const normalized = value.toLowerCase();
    if (normalized !== 'true' && normalized !== 'false') {
      console.error(`Invalid value for --openclaw-auto-memory: ${value}. Use true or false.`);
      process.exit(1);
    }
    const enabled = normalized === 'true';
    setOpenClawAutoMemory(enabled);
    console.log(`OpenClaw auto-memory ${enabled ? 'enabled' : 'disabled'}.`);
    changed = true;
  }

  if (args.includes('--restore-4.10-defaults')) {
    restore410Defaults();
    console.log('Restored v4.10.x defaults:');
    console.log('  proactiveRecall: true');
    console.log('  interceptor.severityActions.high: require_approval');
    console.log('  interceptor.severityActions.critical: require_approval');
    console.log('  sessionStart.preamble: minimal');
    console.log('');
    console.log('Note: the v4.11.0 MAX_CONTEXT_MEMORIES reduction (15 → 5) is a');
    console.log('constant and cannot be reverted via config. Pin shieldcortex@4.10.7');
    console.log('if you need that behaviour.');
    changed = true;
  }

  const rankerIdx = args.indexOf('--ranker');
  if (rankerIdx !== -1) {
    const value = args[rankerIdx + 1];
    if (!value) {
      console.error('Missing value for --ranker. Use rrf or legacy.');
      process.exit(1);
    }
    const engine = value.toLowerCase();
    if (!VALID_RANKER_ENGINES.includes(engine as RankerEngine)) {
      console.error(`Invalid ranker engine: ${value}. Must be one of: ${VALID_RANKER_ENGINES.join(', ')}`);
      process.exit(1);
    }
    setRankerConfig({ engine: engine as RankerEngine });
    console.log(`Ranker engine set to: ${engine}`);
    if (process.env.SHIELDCORTEX_RANKER) {
      console.log('Note: SHIELDCORTEX_RANKER env var is set and will override config.json at runtime.');
    }
    changed = true;
  }

  const proactiveRecallIdx = args.indexOf('--proactive-recall');
  if (proactiveRecallIdx !== -1) {
    const value = args[proactiveRecallIdx + 1];
    if (!value) {
      console.error('Missing value for --proactive-recall. Use true or false.');
      process.exit(1);
    }
    const normalized = value.toLowerCase();
    if (normalized !== 'true' && normalized !== 'false') {
      console.error(`Invalid value for --proactive-recall: ${value}. Use true or false.`);
      process.exit(1);
    }
    const enabled = normalized === 'true';
    setProactiveRecall(enabled);
    console.log(`Proactive recall ${enabled ? 'enabled' : 'disabled'}.`);
    changed = true;
  }

  const selfHealIdx = args.indexOf('--self-heal');
  if (selfHealIdx !== -1) {
    const value = args[selfHealIdx + 1];
    if (!value) {
      console.error('Missing value for --self-heal. Use true or false.');
      process.exit(1);
    }
    const normalized = value.toLowerCase();
    if (normalized !== 'true' && normalized !== 'false') {
      console.error(`Invalid value for --self-heal: ${value}. Use true or false.`);
      process.exit(1);
    }
    const enabled = normalized === 'true';
    setSelfHeal(enabled);
    console.log(
      enabled
        ? 'Hook self-heal enabled (default) — the cortex-memory hook may remove legacy ~/.clawdbot hook dirs and copy itself into ~/.openclaw/hooks at gateway bootstrap.'
        : 'Hook self-heal disabled — the cortex-memory hook will log what it would have done and write nothing. Run `shieldcortex openclaw install` to migrate the hook yourself.',
    );
    console.log('Restart the OpenClaw gateway for this to take effect.');
    changed = true;
  }

  if (args.includes('--tool-firewall-enforce')) {
    setToolResponseScanConfig({ scanToolResponses: true, toolResponseMode: 'enforce' });
    console.log('Tool-output firewall set to ENFORCE — threatening tool output will be redacted/withheld before the agent sees it.');
    changed = true;
  }

  if (args.includes('--tool-firewall-advisory')) {
    setToolResponseScanConfig({ scanToolResponses: true, toolResponseMode: 'advisory' });
    console.log('Tool-output firewall set to ADVISORY — threats are logged but tool output is delivered intact (default).');
    changed = true;
  }

  if (args.includes('--tool-firewall-off')) {
    setToolResponseScanConfig({ scanToolResponses: false });
    console.log('Tool-output firewall disabled — tool responses are no longer scanned.');
    changed = true;
  }

  if (args.includes('--tool-firewall-on')) {
    setToolResponseScanConfig({ scanToolResponses: true });
    console.log('Tool-output firewall enabled (scanning on).');
    changed = true;
  }

  // ── Action Guard core switches (enable/enforce) ──
  // The SIGNED path for actionGuard.enabled / actionGuard.enforce, same reason
  // the notify flags exist: hand-editing config.json for these keys invalidates
  // the `_sig` HMAC and forces defenceMode strict. Both keys default ON when
  // absent (`!== false` semantics on read), so disable/advisory write an
  // explicit false.

  if (args.includes('--action-guard-enable')) {
    setActionGuardCoreConfig({ enabled: true });
    console.log('Action Guard enabled — tool calls are gated on both surfaces.');
    changed = true;
  }

  if (args.includes('--action-guard-disable')) {
    setActionGuardCoreConfig({ enabled: false });
    console.log('Action Guard DISABLED — tool calls are NOT gated on either surface, and catastrophic checks may not fire while the guard is off entirely. Re-enable with --action-guard-enable.');
    changed = true;
  }

  if (args.includes('--action-guard-enforce')) {
    // Enforce implies enabled: enforcing a disabled guard is nonsense, so this
    // flag also switches the guard on rather than writing a dead enforce key.
    setActionGuardCoreConfig({ enabled: true, enforce: true });
    console.log('Action Guard ENFORCE — dangerous ops require approval / block.');
    changed = true;
  }

  if (args.includes('--action-guard-advisory')) {
    setActionGuardCoreConfig({ enforce: false });
    console.log('Action Guard ADVISORY (warn-mode) — dangerous ops log but are not gated (catastrophic still blocks when enabled).');
    changed = true;
  }

  // ── Action Guard notify channel (#275) ──
  // The SIGNED path for what doctor's "enforcing with no notify channel" warn
  // prescribes. Hand-editing config.json for these keys invalidates the `_sig`
  // HMAC and forces defenceMode strict — these flags exist so nobody has to.

  if (args.includes('--action-guard-notify-openclaw')) {
    setActionGuardNotifyConfig({ enabled: true, openclaw: true });
    console.log('Action Guard notify enabled via the OpenClaw approval channel — denials raise an approval card on your gateway\'s channel.');
    changed = true;
  }

  const agNotifyWebhookIdx = args.indexOf('--action-guard-notify-webhook');
  if (agNotifyWebhookIdx !== -1) {
    const url = args[agNotifyWebhookIdx + 1];
    if (!url || url.startsWith('--')) {
      console.error('Missing value for --action-guard-notify-webhook. Provide an https:// URL, e.g. https://hooks.example.com/shieldcortex.');
      process.exit(1);
    }
    try {
      setActionGuardNotifyConfig({ enabled: true, webhookUrl: url });
    } catch (err) {
      console.error((err as Error).message);
      process.exit(1);
    }
    console.log(`Action Guard notify enabled via webhook: ${url.trim()}`);
    changed = true;
  }

  if (args.includes('--action-guard-notify-disable')) {
    setActionGuardNotifyConfig({ enabled: false });
    console.log('Action Guard notify disabled — unattended denials will only reach the audit log and session-guard index.');
    changed = true;
  }

  // ── Memory plane signed writes (empty-brain / sampling doctor fixes) ──
  // The SIGNED path for what doctor's memory-plane and auto-memory checks
  // prescribe. Hand-editing config.json for these keys invalidates the `_sig`
  // HMAC and forces defenceMode strict — these flags exist so nobody has to.

  const memInjectContractIdx = args.indexOf('--memory-inject-contract');
  if (memInjectContractIdx !== -1) {
    const contract = args[memInjectContractIdx + 1];
    if (!contract || contract.startsWith('--')) {
      console.error(`Missing value for --memory-inject-contract. Legal values: ${NATIVE_INJECT_CONTRACTS.join(', ')}.`);
      process.exit(1);
    }
    try {
      setMemoryInjectContract(contract);
    } catch (err) {
      console.error((err as Error).message);
      process.exit(1);
    }
    console.log(`Memory inject nativeContract set to ${contract} (signed write — config re-signed, integrity check stays green).`);
    changed = true;
  }

  const memPlaneIdx = args.indexOf('--memory-plane');
  if (memPlaneIdx !== -1) {
    const plane = args[memPlaneIdx + 1];
    if (!plane || plane.startsWith('--')) {
      console.error(`Missing value for --memory-plane. Legal values: ${MEMORY_PLANE_VALUES.join(', ')}.`);
      process.exit(1);
    }
    try {
      setMemoryPlane(plane);
    } catch (err) {
      console.error((err as Error).message);
      process.exit(1);
    }
    console.log(`Memory plane set to ${plane} (signed write — config re-signed; planeSetAt stamped).`);
    changed = true;
  }

  const autoMemSamplingIdx = args.indexOf('--auto-memory-sampling');
  if (autoMemSamplingIdx !== -1) {
    const rawTurns = args[autoMemSamplingIdx + 1];
    if (!rawTurns || rawTurns.startsWith('--')) {
      console.error('Missing value for --auto-memory-sampling. Provide an integer between 1 and 20 (≤ 5 recommended).');
      process.exit(1);
    }
    const turns = Number(rawTurns);
    if (!Number.isInteger(turns) || turns < 1 || turns > 20) {
      console.error(`Invalid value for --auto-memory-sampling: "${rawTurns}". Provide an integer between 1 and 20 (≤ 5 recommended).`);
      process.exit(1);
    }
    try {
      setAutoMemorySamplingTurns(turns);
    } catch (err) {
      console.error((err as Error).message);
      process.exit(1);
    }
    console.log(`Auto-memory Stop sampling set to every ${turns} turn(s) (signed write).`);
    changed = true;
  }

  if (args.includes('--allow-revoke-by-source')) {
    setRevokeBySourceEnabled(true);
    console.log('Revoke-by-source ENABLED. `forget --fromSource` can now bulk-delete a source\'s memories (trust-hierarchy ACL still applies). Disable again with --disallow-revoke-by-source when done.');
    changed = true;
  }

  if (args.includes('--disallow-revoke-by-source')) {
    setRevokeBySourceEnabled(false);
    console.log('Revoke-by-source disabled (default).');
    changed = true;
  }

  // Accepted no-ops: the Pro upsell was retired with the Free + Enterprise
  // repricing, but fleet scripts still call these flags — they must not error.
  if (args.includes('--upsell-mute')) {
    setUpsellState({ proMuted: true });
    changed = true;
  }

  if (args.includes('--upsell-unmute')) {
    setUpsellState({ proMuted: false });
    changed = true;
  }

  if (!changed) {
    console.log('Usage: shieldcortex config [options]');
    console.log('');
    console.log('Options:');
    console.log('  --mode <mode>          Set defence mode (strict|balanced|permissive)');
    console.log('  --cloud-api-key <key>  Set cloud API key');
    console.log('  --cloud-url <url>      Set cloud base URL');
    console.log('  --cloud-enable         Enable cloud sync');
    console.log('  --cloud-disable        Disable cloud sync');
    console.log('  --cloud-include-sensitive  Sync CONFIDENTIAL+ memories (off by default since v4.27)');
    console.log('  --cloud-exclude-sensitive  Stop syncing CONFIDENTIAL+ memories (default)');
    console.log('  --cloud-status         Show current configuration');
    console.log('  --openclaw-auto-memory <true|false>  Extract memories from OpenClaw LLM output (default: off)');
    console.log('  --proactive-recall <true|false>  Inject SC memory into prompts (default: off — adds latency)');
    console.log('  --ranker <rrf|legacy>  Hybrid retrieval engine (default: rrf; SHIELDCORTEX_RANKER env overrides)');
    console.log('  --self-heal <true|false>  Let the cortex-memory hook repair its own install at gateway bootstrap');
    console.log('                            (default: true; false = warn-only. SHIELDCORTEX_SKIP_SELF_HEAL=1 also opts out)');
    console.log('  --tool-firewall-enforce   Redact/withhold threatening tool output before the agent sees it');
    console.log('  --tool-firewall-advisory  Log tool-output threats but deliver intact (default)');
    console.log('  --tool-firewall-off / --tool-firewall-on  Disable / enable tool-output scanning');
    console.log('  --allow-revoke-by-source / --disallow-revoke-by-source  Enable/disable destructive forget --fromSource (default: disabled)');
    console.log('  --action-guard-enable    Enable Action Guard tool-call gating (default: on)');
    console.log('  --action-guard-disable   Disable Action Guard entirely — tool calls are NOT gated');
    console.log('  --action-guard-enforce   Gate dangerous ops (approval/block); also enables the guard');
    console.log('  --action-guard-advisory  Warn-mode — dangerous ops log but are not gated (catastrophic still blocks)');
    console.log('  --action-guard-notify-openclaw  Notify Action Guard denials via the native OpenClaw approval card');
    console.log('  --action-guard-notify-webhook <https-url>  Notify Action Guard denials to an https webhook');
    console.log('  --action-guard-notify-disable   Disable Action Guard denial notifications');
    console.log('  --memory-inject-contract <sc_only|disable_native_inject>  Set the memory-inject native contract (signed write)');
    console.log('  --memory-plane <dual_legacy|import_only|sc_canonical>  Set memory.plane (signed write; stamps planeSetAt)');
    console.log('  --auto-memory-sampling <n>  Stop-hook sampling cadence in turns (1-20, ≤ 5 recommended; signed write)');
    console.log('  --restore-4.10-defaults  Restore pre-v4.11.0 defaults (recall on, strict interceptor, minimal preamble)');
    console.log('');
    console.log('LLM Verification:');
    console.log('  --verify-enable        Enable LLM verification (requires cloud + verify scope)');
    console.log('  --verify-disable       Disable LLM verification');
    console.log('  --verify-mode <mode>   Set verify mode (advisory|enforce)');
    console.log('  --verify-timeout <ms>  Set verify timeout in ms (1000-30000)');
  }
}

export async function handleCloudCommand(args: string[]): Promise<void> {
  const action = args[0];

  if (action === 'sync' && args.includes('--full')) {
    const config = getCloudConfig();
    if (!config.cloudEnabled || !config.cloudApiKey) {
      console.error('Cloud sync is not configured. Set an API key and enable cloud sync first.');
      process.exit(1);
    }
    if (!isFeatureEnabled('cloud_sync')) {
      console.error('Full cloud memory sync requires an Enterprise licence — sales@drakonsystems.com');
      console.error('(Audit metadata sync is included on the cloud free tier.)');
      process.exit(1);
    }

    initDatabase();
    console.log('Syncing local memories and graph to ShieldCortex Cloud...');
    const memoryResult = await syncAllMemoriesToCloud();
    const graphResult = await syncAllGraphToCloud();
    let reconciled = 0;
    if (memoryResult.failed === 0 && graphResult.failedBatches === 0) {
      reconciled = reconcileSyncQueue({
        kinds: ['memory', 'graph'],
        statuses: ['pending', 'failed'],
        maxCreatedAt: new Date().toISOString(),
      }).removed;
    }
    console.log(
      `Finished. ${memoryResult.synced}/${memoryResult.total} memories synced` +
      `${memoryResult.failed > 0 ? `, ${memoryResult.failed} queued for retry` : ''}.`
    );
    console.log(
      `Graph replica: ${graphResult.entities} entities, ${graphResult.triples} relationships, ${graphResult.memoryEntities} memory links` +
      `${graphResult.failedBatches > 0 ? `, ${graphResult.failedBatches} batch${graphResult.failedBatches === 1 ? '' : 'es'} queued for retry` : ''}.`
    );
    if (reconciled > 0) {
      console.log(`Reconciled ${reconciled} stale sync queue entr${reconciled === 1 ? 'y' : 'ies'}.`);
    }
    return;
  }

  console.log('Usage: shieldcortex cloud sync --full');
}
