import {
  getCloudConfig,
  setCloudConfig,
  getDefenceMode,
  setDefenceMode,
  getVerifyConfig,
  setVerifyConfig,
  getOpenClawAutoMemory,
  setOpenClawAutoMemory,
  isProactiveRecallEnabled,
  setProactiveRecall,
  type DefenceMode,
} from './config.js';
import { syncAllGraphToCloud } from './graph-sync.js';
import { syncAllMemoriesToCloud } from './memory-sync.js';
import { isFeatureEnabled } from '../license/gate.js';
import { initDatabase } from '../database/init.js';
import { reconcileSyncQueue } from './sync-queue.js';

const VALID_MODES: DefenceMode[] = ['strict', 'balanced', 'permissive'];
const VALID_VERIFY_MODES = ['advisory', 'enforce'] as const;

export function handleCloudConfig(args: string[]): void {
  if (args.includes('--cloud-status')) {
    const config = getCloudConfig();
    const mode = getDefenceMode();
    const verify = getVerifyConfig();
    const openclawAutoMemory = getOpenClawAutoMemory();
    console.log('\nShieldCortex Configuration:');
    console.log(`  Defence Mode: ${mode}`);
    console.log(`  Cloud Enabled:  ${config.cloudEnabled ? 'Yes' : 'No'}`);
    console.log(`  API Key:  ${config.cloudApiKey ? config.cloudApiKey.substring(0, 12) + '...' : 'Not set'}`);
    console.log(`  Base URL: ${config.cloudBaseUrl}`);
    console.log(`  LLM Verify:   ${verify.verifyEnabled ? 'Enabled' : 'Disabled'} (${verify.verifyMode}, ${verify.verifyTimeoutMs}ms timeout)`);
    console.log(`  Verify Triggers: ${verify.verifyTriggers.join(', ')}`);
    console.log(`  OpenClaw Auto-Memory: ${openclawAutoMemory ? 'Enabled' : 'Disabled'}`);
    console.log(`  Proactive Recall: ${isProactiveRecallEnabled() ? 'Enabled' : 'Disabled'}`);
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

  if (!changed) {
    console.log('Usage: shieldcortex config [options]');
    console.log('');
    console.log('Options:');
    console.log('  --mode <mode>          Set defence mode (strict|balanced|permissive)');
    console.log('  --cloud-api-key <key>  Set cloud API key');
    console.log('  --cloud-url <url>      Set cloud base URL');
    console.log('  --cloud-enable         Enable cloud sync');
    console.log('  --cloud-disable        Disable cloud sync');
    console.log('  --cloud-status         Show current configuration');
    console.log('  --openclaw-auto-memory <true|false>  Enable or disable OpenClaw auto-memory extraction');
    console.log('  --proactive-recall <true|false>  Enable or disable proactive memory recall on prompts');
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
      console.error('Cloud memory sync requires a Team or higher licence.');
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
