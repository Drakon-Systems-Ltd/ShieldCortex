import { existsSync, readdirSync, rmSync, readFileSync } from 'fs';
import readline from 'readline';
import { getReviewCopilotConfig, setReviewCopilotConfig } from '../cloud/config.js';
import { initDatabase } from '../database/init.js';
import { FeatureGatedError, requireFeature } from '../license/gate.js';
import { preloadReviewCopilotModel, disposeReviewCopilotWorker } from '../defence/judge/index.js';

function usage(): void {
  console.log('Usage: shieldcortex review-copilot <enable|disable|status|download-model|annotate> [options]');
  console.log('');
  console.log('Commands:');
  console.log('  enable [--accept-download]       Enable Local AI Explainer');
  console.log('  disable [--purge]                Disable Local AI Explainer; --purge removes cached model files');
  console.log('  status                           Show config and recent metadata-only telemetry');
  console.log('  download-model [--accept-download]  Download/preload the configured local model');
  console.log('  annotate --pending [--limit N]   Explain pending quarantine items');
  console.log('  annotate --id <id>               Explain one pending quarantine item');
}

function requireReviewCopilotFeature(): boolean {
  try {
    requireFeature('local_ai_explainer');
    return true;
  } catch (error) {
    if (error instanceof FeatureGatedError) {
      console.error('\n' + error.message);
      return false;
    }
    throw error;
  }
}

function isModelCached(cacheDir: string): boolean {
  try {
    return existsSync(cacheDir) && readdirSync(cacheDir).length > 0;
  } catch {
    return false;
  }
}

function tailTelemetry(path: string, count: number = 10): string[] {
  try {
    if (!existsSync(path)) return [];
    return readFileSync(path, 'utf-8').trim().split('\n').filter(Boolean).slice(-count);
  } catch {
    return [];
  }
}

function printDownloadNotice(): void {
  const config = getReviewCopilotConfig();
  console.log('Local AI Explainer runs a local model. Content stays on this machine.');
  console.log(`  Model:      ${config.modelId}`);
  console.log('  Size:       varies by model; expect hundreds of MB or more');
  console.log(`  Cache:      ${config.modelCacheDir}`);
  console.log(`  Telemetry:  ${config.telemetryPath} (metadata only, no raw content)`);
}

function askConfirmation(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return Promise.resolve(false);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim().toLowerCase() === 'y' || answer.trim().toLowerCase() === 'yes');
    });
  });
}

async function confirmDownload(args: string[]): Promise<boolean> {
  if (args.includes('--accept-download')) return true;
  printDownloadNotice();
  if (!process.stdin.isTTY) {
    console.error('Refusing to download in non-interactive mode without --accept-download.');
    return false;
  }
  return askConfirmation('Download/prepare this local model now? [y/N] ');
}

async function enable(args: string[]): Promise<void> {
  if (!requireReviewCopilotFeature()) process.exit(1);
  if (!(await confirmDownload(args))) process.exit(1);

  setReviewCopilotConfig({ enabled: true });
  console.log('Local AI Explainer enabled.');
  const ok = await preloadReviewCopilotModel();
  disposeReviewCopilotWorker();
  if (ok) {
    console.log('Local model is ready.');
  } else {
    console.log('Local model could not be prepared yet. Local AI Explainer will fall back until the model is available.');
  }
}

function disable(args: string[]): void {
  const config = getReviewCopilotConfig();
  setReviewCopilotConfig({ enabled: false });
  disposeReviewCopilotWorker();
  if (args.includes('--purge')) {
    try {
      rmSync(config.modelCacheDir, { recursive: true, force: true });
      console.log(`Purged model cache: ${config.modelCacheDir}`);
    } catch {
      console.log(`Could not purge model cache: ${config.modelCacheDir}`);
    }
  }
  console.log('Local AI Explainer disabled.');
}

function status(): void {
  const config = getReviewCopilotConfig();
  console.log('\nLocal AI Explainer:');
  console.log(`  Enabled:     ${config.enabled ? 'yes' : 'no'}`);
  console.log(`  Model:       ${config.modelId}`);
  console.log(`  Cache:       ${config.modelCacheDir}`);
  console.log(`  Cached:      ${isModelCached(config.modelCacheDir) ? 'yes' : 'no'}`);
  console.log(`  Timeout:     ${config.inferenceTimeoutMs}ms`);
  console.log(`  Worker heap: ${config.workerHeapMB}MB`);
  console.log(`  Telemetry:   ${config.telemetryPath}`);

  const recent = tailTelemetry(config.telemetryPath);
  if (recent.length > 0) {
    console.log('\nRecent telemetry:');
    for (const line of recent) console.log(`  ${line}`);
  }
}

async function downloadModel(args: string[]): Promise<void> {
  if (!requireReviewCopilotFeature()) process.exit(1);
  if (!(await confirmDownload(args))) process.exit(1);
  const ok = await preloadReviewCopilotModel();
  disposeReviewCopilotWorker();
  if (!ok) {
    console.error('Model download/preload failed.');
    process.exit(1);
  }
  console.log('Local AI Explainer model is ready.');
}

async function annotate(args: string[], dbPath?: string): Promise<void> {
  if (!requireReviewCopilotFeature()) process.exit(1);
  const config = getReviewCopilotConfig();
  if (!config.enabled) {
    console.error('Local AI Explainer is disabled. Run `shieldcortex review-copilot enable` first.');
    process.exit(1);
  }
  if (!isModelCached(config.modelCacheDir)) {
    console.error('Local AI Explainer model is not cached. Run `shieldcortex review-copilot download-model` first.');
    process.exit(1);
  }

  initDatabase(dbPath);

  const { annotatePendingQuarantineItems, annotateQuarantineItem } = await import('../defence/judge/annotate.js');
  const idIdx = args.indexOf('--id');
  if (idIdx !== -1) {
    const id = Number(args[idIdx + 1]);
    if (!Number.isInteger(id) || id <= 0) {
      console.error('Invalid --id value.');
      process.exit(1);
    }
    const annotation = await annotateQuarantineItem(id);
    console.log(annotation ? `Explained quarantine item ${id}.` : `No pending quarantine item ${id} was explained.`);
    return;
  }

  if (args.includes('--pending')) {
    const limitIdx = args.indexOf('--limit');
    const limit = limitIdx !== -1 ? Number(args[limitIdx + 1]) : 50;
    const result = await annotatePendingQuarantineItems({ limit });
    console.log(`Attempted ${result.attempted}; explained ${result.annotated}; skipped ${result.skipped}; failed ${result.failed}.`);
    return;
  }

  usage();
  process.exit(1);
}

export async function handleReviewCopilotCommand(args: string[], dbPath?: string): Promise<void> {
  const command = args[0];
  const rest = args.slice(1);
  switch (command) {
    case 'enable':
      await enable(rest);
      break;
    case 'disable':
      disable(rest);
      break;
    case 'status':
      status();
      break;
    case 'download-model':
      await downloadModel(rest);
      break;
    case 'annotate':
      await annotate(rest, dbPath);
      break;
    default:
      usage();
      process.exit(1);
  }
}
