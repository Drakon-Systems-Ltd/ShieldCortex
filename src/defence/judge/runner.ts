import { Worker } from 'worker_threads';
import { dirname, join } from 'path';
import { existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { getReviewCopilotConfig } from '../../cloud/config.js';
import { appendReviewCopilotTelemetry } from './telemetry.js';
import type { ReviewCopilotWorkerResponse } from './types.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let worker: Worker | null = null;
let msgId = 0;
let resolvedWorkerPath: string | null | undefined;
let restartAfterMs = 250;
let modelWarm = false;

const pending = new Map<number, {
  type: 'review' | 'load' | 'ping';
  resolve: (value: string | null) => void;
  timer: ReturnType<typeof setTimeout>;
}>();

function getWorkerPath(): string {
  if (resolvedWorkerPath !== undefined) {
    if (resolvedWorkerPath === null) throw new Error('review_copilot_worker_unavailable');
    return resolvedWorkerPath;
  }

  const candidates = [
    join(__dirname, 'worker.js'),
    join(process.cwd(), 'dist', 'defence', 'judge', 'worker.js'),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      resolvedWorkerPath = candidate;
      return candidate;
    }
  }

  resolvedWorkerPath = null;
  throw new Error('review_copilot_worker_unavailable');
}

function rejectAllPending(reason: string): void {
  for (const [id, request] of pending) {
    clearTimeout(request.timer);
    request.resolve(null);
    pending.delete(id);
  }
  appendReviewCopilotTelemetry({
    type: 'model_unavailable',
    ts: new Date().toISOString(),
    reason,
  });
}

function resetWorker(reason?: string): void {
  if (worker) {
    try { worker.terminate(); } catch { /* best-effort */ }
  }
  worker = null;
  modelWarm = false;
  if (reason) rejectAllPending(reason);
}

function ensureWorker(force: boolean = false): Worker | null {
  if (worker) return worker;

  const config = getReviewCopilotConfig();
  if (!force && !config.enabled) return null;

  try {
    worker = new Worker(getWorkerPath(), {
      execArgv: [],
      resourceLimits: {
        maxOldGenerationSizeMb: config.workerHeapMB,
      },
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    appendReviewCopilotTelemetry({
      type: 'model_unavailable',
      ts: new Date().toISOString(),
      reason,
    });
    return null;
  }

  worker.on('message', (msg: ReviewCopilotWorkerResponse) => {
    if ('type' in msg) return;
    const request = pending.get(msg.id);
    if (!request) return;
    pending.delete(msg.id);
    clearTimeout(request.timer);
    if (msg.ok) {
      if (request.type === 'review' || request.type === 'load') {
        modelWarm = true;
      }
      request.resolve(msg.rawText ?? null);
    } else {
      appendReviewCopilotTelemetry({
        type: 'model_unavailable',
        ts: new Date().toISOString(),
        reason: msg.reason,
      });
      request.resolve(null);
    }
  });

  worker.on('error', (error) => {
    resetWorker(`worker_error:${error.message}`);
  });

  worker.on('exit', (code) => {
    const reason = `worker_exit:${code}`;
    worker = null;
    rejectAllPending(reason);
    restartAfterMs = Math.min(restartAfterMs * 2, 5000);
    setTimeout(() => {
      restartAfterMs = 250;
    }, restartAfterMs).unref();
  });

  return worker;
}

function getRequestTimeoutMs(type: 'review' | 'load' | 'ping'): number {
  const config = getReviewCopilotConfig();
  if (type === 'load') return Math.max(config.inferenceTimeoutMs, 300000);
  if (type === 'review' && !modelWarm) return Math.max(config.inferenceTimeoutMs, 120000);
  return config.inferenceTimeoutMs;
}

function send(type: 'review' | 'load' | 'ping', prompt?: string, force: boolean = false): Promise<string | null> {
  const config = getReviewCopilotConfig();
  if (!force && !config.enabled) return Promise.resolve(null);

  const activeWorker = ensureWorker(force);
  if (!activeWorker) return Promise.resolve(null);

  const id = ++msgId;
  const timeoutMs = getRequestTimeoutMs(type);

  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve(null);
      resetWorker(`${type}_timeout`);
    }, timeoutMs + 1000);

    pending.set(id, { type, resolve, timer });
    activeWorker.postMessage({
      id,
      type,
      modelId: config.modelId,
      cacheDir: config.modelCacheDir,
        allowRemoteModels: force,
        prompt,
        timeoutMs,
      });
  });
}

export async function runReviewCopilotPrompt(prompt: string): Promise<string | null> {
  return send('review', prompt);
}

export async function preloadReviewCopilotModel(): Promise<boolean> {
  return (await send('load', undefined, true)) !== null;
}

export function disposeReviewCopilotWorker(): void {
  resetWorker();
}
