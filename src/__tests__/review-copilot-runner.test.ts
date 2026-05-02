import { EventEmitter } from 'events';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';

interface FakeWorkerOptions {
  execArgv?: string[];
  resourceLimits?: {
    maxOldGenerationSizeMb?: number;
  };
}

interface PostedMessage {
  id: number;
  type: 'review' | 'load' | 'ping';
  allowRemoteModels: boolean;
  prompt?: string;
  timeoutMs: number;
}

let config = {
  enabled: true,
  modelId: 'test-model',
  modelCacheDir: '/tmp/shieldcortex-review-copilot-models',
  telemetryPath: '/tmp/shieldcortex-review-copilot-telemetry.jsonl',
  inferenceTimeoutMs: 10000,
  workerHeapMB: 2048,
};

const workers: FakeWorker[] = [];
const telemetryEvents: unknown[] = [];

class FakeWorker extends EventEmitter {
  filename: string;
  options: FakeWorkerOptions;
  posted: PostedMessage[] = [];
  terminated = false;

  constructor(filename: string, options: FakeWorkerOptions) {
    super();
    this.filename = filename;
    this.options = options;
    workers.push(this);
  }

  postMessage(message: PostedMessage): void {
    this.posted.push(message);
    queueMicrotask(() => {
      this.emit('message', {
        id: message.id,
        ok: true,
        rawText: message.type === 'load' ? 'loaded' : '{"category":"uncertain"}',
      });
    });
  }

  terminate(): Promise<number> {
    this.terminated = true;
    this.emit('exit', 0);
    return Promise.resolve(0);
  }
}

async function loadRunner() {
  jest.unstable_mockModule('fs', () => ({
    existsSync: () => true,
  }));
  jest.unstable_mockModule('worker_threads', () => ({
    Worker: FakeWorker,
  }));
  jest.unstable_mockModule('../cloud/config.js', () => ({
    getReviewCopilotConfig: () => config,
  }));
  jest.unstable_mockModule('../defence/judge/telemetry.js', () => ({
    appendReviewCopilotTelemetry: (event: unknown) => {
      telemetryEvents.push(event);
    },
  }));
  return import('../defence/judge/runner.js');
}

describe('Review Copilot runner', () => {
  beforeEach(() => {
    jest.resetModules();
    workers.length = 0;
    telemetryEvents.length = 0;
    config = {
      enabled: true,
      modelId: 'test-model',
      modelCacheDir: '/tmp/shieldcortex-review-copilot-models',
      telemetryPath: '/tmp/shieldcortex-review-copilot-telemetry.jsonl',
      inferenceTimeoutMs: 10000,
      workerHeapMB: 2048,
    };
  });

  it('does not spawn a worker when disabled', async () => {
    config.enabled = false;
    const { runReviewCopilotPrompt } = await loadRunner();

    await expect(runReviewCopilotPrompt('review this')).resolves.toBeNull();
    expect(workers).toHaveLength(0);
  });

  it('spawns workers with clean execArgv and local-only review requests', async () => {
    const { runReviewCopilotPrompt, disposeReviewCopilotWorker } = await loadRunner();

    await expect(runReviewCopilotPrompt('review this')).resolves.toBe('{"category":"uncertain"}');

    expect(workers).toHaveLength(1);
    expect(workers[0].options.execArgv).toEqual([]);
    expect(workers[0].options.resourceLimits?.maxOldGenerationSizeMb).toBe(2048);
    expect(workers[0].posted[0]).toMatchObject({
      type: 'review',
      allowRemoteModels: false,
      prompt: 'review this',
      timeoutMs: 120000,
    });

    disposeReviewCopilotWorker();
    expect(workers[0].terminated).toBe(true);
  });

  it('allows remote model access only for explicit preload', async () => {
    config.enabled = false;
    const { preloadReviewCopilotModel, disposeReviewCopilotWorker } = await loadRunner();

    await expect(preloadReviewCopilotModel()).resolves.toBe(true);

    expect(workers).toHaveLength(1);
    expect(workers[0].posted[0]).toMatchObject({
      type: 'load',
      allowRemoteModels: true,
      timeoutMs: 300000,
    });

    disposeReviewCopilotWorker();
  });
});
