import { parentPort } from 'worker_threads';
import type { ReviewCopilotWorkerRequest } from './types.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let generator: any = null;
let activeModelId: string | null = null;
let loadError: string | null = null;

async function initTransformers(cacheDir: string, allowRemoteModels: boolean): Promise<void> {
  try {
    const mod = await import('@huggingface/transformers');
    mod.env.allowRemoteModels = allowRemoteModels;
    mod.env.allowLocalModels = true;
    mod.env.cacheDir = cacheDir;
  } catch (error) {
    loadError = error instanceof Error ? error.message : String(error);
    throw new Error(`transformers_load_failed:${loadError}`);
  }
}

async function loadModel(modelId: string, cacheDir: string, allowRemoteModels: boolean): Promise<void> {
  if (generator && activeModelId === modelId) return;
  if (loadError) throw new Error(loadError);

  await initTransformers(cacheDir, allowRemoteModels);
  const mod = await import('@huggingface/transformers');
  generator = await mod.pipeline('text-generation', modelId, {
    dtype: 'q4',
  });
  activeModelId = modelId;
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | null = null;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(`timeout:${timeoutMs}`)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

async function generate(prompt: string, timeoutMs: number): Promise<string> {
  const messages = [
    {
      role: 'system',
      content: 'You are ShieldCortex Review Copilot. Return exactly one valid JSON object and no other text.',
    },
    {
      role: 'user',
      content: prompt,
    },
  ];

  const output = await withTimeout(generator(messages, {
    max_new_tokens: 768,
    do_sample: false,
    temperature: 0,
    return_full_text: false,
  }), timeoutMs);

  if (Array.isArray(output) && output[0]?.generated_text) {
    const generated = output[0].generated_text;
    if (Array.isArray(generated)) {
      const last = generated[generated.length - 1] as { content?: unknown } | undefined;
      return String(last?.content ?? '');
    }
    return String(generated);
  }
  if (typeof output === 'object' && output && 'generated_text' in output) {
    const generated = (output as { generated_text: unknown }).generated_text;
    if (Array.isArray(generated)) {
      const last = generated[generated.length - 1] as { content?: unknown } | undefined;
      return String(last?.content ?? '');
    }
    return String(generated);
  }
  return String(output ?? '');
}

parentPort?.postMessage({ type: 'ready' });

setInterval(() => {
  parentPort?.postMessage({ type: 'heartbeat' });
}, 5000).unref();

parentPort?.on('message', async (msg: ReviewCopilotWorkerRequest) => {
  try {
    if (msg.type === 'ping') {
      parentPort?.postMessage({ id: msg.id, ok: true, rawText: 'pong' });
      return;
    }

    await loadModel(msg.modelId, msg.cacheDir, msg.allowRemoteModels);

    if (msg.type === 'load') {
      parentPort?.postMessage({ id: msg.id, ok: true, rawText: 'loaded' });
      return;
    }

    if (!msg.prompt) {
      parentPort?.postMessage({ id: msg.id, ok: false, reason: 'missing_prompt' });
      return;
    }

    const rawText = await generate(msg.prompt, msg.timeoutMs);
    parentPort?.postMessage({ id: msg.id, ok: true, rawText });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    parentPort?.postMessage({ id: msg.id, ok: false, reason });
  }
});
