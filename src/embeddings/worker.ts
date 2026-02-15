/**
 * Worker thread for ONNX embedding model.
 * Runs model loading and inference off the main thread so the event loop
 * stays responsive for MCP JSON-RPC messages.
 *
 * The ONNX runtime does synchronous C++ work during model loading and
 * inference that blocks the Node.js event loop. setTimeout/Promise.race
 * timeouts can't fire while the event loop is frozen. Running in a
 * worker_threads Worker solves this — the main thread stays free.
 */
import { parentPort } from 'worker_threads';
import { pipeline, env } from '@huggingface/transformers';
import type { FeatureExtractionPipeline } from '@huggingface/transformers';
import { join } from 'path';
import { homedir } from 'os';

env.allowRemoteModels = true;
env.allowLocalModels = true;
env.cacheDir = join(homedir(), '.cache', 'shieldcortex', 'models');

let extractor: FeatureExtractionPipeline | null = null;

async function loadModel(): Promise<void> {
  if (extractor) return;
  extractor = await pipeline(
    'feature-extraction',
    'Xenova/all-MiniLM-L6-v2',
  ) as unknown as FeatureExtractionPipeline;
}

async function embed(text: string): Promise<number[]> {
  if (!extractor) await loadModel();

  const truncated = text.slice(0, 2000);
  const output = await extractor!(truncated, {
    pooling: 'mean',
    normalize: true,
  });

  let result: number[];
  if (output.data && (output.data as ArrayLike<number>).length > 0) {
    result = Array.from(output.data as ArrayLike<number>);
  } else if (typeof output.tolist === 'function') {
    result = (output.tolist().flat(Infinity) as number[]);
  } else {
    throw new Error('Cannot extract embedding from tensor');
  }

  // Release ONNX native memory
  if (output && typeof (output as { dispose?: () => void }).dispose === 'function') {
    (output as { dispose: () => void }).dispose();
  }

  return result;
}

parentPort!.on('message', async (msg: { id: number; type: string; text?: string }) => {
  try {
    if (msg.type === 'load') {
      await loadModel();
      parentPort!.postMessage({ id: msg.id, ok: true });
    } else if (msg.type === 'embed') {
      const data = await embed(msg.text!);
      parentPort!.postMessage({ id: msg.id, ok: true, data });
    } else if (msg.type === 'ping') {
      parentPort!.postMessage({ id: msg.id, ok: true });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    parentPort!.postMessage({ id: msg.id, ok: false, error: message });
  }
});

// Signal ready
parentPort!.postMessage({ type: 'ready' });
