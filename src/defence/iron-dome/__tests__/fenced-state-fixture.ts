/**
 * Test-only: where a fenced store's state lives (fenced-store.ts). The path a
 * store is named by holds only a pointer once anything has committed; the
 * state is its newest generation. Before the first commit the pre-fence copy
 * at the store path is the state. Tests read and edit the state here, as a
 * same-UID writer could.
 */
import { join } from 'node:path';

import { fencedGenerationDir, readFencedJson } from '../fenced-store.js';

export function fencedStateFile(storePath: string): string {
  const { base } = readFencedJson(storePath);
  return base > 0 ? join(fencedGenerationDir(storePath), String(base)) : storePath;
}
