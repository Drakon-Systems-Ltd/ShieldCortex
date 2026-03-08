import fs from 'node:fs/promises';
import path from 'node:path';

const standaloneDir = path.resolve('dashboard/.next/standalone');
const removable = [
  'dashboard/node_modules/typescript',
  'dashboard/node_modules/@types',
];

for (const relativePath of removable) {
  await fs.rm(path.join(standaloneDir, relativePath), { recursive: true, force: true });
}
