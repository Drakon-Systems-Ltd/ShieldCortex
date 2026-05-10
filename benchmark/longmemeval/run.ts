/**
 * CLI entry: `tsx benchmark/longmemeval/run.ts [--dataset <path>] [--top-k <n>] [--engine rrf|legacy|both]`
 *
 * Reads the dataset, runs each requested engine, writes
 * `benchmark/longmemeval/SCORECARD.md` and a sibling `report.json` for
 * downstream tools.
 *
 * Defaults are tuned for `npm run bench:smoke` to chew on the toy
 * fixture in <100 ms — the same harness, just shorter input. Long
 * runs (full LongMemEval-S, 500 questions) take longer; the runner
 * prints a per-question progress line so the user can see life signs.
 */

import { writeFileSync } from 'fs';
import { dirname, resolve } from 'path';
import { fileURLToPath } from 'url';
import { loadDataset } from './load.js';
import { runEngine } from './runner.js';
import { renderScorecard } from './scorecard.js';
import type { BenchmarkReport, EngineScorecard } from './types.js';
import type { RankerEngine } from '../../src/memory/types.js';

interface CliOptions {
  datasetPath: string;
  topK: number;
  engines: RankerEngine[];
  outDir: string;
  quiet: boolean;
}

function parseArgs(argv: readonly string[]): CliOptions {
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const opts: CliOptions = {
    datasetPath: resolve(__dirname, 'fixtures/toy-dataset.jsonl'),
    topK: 10,
    engines: ['rrf', 'legacy'],
    outDir: __dirname,
    quiet: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--dataset' && argv[i + 1]) {
      opts.datasetPath = resolve(argv[i + 1]);
      i++;
    } else if (arg === '--top-k' && argv[i + 1]) {
      opts.topK = Number.parseInt(argv[i + 1], 10);
      i++;
    } else if (arg === '--engine' && argv[i + 1]) {
      const value = argv[i + 1].toLowerCase();
      if (value === 'rrf' || value === 'legacy') opts.engines = [value];
      else if (value === 'both') opts.engines = ['rrf', 'legacy'];
      else throw new Error(`Invalid --engine: ${argv[i + 1]} (use rrf|legacy|both)`);
      i++;
    } else if (arg === '--out-dir' && argv[i + 1]) {
      opts.outDir = resolve(argv[i + 1]);
      i++;
    } else if (arg === '--quiet') {
      opts.quiet = true;
    } else if (arg === '--help' || arg === '-h') {
      printHelp();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return opts;
}

function printHelp(): void {
  console.log(`Usage: tsx benchmark/longmemeval/run.ts [options]

Options:
  --dataset <path>   Path to LongMemEval JSONL or JSON-array file
                     (default: fixtures/toy-dataset.jsonl)
  --top-k <n>        Top-k results to retrieve per question (default: 10)
  --engine <name>    rrf | legacy | both (default: both)
  --out-dir <path>   Where to write SCORECARD.md and report.json
                     (default: alongside the runner)
  --quiet            Suppress per-question progress output
  --help, -h         Show this help

Output:
  <out-dir>/SCORECARD.md   Human-readable comparison
  <out-dir>/report.json    Full machine-readable report
`);
}

async function main(argv: readonly string[]): Promise<number> {
  let opts: CliOptions;
  try {
    opts = parseArgs(argv);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    printHelp();
    return 2;
  }

  console.log(`[bench] dataset: ${opts.datasetPath}`);
  const questions = loadDataset(opts.datasetPath);
  console.log(`[bench] loaded ${questions.length} question(s)`);
  console.log(`[bench] top-k=${opts.topK} engines=${opts.engines.join(',')}`);

  const cards: EngineScorecard[] = [];
  for (const engine of opts.engines) {
    console.log(`\n[bench] ── engine: ${engine} ─────────────────────`);
    const card = await runEngine({
      engine,
      questions,
      topK: opts.topK,
      onProgress: opts.quiet
        ? undefined
        : (done, total, qid) => {
            if (done % 25 === 0 || done === total) {
              console.log(`[bench/${engine}] ${done}/${total} (last: ${qid})`);
            }
          },
    });
    cards.push(card);
    console.log(
      `[bench/${engine}] R@5=${(card.recall_at_5 * 100).toFixed(2)}% ` +
        `R@10=${(card.recall_at_10 * 100).toFixed(2)}% ` +
        `MRR=${card.mrr.toFixed(4)} ` +
        `duration=${(card.duration_ms / 1000).toFixed(2)}s`,
    );
  }

  const report: BenchmarkReport = {
    dataset_path: opts.datasetPath,
    k_top: opts.topK,
    generated_at: new Date().toISOString(),
    engines: cards,
  };

  const scorecardPath = resolve(opts.outDir, 'SCORECARD.md');
  const reportPath = resolve(opts.outDir, 'report.json');
  writeFileSync(scorecardPath, renderScorecard(report));
  writeFileSync(reportPath, JSON.stringify(report, null, 2));
  console.log(`\n[bench] wrote ${scorecardPath}`);
  console.log(`[bench] wrote ${reportPath}`);

  return 0;
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(`[bench] fatal:`, err);
    process.exit(1);
  },
);
