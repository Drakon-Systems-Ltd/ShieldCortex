/**
 * `shieldcortex ledger verify [--json] [--db <path>]` (#617, design §5.7).
 *
 * Opens the database READ-ONLY and walks the chained ledger with the same
 * verifier the doctor row uses. It never migrates, never writes a row and
 * never creates the ledger: a database this build has not opened yet is
 * reported as "unchained".
 *
 * Exit codes: 0 consistent (or no chain yet), 1 inconsistent, 2 usage error or
 * no database to verify.
 */

import { existsSync } from 'fs';
import { getBetterSqlite3 } from '../database/better-sqlite3-guard.js';
import { resolveMemoriesDbPath } from '../database/init.js';
import { verifyLedger, formatLedgerReport } from '../defence/ledger/verify.js';
import { resolveLedgerConfig } from '../defence/ledger/config.js';

export const LEDGER_HELP = `Usage: shieldcortex ledger verify [--json] [--db <path>]

Walk the chained audit ledger of this database and report whether it is
internally consistent: the first bad row if not, unchained history from
before the chain existed, epochs, gaps in seq, missing intervals (no rows and
no heartbeat), lost-coverage markers and retention checkpoints.

A consistent result does NOT show that the history is complete, or that the
whole chain was not rewritten or its tail deleted: those need a head retained
outside this database. The report says so every time.

Options:
  --json         Machine-readable report
  --db <path>    Database to verify (default: the ShieldCortex database)
  -h, --help     Show this help

Exit codes: 0 consistent, 1 inconsistent, 2 usage error or no database.
`;

export interface LedgerIo {
  stdout: (s: string) => void;
  stderr: (s: string) => void;
}

const defaultIo: LedgerIo = {
  stdout: (s) => { process.stdout.write(s); },
  stderr: (s) => { process.stderr.write(s); },
};

export function runLedgerCommand(argv: string[], io: LedgerIo = defaultIo): number {
  if (argv.length === 0) {
    io.stderr(LEDGER_HELP);
    return 2;
  }
  if (argv.some((a) => a === '--help' || a === '-h') || argv[0] === 'help') {
    io.stdout(LEDGER_HELP);
    return 0;
  }
  const [verb, ...rest] = argv;
  if (verb !== 'verify') {
    io.stderr(`Unknown ledger command: ${verb}\n\n${LEDGER_HELP}`);
    return 2;
  }

  let json = false;
  let dbPath: string | undefined;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--json') json = true;
    else if (a === '--db') {
      const v = rest[i + 1];
      if (!v || v.startsWith('-')) {
        io.stderr('--db needs a path\n');
        return 2;
      }
      dbPath = v;
      i++;
    } else if (a.startsWith('--db=')) {
      dbPath = a.slice('--db='.length);
    } else {
      io.stderr(`Unknown option: ${a}\n\n${LEDGER_HELP}`);
      return 2;
    }
  }

  const path = resolveMemoriesDbPath(dbPath);
  if (!existsSync(path)) {
    io.stderr(`No ShieldCortex database at ${path} — nothing to verify.\n`);
    return 2;
  }

  const Database = getBetterSqlite3();
  let db: InstanceType<typeof Database>;
  try {
    db = new Database(path, { readonly: true, fileMustExist: true });
  } catch (err) {
    io.stderr(`Could not open ${path} read-only: ${err instanceof Error ? err.message : String(err)}\n`);
    return 2;
  }
  try {
    const report = verifyLedger(db, { heartbeatIntervalMs: resolveLedgerConfig().heartbeatIntervalMs });
    io.stdout(json ? `${JSON.stringify({ database: path, ...report }, null, 2)}\n` : formatLedgerReport(report));
    return report.status === 'inconsistent' ? 1 : 0;
  } finally {
    db.close();
  }
}
