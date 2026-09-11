/**
 * `shieldcortex scan` CLI — runs the defence pipeline and returns the #449
 * process-exit code. Does not call process.exit; the dispatcher does.
 */
import path from 'node:path';
import os from 'node:os';

import type { ProvenanceLabel, ProvenanceSource } from '../defence/types.js';
// Static import: provenance-policy is pure (regex + the window helper) and pulls
// in no database, no model and no native binding, so it is safe on the CLI's
// cold path where the pipeline itself is still lazily imported.
import { describeProvenance, isProvenanceLabel } from '../defence/firewall/provenance-policy.js';
import {
  SCAN_EXIT,
  SCAN_USAGE_LINES,
  formatScanToolFailure,
  scanVerdictExit,
  type ScanExitCode,
} from './scan-exit.js';

export { SCAN_EXIT, SCAN_USAGE_LINES, formatScanToolFailure, scanVerdictExit };
export type { ScanExitCode };

const IDENTIFIER_PATTERN = /^[A-Za-z0-9._:-]{1,64}$/;
const DEFAULT_CLI_SOURCE: ProvenanceSource = { type: 'cli', identifier: 'shieldcortex-scan' };

export type ParsedScanArgs =
  | { ok: true; text: string; source: ProvenanceSource; sourceAttested: boolean; json: boolean }
  | { ok: false };

function takeFlagValue(
  args: string[],
  index: number,
  prefix: '--source' | '--identifier',
): { value: string; consumed: number } | null {
  const token = args[index];
  if (token === prefix) {
    const value = args[index + 1];
    if (!value || value.startsWith('-')) return null;
    return { value, consumed: 2 };
  }
  if (token.startsWith(`${prefix}=`)) {
    const value = token.slice(prefix.length + 1);
    if (!value) return null;
    return { value, consumed: 1 };
  }
  return null;
}

/**
 * Parse `shieldcortex scan` argv after the subcommand.
 * Bare `scan TEXT` remains attested cli:shieldcortex-scan.
 * `--source` is a caller declaration, never host attestation.
 */
export function parseScanArgs(args: string[]): ParsedScanArgs {
  let sourceType: ProvenanceLabel | undefined;
  let identifier: string | undefined;
  let json = false;
  const positionals: string[] = [];

  for (let i = 0; i < args.length; ) {
    const token = args[i];
    if (token === '--') {
      positionals.push(...args.slice(i + 1));
      break;
    }
    if (!token.startsWith('-')) {
      positionals.push(token);
      i += 1;
      continue;
    }
    if (token === '--json') {
      // A repeat is a caller mistake, not a second opinion — same treatment as
      // a repeated --source.
      if (json) return { ok: false };
      json = true;
      i += 1;
      continue;
    }
    const sourceFlag = takeFlagValue(args, i, '--source');
    if (sourceFlag) {
      if (!isProvenanceLabel(sourceFlag.value) || sourceType !== undefined) return { ok: false };
      sourceType = sourceFlag.value;
      i += sourceFlag.consumed;
      continue;
    }
    const idFlag = takeFlagValue(args, i, '--identifier');
    if (idFlag) {
      if (!IDENTIFIER_PATTERN.test(idFlag.value) || identifier !== undefined) return { ok: false };
      identifier = idFlag.value;
      i += idFlag.consumed;
      continue;
    }
    return { ok: false };
  }

  if (positionals.length !== 1 || positionals[0] === '') return { ok: false };
  if (identifier !== undefined && sourceType === undefined) return { ok: false };

  if (sourceType === undefined) {
    return { ok: true, text: positionals[0], source: DEFAULT_CLI_SOURCE, sourceAttested: true, json };
  }

  return {
    ok: true,
    text: positionals[0],
    source: { type: sourceType, identifier: identifier ?? 'scan' },
    sourceAttested: false,
    json,
  };
}

/**
 * The one line an undeclared scan owes its caller.
 *
 * `--source=unknown` is a legitimate answer — an integration that genuinely
 * cannot classify its input should say so rather than guess `user`. But the
 * scan it produces is NOT the same scan: the L2 floor is off, so a caller who
 * read "ALLOW" without this line would over-read the verdict. Bounded, and it
 * never echoes the scanned text — a diagnostic is the wrong place to reprint
 * bytes that were just described as being of unknown origin.
 */
export const UNDECLARED_PROVENANCE_NOTICE =
  'Note: provenance is undeclared (--source=unknown) — the L2 non-authoritative-instruction ' +
  'floor was NOT applied to this scan; only the standard detectors ran.';

export function printScanUsage(writeErr: (line: string) => void = (l) => console.error(l)): void {
  for (const line of SCAN_USAGE_LINES) writeErr(line);
}

/**
 * One line naming the provenance CLASS, so a reader can tell which policy ran.
 *
 * Three states, not two: trusted (L2 deliberately off), untrusted data origin
 * (L2 on), and everything else — `hook`, `agent`, `file`, `api`,
 * `tool_response`, `unknown` — which is neither, and keeps exactly the L1 path
 * it had before this round. Collapsing the third into "trusted" would be a
 * claim the policy does not make.
 */
function describeProvenanceLine(label: string): string {
  const p = describeProvenance(label);
  if (p.trusted) return `${p.label} (trusted, L2 not applied)`;
  if (p.l2Applied) return `${p.label} (untrusted, L2 applied)`;
  if (p.label === 'unknown') return `${p.label} (undeclared, L2 not applied)`;
  return `${p.label} (not a declared data origin, L2 not applied)`;
}

/**
 * The `--json` envelope.
 *
 * Deliberately NOT a dump of the pipeline result. Two omissions are on
 * purpose: the scanned text never appears (a machine-readable verdict is the
 * most likely thing to be shipped to a log aggregator), and credential
 * findings carry severity/provider/type/action but NOT the matched bytes — the
 * human report prints `match` to a terminal the operator is already looking
 * at, which is a different disclosure surface from a file a pipeline keeps.
 */
export interface ScanJsonReport {
  result: string;
  allowed: boolean;
  reason: string;
  trust: number;
  sensitivity: string;
  anomalyScore: number;
  threatIndicators: string[];
  blockedPatterns: string[];
  source: { type: string; identifier: string; attested: boolean };
  provenance: { label: string; trusted: boolean; l2Applied: boolean };
  credentialFindings: Array<{ severity: string; provider?: string; type: string; action: string }>;
  exit: ScanExitCode;
}

export function buildScanJsonReport(
  result: Parameters<typeof printScanVerdict>[0] & { allowed: boolean },
  parsed: Extract<ParsedScanArgs, { ok: true }>,
  exit: ScanExitCode,
): ScanJsonReport {
  return {
    result: result.firewall.result,
    allowed: result.allowed,
    reason: result.firewall.reason,
    trust: result.trust.score,
    sensitivity: result.sensitivity.level,
    anomalyScore: result.firewall.anomalyScore,
    threatIndicators: [...result.firewall.threatIndicators],
    blockedPatterns: [...result.firewall.blockedPatterns],
    source: {
      type: parsed.source.type,
      identifier: parsed.source.identifier,
      attested: parsed.sourceAttested,
    },
    provenance: describeProvenance(parsed.source.type),
    credentialFindings: (result.credentialScan?.findings ?? []).map((f) => ({
      severity: f.severity,
      ...(f.provider ? { provider: f.provider } : {}),
      type: f.type,
      action: f.action,
    })),
    exit,
  };
}

function printScanVerdict(result: {
  allowed: boolean;
  firewall: {
    result: string;
    reason: string;
    anomalyScore: number;
    threatIndicators: string[];
    blockedPatterns: string[];
  };
  trust: { score: number };
  sensitivity: { level: string };
  source?: { type: string; identifier: string };
  sourceAttested?: boolean;
  credentialScan?: { findings: Array<{ severity: string; provider?: string; type: string; match: string; action: string }> } | null;
}): void {
  const bold = '\x1b[1m';
  const reset = '\x1b[0m';
  const green = '\x1b[32m';
  const red = '\x1b[31m';
  const yellow = '\x1b[33m';

  const resultColor = result.firewall.result === 'ALLOW' ? green :
                      result.firewall.result === 'QUARANTINE' ? yellow : red;

  console.log(`\n${bold}ShieldCortex Scan Result${reset}`);
  console.log(`${'─'.repeat(50)}`);
  console.log(`  Result:      ${resultColor}${result.firewall.result}${reset}`);
  if (result.source) {
    const attestation = result.sourceAttested === true ? 'attested' : 'declared';
    console.log(`  Source:      ${result.source.type}:${result.source.identifier} (${attestation})`);
    console.log(`  Provenance:  ${describeProvenanceLine(result.source.type)}`);
  }
  console.log(`  Trust:       ${result.trust.score.toFixed(2)}`);
  console.log(`  Sensitivity: ${result.sensitivity.level}`);
  console.log(`  Anomaly:     ${result.firewall.anomalyScore.toFixed(2)}`);
  console.log(`  Reason:      ${result.firewall.reason}`);

  if (result.firewall.threatIndicators.length > 0) {
    console.log(`  Threats:     ${result.firewall.threatIndicators.join(', ')}`);
  }
  if (result.firewall.blockedPatterns.length > 0) {
    console.log(`  Patterns:    ${result.firewall.blockedPatterns.join(', ')}`);
  }

  if (result.credentialScan && result.credentialScan.findings.length > 0) {
    console.log(`\n${bold}Credential Findings (${result.credentialScan.findings.length}):${reset}`);
    for (const f of result.credentialScan.findings) {
      const sColor = f.severity === 'critical' ? red : f.severity === 'high' ? red : yellow;
      console.log(`  ${sColor}[${f.severity.toUpperCase()}]${reset} ${f.provider ? f.provider + ' ' : ''}${f.type}: ${f.match} (${f.action})`);
    }
  }

  console.log();
}

/**
 * WHAT `scan` WRITES (r2/B8 correction).
 *
 * It stores no MEMORY — nothing lands in `memories` and no recall changes.
 * It is not, however, a read-only probe, and describing it as "writes
 * nothing" was wrong: it initialises the database at `dbPath` (creating it
 * if absent) and runs the ORDINARY defence pipeline, which writes a
 * `defence_audit` row for the verdict and, where an operator has configured
 * cloud sync, can forward quarantine content like any other pipeline caller.
 * Measured: eleven scans against an isolated HOME left eleven defence_audit
 * rows and zero memories.
 *
 * That matters for anyone using `scan` as a measurement harness: the runs are
 * on the record, which is usually what you want, and the isolation you need is
 * HOME / CLAUDE_MEMORY_DB, not an assumption that the command is inert.
 */
async function runParsedScan(parsed: Extract<ParsedScanArgs, { ok: true }>): Promise<ScanExitCode> {
  let result: Parameters<typeof printScanVerdict>[0] & { allowed: boolean };
  try {
    const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
    const { initDatabase } = await import('../database/init.js');
    initDatabase(dbPath);

    const { runDefencePipeline } = await import('../defence/pipeline.js');
    // Bare CLI identity is hardcoded in this dispatch → attested by construction.
    // Declared --source is caller labelling only and is never host-attested.
    result = runDefencePipeline(
      parsed.text,
      'CLI Scan',
      parsed.source,
      undefined,
      undefined,
      { sourceAttested: parsed.sourceAttested },
    );
  } catch (err) {
    console.error(formatScanToolFailure(err));
    return SCAN_EXIT.TOOL_FAILURE;
  }

  const exit = scanVerdictExit(result.allowed);

  // The undeclared notice goes to STDERR in both modes, so `--json` stdout
  // stays exactly one parseable object.
  if (parsed.source.type === 'unknown') {
    console.error(UNDECLARED_PROVENANCE_NOTICE);
  }

  if (parsed.json) {
    console.log(JSON.stringify(buildScanJsonReport(result, parsed, exit)));
  } else {
    printScanVerdict({
      ...result,
      source: parsed.source,
      sourceAttested: parsed.sourceAttested,
    });
  }

  // A flush failure is not a scan failure: the verdict already printed.
  try {
    const { flushPendingCloudSync } = await import('../cloud/sync.js');
    await flushPendingCloudSync(8000);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`Scan verdict stands; cloud flush failed: ${msg}`);
  }

  return exit;
}

/** Legacy single-positional helper. Bare text stays attested cli:shieldcortex-scan. */
export async function runScanCommand(text: string | undefined): Promise<ScanExitCode> {
  return runScanArgv(text === undefined ? [] : [text]);
}

export async function runScanArgv(args: string[]): Promise<ScanExitCode> {
  const parsed = parseScanArgs(args);
  if (!parsed.ok) {
    printScanUsage();
    return SCAN_EXIT.USAGE;
  }
  return runParsedScan(parsed);
}
