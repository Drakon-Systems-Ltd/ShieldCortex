/**
 * SARIF 2.1.0 output for ShieldCortex findings.
 *
 * Phase 15b — turns X-Ray / audit / mcp-scan findings into a SARIF 2.1.0
 * document so they surface in GitHub Code Scanning (the Security tab).
 *
 * Lives in the xray layer (its `index.ts` already re-exports the other
 * formatters) but is shape-agnostic: it accepts BOTH the xray `XRayFinding`
 * and the audit `AuditFinding` via a single internal normaliser, so the SARIF
 * builder never branches on the source shape.
 *
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import path from 'path';
import { createRequire } from 'module';
import type { XRayFinding, XRayCategory } from './types.js';
import type { AuditFinding, AuditSeverity } from '../audit/types.js';

const INFORMATION_URI = 'https://shieldcortex.ai';
const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';

// ── SARIF document types (the subset we emit) ──────────────────

export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

export interface SarifRule {
  id: string;
  name?: string;
  shortDescription?: { text: string };
  helpUri?: string;
}

export interface SarifArtifactLocation {
  uri: string;
}

export interface SarifRegion {
  startLine: number;
}

export interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
  region?: SarifRegion;
}

export interface SarifLogicalLocation {
  fullyQualifiedName: string;
  kind?: string;
}

export interface SarifLocation {
  physicalLocation?: SarifPhysicalLocation;
  logicalLocations?: SarifLogicalLocation[];
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations?: SarifLocation[];
}

export interface SarifDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifRule[];
}

export interface SarifRun {
  tool: { driver: SarifDriver };
  results: SarifResult[];
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export interface ToSarifOptions {
  /** Tool version recorded in tool.driver.version. Resolved from package.json when omitted. */
  version?: string;
  /** Base directory to make file URIs relative to (defaults to process.cwd()). */
  baseDir?: string;
}

// ── Normalised finding ─────────────────────────────────────────

/**
 * The common shape the SARIF builder works from. Both finding types map onto
 * this so the builder has exactly one code path.
 */
interface NormalisedFinding {
  ruleId: string;
  ruleName: string;
  level: SarifLevel;
  message: string;
  helpUri?: string;
  /** Present for findings tied to a file. */
  file?: string;
  /** Present only when a file AND a line number are known. */
  line?: number;
  /** Present for fileless findings (e.g. an MCP tool description). */
  logicalName?: string;
}

// ── Helpers ────────────────────────────────────────────────────

/**
 * Map a ShieldCortex severity onto a SARIF result level.
 *   critical / high → error
 *   medium          → warning
 *   low / info      → note
 */
function severityToLevel(severity: AuditSeverity): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'note';
  }
}

/**
 * Stable rule id from a category/scanner key + title. SARIF rule ids should be
 * opaque, stable, and free of whitespace so they read well in the GitHub UI and
 * dedupe deterministically across runs.
 */
function makeRuleId(prefix: string, title: string): string {
  const slug = `${prefix}/${title}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return `shieldcortex/${slug}`;
}

function isXRayFinding(f: XRayFinding | AuditFinding): f is XRayFinding {
  // XRayFinding has `category`; AuditFinding has `scanner`. They are disjoint.
  return (f as XRayFinding).category !== undefined;
}

/** Make a file path relative to baseDir + posix-separated for SARIF URIs. */
function toUri(file: string, baseDir: string): string {
  let rel = file;
  if (path.isAbsolute(file)) {
    rel = path.relative(baseDir, file);
    // If the file is outside baseDir, relative() yields ../ — fall back to the
    // absolute path rather than emitting a confusing climb-out URI.
    if (rel.startsWith('..')) rel = file;
  }
  return rel.split(path.sep).join('/');
}

function normalise(f: XRayFinding | AuditFinding): NormalisedFinding {
  if (isXRayFinding(f)) {
    const category: XRayCategory = f.category;
    return {
      ruleId: makeRuleId(category, f.title),
      ruleName: f.title,
      level: severityToLevel(f.severity),
      message: f.description,
      file: f.file,
      line: f.line,
    };
  }

  // AuditFinding. May or may not have a filePath.
  const audit = f;
  const norm: NormalisedFinding = {
    ruleId: makeRuleId(audit.scanner, audit.title),
    ruleName: audit.title,
    level: severityToLevel(audit.severity),
    message: audit.description,
    helpUri: audit.learnMoreUrl,
  };
  if (audit.filePath) {
    norm.file = audit.filePath;
  } else {
    // Fileless: synthesise a logical location from scanner + title so the
    // result still carries a location and stays schema-valid without a
    // physicalLocation.
    norm.logicalName = `${audit.scanner}/${audit.title}`;
  }
  return norm;
}

// ── Builder ────────────────────────────────────────────────────

function resolveVersion(): string {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require('../../package.json') as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/**
 * Build a SARIF 2.1.0 log from a list of findings (either shape).
 * Rules are deduped into `tool.driver.rules` by ruleId.
 */
export function toSarif(
  findings: (XRayFinding | AuditFinding)[],
  options: ToSarifOptions = {},
): SarifLog {
  const version = options.version ?? resolveVersion();
  const baseDir = options.baseDir ?? process.cwd();

  const rulesById = new Map<string, SarifRule>();
  const results: SarifResult[] = [];

  for (const finding of findings) {
    const n = normalise(finding);

    if (!rulesById.has(n.ruleId)) {
      const rule: SarifRule = {
        id: n.ruleId,
        name: n.ruleName,
        shortDescription: { text: n.ruleName },
      };
      if (n.helpUri) rule.helpUri = n.helpUri;
      rulesById.set(n.ruleId, rule);
    }

    const result: SarifResult = {
      ruleId: n.ruleId,
      level: n.level,
      message: { text: n.message },
    };

    if (n.file) {
      const physicalLocation: SarifPhysicalLocation = {
        artifactLocation: { uri: toUri(n.file, baseDir) },
      };
      if (typeof n.line === 'number') {
        physicalLocation.region = { startLine: n.line };
      }
      result.locations = [{ physicalLocation }];
    } else if (n.logicalName) {
      result.locations = [{ logicalLocations: [{ fullyQualifiedName: n.logicalName }] }];
    }

    results.push(result);
  }

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'ShieldCortex',
            version,
            informationUri: INFORMATION_URI,
            rules: Array.from(rulesById.values()),
          },
        },
        results,
      },
    ],
  };
}
