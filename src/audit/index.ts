/**
 * Audit Module — Public Exports
 *
 * `npx shieldcortex audit` — comprehensive security scanner for
 * AI agent environments.
 */

export { scanMemories } from './memory-scanner.js';
export { scanMcpConfigs } from './mcp-config-scanner.js';
export { scanEnvFiles } from './env-scanner.js';
export { scanRulesFiles } from './rules-file-scanner.js';
export { scanDependencies, resolveNodeModulesPath, quarantinePackage, cleanPackage } from './dependency-scanner.js';
export { formatTerminalReport, formatMarkdownReport, formatJsonReport } from './report-formatter.js';
export { calculateGrade } from './types.js';
export type {
  AuditFinding,
  AuditReport,
  AuditGrade,
  AuditSeverity,
  ScannerResult,
} from './types.js';
