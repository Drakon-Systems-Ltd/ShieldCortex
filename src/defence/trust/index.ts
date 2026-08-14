export { scoreSource } from './source-scorer.js';
export { filterByTrust } from './recall-filter.js';
export { scoreAgent, getAgentDepth, buildAgentHierarchy } from './agent-scorer.js';
export { checkAccess } from './access-control.js';
export { inferSourceFromEnvironment, resolveSource, clampSourceToCeiling } from './env-detector.js';
export type { CeilingClampResult } from './env-detector.js';
export { resolveToolSource, deriveAttested, deriveEnvConfirmed } from './resolve-tool-source.js';
export type { ResolveToolSourceOptions, ResolvedToolSource } from './resolve-tool-source.js';
export {
  UNATTESTED_ORIGIN,
  applyOwnershipStamp,
  isUnattestedIdentifier,
  isUnattestedSourceKey,
  stampUnattestedIdentifier,
  stripUnattestedStamp,
} from './attestation-stamp.js';
export type { AccessPolicy, AccessCheckMemory } from './access-control.js';
export type { AgentTrustConfig } from './agent-scorer.js';
export type { EnvDetectionResult } from './env-detector.js';
