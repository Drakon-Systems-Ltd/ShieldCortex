import { z } from 'zod';

/**
 * PINNED transcription of OpenClaw v2026.9.4's persisted installed-plugin-index
 * parser (upstream tag `v2026.9.4`, commit 3a9d69db306cd7f081e06254cb89c4bcc14a7107):
 *
 *   - `src/plugins/installed-plugin-index-store.ts` → `InstalledPluginIndexSchema`,
 *     `parseInstalledPluginIndex()`, `readPersistedInstalledPluginIndexSync()`
 *   - `src/config/zod-schema.installs.ts`         → `InstallRecordShape`, `PluginInstallRecordShape`
 *   - `src/config/plugin-install-record-map.ts`   → `parsePluginInstallRecord()`, `parsePluginInstallRecordMap()`
 *   - `src/plugins/installed-plugin-index.ts`     → `indexInstallRecords()` (the no-`installRecords` fallback)
 *
 * Why a verbatim copy rather than "the fields we consume": the migrated
 * `config_machine_state.plugins.installedIndex` row is OpenClaw's evidence, and
 * OpenClaw only trusts it after THIS parser accepts it. A row the host rejects is
 * a row the host will regenerate; if ShieldCortex read it anyway it would reconcile
 * against state the host never used and manufacture `enabled-not-loaded` FAILs
 * and `reinstall-pinned` advice out of an unreadable index (PR #480 review). So
 * the reader rejects exactly what the host rejects, no more and no less. Keep the
 * shapes byte-for-byte aligned with the pinned version; bump the pin deliberately
 * when the host contract moves, with a live-row probe against the new host.
 *
 * Zod semantics mirrored: `z.object()` strips unknown keys (host default),
 * `.passthrough()` on install records, `.strict()` on `acceptedSurface`,
 * `.optional()` rejects `null`.
 */

const StringArraySchema = z.array(z.string());

const InstalledPluginIndexStartupSchema = z.object({
  sidecar: z.boolean(),
  memory: z.boolean(),
  agentHarnesses: StringArraySchema,
  configPaths: StringArraySchema.optional(),
});

const InstalledPluginIndexContributionSchema = z.object({
  channels: StringArraySchema,
  channelConfigs: StringArraySchema,
  providers: StringArraySchema,
  modelCatalogProviders: StringArraySchema,
  modelSupportPrefixes: StringArraySchema,
  modelSupportPatterns: StringArraySchema,
  autoEnableProviderIds: StringArraySchema,
  commandAliases: StringArraySchema,
  contracts: z.record(z.string(), StringArraySchema),
});

const InstalledPluginFileSignatureSchema = z.object({
  size: z.number(),
  mtimeMs: z.number(),
  ctimeMs: z.number().optional(),
});

// src/config/zod-schema.installs.ts
const InstallSourceSchema = z.union([
  z.literal('npm'),
  z.literal('archive'),
  z.literal('path'),
  z.literal('clawhub'),
  z.literal('git'),
]);
const PluginInstallSourceSchema = z.union([InstallSourceSchema, z.literal('marketplace')]);

const InstallRecordShape = {
  source: InstallSourceSchema,
  spec: z.string().optional(),
  sourcePath: z.string().optional(),
  installPath: z.string().optional(),
  version: z.string().optional(),
  resolvedName: z.string().optional(),
  resolvedVersion: z.string().optional(),
  resolvedSpec: z.string().optional(),
  integrity: z.string().optional(),
  shasum: z.string().optional(),
  resolvedAt: z.string().optional(),
  installedAt: z.string().optional(),
  clawhubUrl: z.string().optional(),
  clawhubPackage: z.string().optional(),
  clawhubFamily: z.union([z.literal('code-plugin'), z.literal('bundle-plugin')]).optional(),
  clawhubChannel: z.union([z.literal('official'), z.literal('community'), z.literal('private')]).optional(),
  clawhubTrustDisposition: z
    .union([z.literal('clean'), z.literal('review-recommended'), z.literal('review-required'), z.literal('blocked')])
    .optional(),
  clawhubTrustScanStatus: z.string().optional(),
  clawhubTrustModerationState: z.string().optional(),
  clawhubTrustReasons: z.array(z.string()).optional(),
  clawhubTrustPending: z.boolean().optional(),
  clawhubTrustStale: z.boolean().optional(),
  clawhubTrustCheckedAt: z.string().optional(),
  clawhubTrustAcknowledgedAt: z.string().optional(),
  artifactKind: z.union([z.literal('legacy-zip'), z.literal('npm-pack')]).optional(),
  artifactFormat: z.union([z.literal('zip'), z.literal('tgz')]).optional(),
  npmIntegrity: z.string().optional(),
  npmShasum: z.string().optional(),
  npmTarballName: z.string().optional(),
  clawpackSha256: z.string().optional(),
  clawpackSpecVersion: z.number().int().nonnegative().optional(),
  clawpackManifestSha256: z.string().optional(),
  clawpackSize: z.number().int().nonnegative().optional(),
  gitUrl: z.string().optional(),
  gitRef: z.string().optional(),
  gitCommit: z.string().optional(),
};

const PluginInstallRecordShape = {
  ...InstallRecordShape,
  source: PluginInstallSourceSchema,
  marketplaceName: z.string().optional(),
  marketplaceSource: z.string().optional(),
  marketplacePlugin: z.string().optional(),
  acceptedSurface: z
    .object({
      channels: z.array(z.string().min(1)),
      providers: z.array(z.string().min(1)),
      tools: z.array(z.string().min(1)),
      contracts: z.array(z.string().min(1)),
      hooks: z.array(z.string().min(1)),
      mcpServers: z.array(z.string().min(1)),
      cliCommands: z.array(z.string().min(1)),
      cliBackends: z.array(z.string().min(1)),
      skills: z.array(z.string().min(1)),
      dangerousConfigFlags: z.array(z.string().min(1)),
    })
    .strict()
    .optional(),
  acceptedSurfaceHash: z.string().optional(),
  acceptedSurfaceAt: z.string().optional(),
  acceptedSurfaceIntegrity: z.string().optional(),
};

// src/config/plugin-install-record-map.ts
const PluginInstallRecordSchema = z.object(PluginInstallRecordShape).passthrough();

export type HostPluginInstallRecord = z.infer<typeof PluginInstallRecordSchema>;

const InstalledPluginIndexRecordSchema = z.object({
  pluginId: z.string(),
  installOwner: z.string().optional(),
  installOwnerAmbiguous: z.literal(true).optional(),
  packageName: z.string().optional(),
  packageVersion: z.string().optional(),
  installRecord: PluginInstallRecordSchema.optional(),
  installRecordHash: z.string().optional(),
  packageInstall: z.unknown().optional(),
  packageChannel: z.unknown().optional(),
  packageBuild: z.object({ bundledDist: z.boolean().optional() }).optional(),
  manifestPath: z.string(),
  manifestHash: z.string(),
  doctorContractHash: z.string().optional(),
  doctorContractFile: InstalledPluginFileSignatureSchema.optional(),
  manifestFile: InstalledPluginFileSignatureSchema.optional(),
  format: z.string().optional(),
  bundleFormat: z.string().optional(),
  source: z.string().optional(),
  setupSource: z.string().optional(),
  packageJson: z
    .object({
      path: z.string(),
      hash: z.string(),
      fileSignature: InstalledPluginFileSignatureSchema.optional(),
    })
    .optional(),
  rootDir: z.string(),
  origin: z.string(),
  enabled: z.boolean(),
  enabledByDefault: z.boolean().optional(),
  enabledByDefaultOnPlatforms: StringArraySchema.optional(),
  syntheticAuthRefs: StringArraySchema.optional(),
  startup: InstalledPluginIndexStartupSchema,
  contributions: InstalledPluginIndexContributionSchema.optional(),
  compat: z.array(z.string()),
});

export type HostInstalledPluginIndexRecord = z.infer<typeof InstalledPluginIndexRecordSchema>;

const PluginDiagnosticSchema = z.object({
  level: z.union([z.literal('warn'), z.literal('error')]),
  message: z.string(),
  pluginId: z.string().optional(),
  source: z.string().optional(),
  code: z.string().optional(),
});

const InstalledPluginIndexSchema = z.object({
  version: z.literal(1),
  warning: z.string().optional(),
  hostContractVersion: z.string(),
  compatRegistryVersion: z.string(),
  migrationVersion: z.literal(1),
  policyHash: z.string(),
  generatedAtMs: z.number(),
  workspaceDir: z.string().optional(),
  refreshReason: z.string().optional(),
  installRecords: z.unknown().optional(),
  plugins: z.array(InstalledPluginIndexRecordSchema),
  diagnostics: z.array(PluginDiagnosticSchema),
});

/** The host-valid index as OpenClaw 2026.9.4 hands it to its own consumers. */
export interface HostInstalledPluginIndex {
  version: 1;
  warning?: string;
  hostContractVersion: string;
  compatRegistryVersion: string;
  migrationVersion: 1;
  policyHash: string;
  generatedAtMs: number;
  workspaceDir?: string;
  refreshReason?: string;
  /** Null-prototype map keyed by plugin id (host: `createPluginInstallRecordMap()`). */
  installRecords: Record<string, HostPluginInstallRecord>;
  plugins: HostInstalledPluginIndexRecord[];
  diagnostics: z.infer<typeof PluginDiagnosticSchema>[];
}

/** Host `PLUGIN_INSTALL_RECORD_NORMALIZED_STRING_FIELDS` (trimmed; empty → deleted). */
const NORMALIZED_STRING_FIELDS = [
  'spec',
  'sourcePath',
  'installPath',
  'version',
  'resolvedName',
  'resolvedVersion',
  'resolvedSpec',
  'integrity',
  'shasum',
  'resolvedAt',
  'installedAt',
  'clawhubUrl',
  'clawhubPackage',
  'clawhubFamily',
  'clawhubChannel',
  'clawhubTrustDisposition',
  'clawhubTrustScanStatus',
  'clawhubTrustModerationState',
  'clawhubTrustCheckedAt',
  'clawhubTrustAcknowledgedAt',
  'artifactKind',
  'artifactFormat',
  'npmIntegrity',
  'npmShasum',
  'npmTarballName',
  'clawpackSha256',
  'clawpackManifestSha256',
  'gitUrl',
  'gitRef',
] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function createPluginInstallRecordMap(): Record<string, HostPluginInstallRecord> {
  return Object.create(null) as Record<string, HostPluginInstallRecord>;
}

/** Host `setPluginInstallRecordMapEntry`: every plugin id is an own enumerable key, `__proto__` included. */
function setPluginInstallRecordMapEntry(
  map: Record<string, HostPluginInstallRecord>,
  pluginId: string,
  record: HostPluginInstallRecord,
): void {
  Object.defineProperty(map, pluginId, { value: record, enumerable: true, writable: true, configurable: true });
}

/** Host `parsePluginInstallRecord`: schema + string-field normalisation. */
export function parseHostPluginInstallRecord(value: unknown): HostPluginInstallRecord | null {
  const parsed = PluginInstallRecordSchema.safeParse(value);
  if (!parsed.success) return null;
  const record = parsed.data as Record<string, unknown>;
  for (const field of NORMALIZED_STRING_FIELDS) {
    const fieldValue = record[field];
    if (typeof fieldValue !== 'string') continue;
    const normalized = fieldValue.trim();
    if (normalized) record[field] = normalized;
    else delete record[field];
  }
  const reasons = record.clawhubTrustReasons;
  if (Array.isArray(reasons)) {
    const trimmed = (reasons as string[]).map((entry) => entry.trim()).filter(Boolean);
    if (trimmed.length > 0) record.clawhubTrustReasons = trimmed;
    else delete record.clawhubTrustReasons;
  }
  return record as HostPluginInstallRecord;
}

/** Host `parsePluginInstallRecordMap`: not a record, or ANY entry invalid → null. */
export function parseHostPluginInstallRecordMap(value: unknown): Record<string, HostPluginInstallRecord> | null {
  if (!isRecord(value)) return null;
  const records = createPluginInstallRecordMap();
  for (const [pluginId, rawRecord] of Object.entries(value)) {
    const record = parseHostPluginInstallRecord(rawRecord);
    if (!record) return null;
    setPluginInstallRecordMapEntry(records, pluginId, record);
  }
  return records;
}

/**
 * Host `parseInstalledPluginIndex`: the full-schema parse, then the install-record
 * map — from the index's own `installRecords` when that key is present (any invalid
 * record rejects the whole index), otherwise rebuilt from each plugin's
 * `installRecord` (host `indexInstallRecords()` fallback).
 */
export function parseHostInstalledPluginIndex(value: unknown): HostInstalledPluginIndex | null {
  const result = InstalledPluginIndexSchema.safeParse(value);
  if (!result.success) return null;
  const parsed = result.data;
  let installRecords: Record<string, HostPluginInstallRecord> | null;
  if (Object.hasOwn(parsed, 'installRecords')) {
    installRecords = parseHostPluginInstallRecordMap(parsed.installRecords);
  } else {
    // Host `restoreInstallRecordMap(indexInstallRecords(index))`: the per-plugin
    // records are re-parsed through the record map, so they get the same
    // string-field normalisation as an explicit `installRecords` map.
    const raw = createPluginInstallRecordMap();
    for (const plugin of parsed.plugins) {
      if (plugin.installRecord) setPluginInstallRecordMapEntry(raw, plugin.pluginId, plugin.installRecord);
    }
    installRecords = parseHostPluginInstallRecordMap(raw);
  }
  if (!installRecords) return null;
  return {
    version: parsed.version,
    ...(parsed.warning ? { warning: parsed.warning } : {}),
    hostContractVersion: parsed.hostContractVersion,
    compatRegistryVersion: parsed.compatRegistryVersion,
    migrationVersion: parsed.migrationVersion,
    policyHash: parsed.policyHash,
    generatedAtMs: parsed.generatedAtMs,
    ...(parsed.workspaceDir !== undefined ? { workspaceDir: parsed.workspaceDir } : {}),
    ...(parsed.refreshReason ? { refreshReason: parsed.refreshReason } : {}),
    installRecords,
    plugins: parsed.plugins,
    diagnostics: parsed.diagnostics,
  };
}

/**
 * Host `readPersistedInstalledPluginIndexSync` on an already-decoded
 * `config_machine_state.value_json`: the wrapper must be an object carrying a
 * numeric `revision`; the `index` key may be absent (host parses `undefined`
 * → null). Anything else is exactly as unreadable to ShieldCortex as it is to
 * OpenClaw.
 */
export function parseHostPersistedInstalledPluginIndexRow(value: unknown): HostInstalledPluginIndex | null {
  if (!isRecord(value) || typeof value.revision !== 'number') return null;
  return parseHostInstalledPluginIndex('index' in value ? value.index : undefined);
}
