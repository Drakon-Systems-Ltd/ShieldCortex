/**
 * The one place that builds the `openclaw plugins install` spec for the
 * realtime plugin.
 *
 * OpenClaw 2026.11.5 resolves a spec with no source prefix (`@scope/name`,
 * `@scope/name@1.2.3`, `@scope/name@latest`) on ClawHub and no longer falls
 * back to npm. ClawHub carries an old one-off listing of this package
 * (5.17.3), so a bare `@latest` install there silently put a stale plugin
 * behind a current CLI. `npm:<spec>` forces npm; an exact version means a
 * stale registry cannot swap in anything else. The plugin ships in lockstep
 * with the CLI, so the version is the one this CLI expects.
 *
 * OpenClaw hosts older than the `npm:` prefix (it landed in 2026.4.26) reject
 * it before installing anything, with `unsupported npm spec: protocol specs
 * are not allowed`. Only that refusal earns ONE retry with the bare, still
 * exact-pinned spec. Every other failure (integrity, trust, policy, consent,
 * network, config) is surfaced as is, and nothing ever falls back to
 * `clawhub:`.
 *
 * `--force` is always passed: since OpenClaw 2026.7 a non-ClawHub source
 * installed without a terminal is cancelled unless `--force` confirms it, and
 * `--force` also overwrites an existing install (which every caller wants).
 */
import semver from 'semver';

export const REALTIME_PLUGIN_PACKAGE = '@drakon-systems/shieldcortex-realtime';

/** `npm:` forces npm; `bare` is only for hosts that predate that prefix. */
export type RealtimePluginSpecSource = 'npm' | 'bare';

/** The exact version when it is valid semver, else `latest`. */
function selector(version: string | null | undefined): string {
  const v = typeof version === 'string' ? semver.valid(version.trim()) : null;
  return v ?? 'latest';
}

/** `npm:@drakon-systems/shieldcortex-realtime@<version>` (or `@latest` when the version is unknown). */
export function realtimePluginInstallSpec(
  version: string | null | undefined,
  source: RealtimePluginSpecSource = 'npm',
): string {
  const spec = `${REALTIME_PLUGIN_PACKAGE}@${selector(version)}`;
  return source === 'npm' ? `npm:${spec}` : spec;
}

/** argv for the `openclaw` binary. */
export function realtimePluginInstallArgs(
  version: string | null | undefined,
  source: RealtimePluginSpecSource = 'npm',
): string[] {
  return ['plugins', 'install', '--force', realtimePluginInstallSpec(version, source)];
}

/** The copy-paste command an operator runs. */
export function realtimePluginInstallCommand(
  version: string | null | undefined,
  source: RealtimePluginSpecSource = 'npm',
): string {
  return `openclaw ${realtimePluginInstallArgs(version, source).join(' ')}`;
}

/**
 * True only when OpenClaw refused the `npm:` source itself because it predates
 * the prefix. OpenClaw <= 2026.4.25 validates every npm spec and rejects any
 * `:` with exactly this text, before ClawHub, npm or the gateway is touched.
 */
export function rejectsNpmSourcePrefix(output: string): boolean {
  return /unsupported npm spec: protocol specs are not allowed/i.test(output);
}

/**
 * The same install with the bare spec, for a host that rejected `npm:`; null
 * when `args` carry no `npm:` realtime spec (nothing to fall back from).
 */
export function bareFallbackArgs(args: readonly string[]): string[] | null {
  const prefix = `npm:${REALTIME_PLUGIN_PACKAGE}@`;
  const i = args.findIndex((a) => a.startsWith(prefix));
  if (i < 0) return null;
  const out = [...args];
  out[i] = args[i].slice('npm:'.length);
  return out;
}

/**
 * Run a synchronous install, retrying ONCE with the bare spec when — and only
 * when — the host rejected the `npm:` source. `outputOf` returns everything the
 * child said when it failed, or null when it succeeded.
 */
export function runWithNpmSourceFallbackSync<R>(
  args: readonly string[],
  run: (args: string[]) => R,
  outputOf: (r: R) => string | null,
): { result: R; args: string[]; fellBack: boolean } {
  const first = run([...args]);
  const said = outputOf(first);
  const bare = said !== null && rejectsNpmSourcePrefix(said) ? bareFallbackArgs(args) : null;
  if (!bare) return { result: first, args: [...args], fellBack: false };
  return { result: run(bare), args: bare, fellBack: true };
}
