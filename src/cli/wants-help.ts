/**
 * Shared CLI help detection (#515).
 *
 * `--help` / `-h` (and a bare `help` token) must never execute an action.
 * Commands that previously ignored these flags ran the action anyway —
 * `audit --help` scanned the environment; `allowlist --help` was rejected
 * as an unknown subcommand.
 */
export function wantsHelp(args: readonly string[]): boolean {
  return args.some((a) => a === '--help' || a === '-h' || a === 'help');
}
