/**
 * Shared `--help` / bad-argument gate for the host-mutating subcommands (#577).
 *
 * #515 established that `--help` must never execute an action, and fixed the
 * two commands that were found then (`audit`, `allowlist`). The mutating
 * commands kept the defect: `update --help` ran the entire upgrade on 5.1.0
 * (npm global install, re-exec, hook rewrites, plugin reinstall) because
 * `runUpdate()` only ever looked for `--force`/`-f`/`--verbose` and ignored
 * everything else. A help flag is the operator's one chance to read what a
 * command will do BEFORE it does it; spending that chance on the action itself
 * is the worst possible failure for a command that rewrites the host.
 *
 * This gate is deliberately tiny and pure: it reads no files, opens no sockets
 * and never touches `process.argv`. A command that calls it first therefore
 * cannot mutate anything on the help or bad-argument path — the proof is
 * structural, not a matter of ordering luck inside a long function.
 */
import { wantsHelp } from './wants-help.js';

export interface HelpGateOptions {
  /**
   * The complete set of arguments the command honours. Omit it to gate on help
   * only — appropriate for the multi-verb dispatchers (`openclaw`, `hermes`,
   * `memories`, `sessions`) whose own switch already rejects what it does not
   * know, and whose value-taking flags (`--days 30`, `--source <path>`) a flat
   * allow-list cannot describe.
   */
  known?: readonly string[];
  /**
   * The command's value-taking options, forwarded to `wantsHelp` so that a
   * VALUE spelled `help` (`--agent help`) is not mistaken for the help verb
   * (#577). Omit for commands whose options are all boolean.
   */
  valueFlags?: readonly string[];
  log?: (message: string) => void;
  error?: (message: string) => void;
}

/**
 * Returns the exit code the command must stop on — 0 for `--help`, 2 for an
 * unknown flag or an extra positional — or `null` when it may proceed.
 *
 * Callers assign the result to `process.exitCode` and return; 0 is a no-op
 * assignment, and 2 reaches the shell without a `process.exit` that could cut
 * off buffered output.
 */
export function helpGate(
  args: readonly string[],
  help: string,
  options: HelpGateOptions = {},
): 0 | 2 | null {
  if (wantsHelp(args, { valueFlags: options.valueFlags })) {
    (options.log ?? ((m: string) => process.stdout.write(`${m}\n`)))(help);
    return 0;
  }

  const known = options.known;
  if (!known) return null;

  const unknown = args.filter((a) => !known.includes(a));
  if (unknown.length === 0) return null;

  const error = options.error ?? ((m: string) => process.stderr.write(`${m}\n`));
  error(`${unknown.length === 1 ? 'Unknown argument' : 'Unknown arguments'}: ${unknown.join(' ')}`);
  error('');
  error(help);
  return 2;
}
