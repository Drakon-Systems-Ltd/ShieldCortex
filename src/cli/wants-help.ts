/**
 * Shared CLI help detection (#515, hardened in #577).
 *
 * `--help` / `-h` (and a bare `help` verb) must never execute an action.
 * Commands that previously ignored these flags ran the action anyway —
 * `audit --help` scanned the environment; `allowlist --help` was rejected
 * as an unknown subcommand.
 *
 * #577 put this function in front of every host-mutating subcommand, which
 * exposed the other half of the problem: it used to answer "does the word
 * `help` appear anywhere in argv?". That is not a question about the command
 * line, it is a substring search, and it swallowed perfectly valid VALUES —
 * `openclaw skill install --agent help`, `memories prune --project help` and
 * `memories migrate-legacy --source help` all printed usage and did nothing,
 * silently, while the downstream consumers accept those tokens as an agent id,
 * a project key and a source path. A help gate that eats real work is the same
 * defect as an action that eats a help flag, pointed the other way.
 *
 * The rule now: `--help` / `-h` count anywhere (they are never a value the CLI
 * asks for), and a bare `help` counts only in the verb position — the FIRST
 * positional, with the values of value-taking options skipped so they can never
 * be mistaken for one.
 */

/** Options that consume the following token as their value, per command. */
export interface WantsHelpOptions {
  /**
   * The command's value-taking options (`--agent`, `--project`, `--days`, …).
   * A token immediately after one of these is that option's value and is never
   * read as a verb. Omit it only for commands whose options are all boolean.
   */
  valueFlags?: readonly string[];
}

export function wantsHelp(args: readonly string[], options: WantsHelpOptions = {}): boolean {
  // Explicit help flags win wherever they appear: no option in this CLI takes a
  // value spelled `--help`, so there is no ambiguity to resolve.
  if (args.some((a) => a === '--help' || a === '-h')) return true;

  const valueFlags = options.valueFlags ?? [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    // `--flag value` — skip the value; `--flag=value` is one token and falls
    // through to the option branch below.
    if (valueFlags.includes(a)) {
      i++;
      continue;
    }
    if (a.startsWith('-') && a !== '-') continue;
    // First positional reached. `help` here is the verb; anywhere later it is
    // an argument to a verb that has already been chosen.
    return a === 'help';
  }
  return false;
}

/**
 * Value-taking options that can appear BEFORE the subcommand word, for the two
 * whole-argv gates in `src/index.ts` (the npm-staleness preamble and the stats
 * banner). Per-command lists live next to their own gate.
 */
export const GLOBAL_VALUE_FLAGS = ['--db', '--mode', '--dir'] as const;
