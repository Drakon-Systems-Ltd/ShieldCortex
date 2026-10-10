/**
 * `shieldcortex setup` / `install` / `doctor` dispatch, help first (#707).
 *
 * On 5.5.0 `install --help` wrote the Claude Code config and hooks instead of
 * printing usage: `main()` sent `install` (and any `setup` carrying a
 * `--with-*` / `--no-*` flag) straight into `setupClaudeMd()`, which never looks
 * at a help flag. `doctor --help` ran every diagnostic. `setup --help` only
 * "worked" because the quickstart target switch fell through to its usage error
 * — after scanning the host table, and with exit 1.
 *
 * The dispatch lives here rather than inline in `main()` for the reason
 * `vacuum.ts` gives: a gate buried in `main()` can only be grepped, and grepping
 * cannot tell a live gate from a dead one. Each handler module is imported only
 * AFTER the gate, so a help request loads none of them — doctor's module graph
 * in particular is large, and nothing in it is worth importing to print usage.
 *
 * The help verdict is `wantsHelp(args)` with no value flags: none of these
 * commands takes an option value, and it is exactly the verdict `argvWantsHelp`
 * already reaches for an unregistered command word — so the staleness preamble,
 * the stats banner and this gate cannot disagree about the same command line.
 */
import { wantsHelp } from './wants-help.js';
import type { HookOptInOptions } from '../setup/settings-hooks.js';

export const SETUP_HELP = `Usage: shieldcortex setup [target] [hook flags]
       shieldcortex install [hook flags]
       shieldcortex setup uninstall

With no arguments, setup shows the detected-host table, offers to wire each
unwired host, and asks for an Action Guard posture on a terminal.

Targets:
  claude | openclaw | hermes | copilot | codex
                           Install into that one host
  security                 Print the security setup guide
  --yes, --install-detected
                           Wire every detected host without prompting
  uninstall                Remove hooks and the CLAUDE.md block (asks first)

install is the Claude Code install: CLAUDE.md, the global MCP server entry,
hooks in ~/.claude/settings.json, the OpenClaw hook when OpenClaw is present,
and owner-only permissions on ShieldCortex state. setup given --with-stop-hook
or --with-session-end does the same Claude Code install; the --without-* opt-outs
go with install.

Hook flags:
  --with-stop-hook         Opt in to the Stop hook (sampled per-turn extraction)
  --with-session-end       Opt in to the SessionEnd hook (extraction on exit)
  --without-stop-hook      Opt out of the Stop hook
  --without-session-end    Opt out of the SessionEnd hook
                           Absent flags leave existing opt-ins unchanged.

  -h, --help               Show this help and exit (installs and changes nothing)`;

export const DOCTOR_HELP = `Usage: shieldcortex doctor [options]

Diagnose the installation. Exits 1 when any check fails.

Options:
  --strict                 Also exit 1 when any check warns
  --json                   Print the checked rows as JSON instead of the report
  --verbose, --debug       Show every passing check
  --fix-project-keys       Repair unambiguous project-key collisions (backs up first)
  --fix-action-guard       Migrate the deprecated interceptor.actionGuard alias
  --fix-hermes-plugin-copies
                           Move shadowing Hermes plugin copies into
                           ~/.hermes/backups/ (exit 1 if any could not be moved)
  --repair                 On a terminal, offer to wire unwired hosts
  --repair --agent         Write a repair brief instead (spawns no agent)
  --ai                     Append an AI explanation of the results (never
                           changes the checks or the exit code)
  -h, --help               Show this help and exit (runs no checks)`;

/** Handlers `dispatchSetupCommand` routes to; each defaults to the real one. */
export interface SetupDispatchDeps {
  log?: (message: string) => void;
  uninstallSetup?: () => Promise<void>;
  setupClaudeMd?: (options: HookOptInOptions) => Promise<void>;
  handleQuickstartCommand?: (target?: string) => Promise<void>;
}

/**
 * `args` is the command's own argv — everything after `setup` / `install`,
 * exactly what `main()` holds as `process.argv.slice(3)`.
 */
export async function dispatchSetupCommand(
  command: 'setup' | 'install',
  args: readonly string[],
  deps: SetupDispatchDeps = {},
): Promise<void> {
  if (wantsHelp(args)) {
    (deps.log ?? ((m: string) => process.stdout.write(`${m}\n`)))(SETUP_HELP);
    return;
  }

  if (args[0] === 'uninstall') {
    const uninstallSetup = deps.uninstallSetup
      ?? (await import('../setup/uninstall.js')).uninstallSetup;
    await uninstallSetup();
    return;
  }

  const { parseHookOptInFlags } = await import('../setup/settings-hooks.js');
  // `setup` with no extra flags is the host-table wizard. `install` stays
  // Claude Code only so existing scripts do not grow OpenClaw/Hermes
  // installs. Explicit hook flags on setup also stay Claude-only.
  const hookFlags = parseHookOptInFlags([...args]);
  const hasHookFlag = args.some((a) => a.startsWith('--with-') || a.startsWith('--no-'));
  if (command === 'install' || hasHookFlag) {
    const setupClaudeMd = deps.setupClaudeMd
      ?? (await import('../setup/claude-md.js')).setupClaudeMd;
    await setupClaudeMd(hookFlags);
  } else {
    const handleQuickstartCommand = deps.handleQuickstartCommand
      ?? (await import('../setup/quickstart.js')).handleQuickstartCommand;
    await handleQuickstartCommand(args[0]);
  }
}

/** Handlers `dispatchDoctorCommand` routes to; each defaults to the real one. */
export interface DoctorDispatchDeps {
  log?: (message: string) => void;
  runDoctor?: (args: string[]) => Promise<unknown>;
}

/** `args` is everything after `doctor` (`process.argv.slice(3)`). */
export async function dispatchDoctorCommand(
  args: readonly string[],
  deps: DoctorDispatchDeps = {},
): Promise<void> {
  if (wantsHelp(args)) {
    (deps.log ?? ((m: string) => process.stdout.write(`${m}\n`)))(DOCTOR_HELP);
    return;
  }
  const runDoctor = deps.runDoctor ?? (await import('./doctor.js')).runDoctor;
  await runDoctor([...args]);
}
