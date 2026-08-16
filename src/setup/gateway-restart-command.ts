/**
 * ShieldCortex — the gateway restart command, defined once.
 *
 * Field evidence, 31 Jul 2026 (Michael's MacBook): `doctor` told an operator to
 * run `systemctl --user restart openclaw-gateway`. On macOS that is
 * `command not found`, twice, before anyone realised the tool was at fault
 * rather than the typing.
 *
 * The galling part is that the codebase already knew better. `deep-clean.ts`
 * branches on platform and uses `launchctl kickstart` for darwin; so does the
 * install path's fallback advice. `doctor` — the one surface operators actually
 * read when something is wrong — was the single place that hardcoded Linux.
 *
 * Knowing the right answer in the DOING code and printing the wrong one in the
 * TELLING code is the same defect family as #146 and #152: the machinery is
 * correct and the thing reporting on it is not. So the string lives here, once,
 * and both the executor and every piece of printed advice read it from here.
 */

/** Platform values we have a specific answer for. */
export type RestartPlatform = 'linux' | 'darwin' | string;

export interface GatewayRestartCommand {
  /** The exact command to run, or null when we genuinely do not know. */
  command: string | null;
  /** Short label for the mechanism, for logs and reports. */
  method: string;
  /** Operator-facing advice, always safe to print. */
  advice: string;
}

/**
 * The correct restart invocation for a platform.
 *
 * `uid` is only consulted on darwin, where launchd needs the GUI domain of the
 * user whose gateway this is. It is injectable so this stays pure and testable.
 */
export function gatewayRestartCommand(
  platform: RestartPlatform = process.platform,
  uid: number | null = typeof process.getuid === 'function' ? process.getuid() : null,
): GatewayRestartCommand {
  if (platform === 'linux') {
    const command = 'systemctl --user restart openclaw-gateway';
    return { command, method: 'systemctl --user', advice: command };
  }

  if (platform === 'darwin') {
    // `$(id -u)` keeps the printed form copy-pasteable even when we could not
    // read a uid ourselves; the executed form always uses the real number.
    const domain = uid == null ? '$(id -u)' : String(uid);
    const command = `launchctl kickstart -k gui/${domain}/ai.openclaw.gateway`;
    return {
      command,
      method: 'launchctl kickstart',
      advice:
        `${command}\n` +
        '  (if that reports "Could not find service", the gateway is not under launchd — ' +
        'quit and reopen the OpenClaw app/process instead)',
    };
  }

  // Windows, BSD, or anything else: we have no verified invocation, and
  // inventing one is how this bug happened in the first place.
  return {
    command: null,
    method: 'unknown',
    advice: 'restart the OpenClaw gateway process however it is managed on this host',
  };
}

/** Just the operator-facing advice, for printed remediation text. */
export function gatewayRestartAdvice(platform: RestartPlatform = process.platform): string {
  return gatewayRestartCommand(platform).advice;
}

/** How to inspect the running gateway boot line — not journalctl on Darwin. */
export function gatewayBootLogAdvice(platform: RestartPlatform = process.platform): string {
  if (platform === 'darwin') {
    return 'openclaw gateway restart   # then: launchctl print gui/$(id -u)/ai.openclaw.gateway';
  }
  if (platform === 'linux') {
    return 'journalctl --user -u openclaw-gateway | grep "http server listening"';
  }
  return 'inspect the OpenClaw gateway process log for a boot/"http server listening" line';
}
