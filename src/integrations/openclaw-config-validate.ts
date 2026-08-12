/**
 * Is OpenClaw's own config in a state where its CLI will actually run? (#221)
 *
 * OpenClaw refuses EVERY `plugins` and `skills` subcommand while any config
 * entry dangles — and the refusal reads `Unknown command: openclaw plugins
 * list`, not "your config is invalid". Verified live against 2026.7.1-2 with a
 * dangling plugin path: `plugins list` and `skills list` both exit 1 with that
 * message; fix the config and the identical command exits 0. OpenClaw itself
 * names the survivors on stderr — "Audit, status, health, logs, tasks
 * list/audit, and doctor commands still run with invalid config."
 *
 * That is why the operator in #221 followed doctor's advice for five days: the
 * commands did not say they were refusing, so nothing pointed at the cause.
 *
 * THE VERDICT IS THREE-STATE, AND THAT IS THE WHOLE DESIGN.
 *
 * Suppressing a remedy is destructive — if we are wrong, we hide the advice
 * that would have fixed the host. So only a PROVEN-invalid config suppresses
 * anything; every uncertainty resolves to `indeterminate` and changes nothing.
 * Each of these was measured, and each would otherwise be a false red:
 *
 *   - no config file        → OpenClaw exits 1 with {"valid":false,"error":
 *                             "file not found"} and NO issues[]. A pure
 *                             exit-code gate calls an OpenClaw-less host
 *                             "config invalid".
 *   - binary absent         → spawnSync gives status: null + error.code
 *                             ENOENT, NOT 127 (127 is the shell path only).
 *                             The `status ?? 1` idiom used elsewhere collapses
 *                             this into "exit 1" — indistinguishable from a
 *                             genuinely invalid config.
 *   - timed out             → status null again, same trap.
 *   - warnings but valid    → exits 0. The dev box does this today with a
 *                             duplicate-plugin-id warning. Keying on output
 *                             text rather than exit code would report a
 *                             healthy host as broken.
 *
 * `--json` is deliberately NOT passed. It exists on 2026.7.1-2 and is tidier,
 * but an OpenClaw old enough not to know the flag exits non-zero with a usage
 * dump — manufacturing the exact false red this module exists to avoid. The
 * exit code of the bare command is the verdict; output is quoted detail only.
 */
import os from 'os';
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';

import { resolveOpenClawBinary } from '../setup/openclaw.js';
import { summariseCommandOutput } from './child-output.js';

export type OpenClawConfigVerdict =
  | { state: 'valid' }
  | { state: 'invalid'; detail: string[] }
  | { state: 'indeterminate'; reason: string };

export interface SpawnOutcome {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: NodeJS.ErrnoException;
  signal?: NodeJS.Signals | null;
}

export interface ValidateDeps {
  resolveBin?: (home: string) => string | null;
  configPath?: (home: string) => string;
  exists?: (target: string) => boolean;
  run?: (bin: string, home: string) => SpawnOutcome;
}

/**
 * ~7-10x the measured worst case (1.0-1.5 s on macOS arm64; cost is Node
 * startup and plugin registration, not config size, so valid and invalid
 * configs cost the same). Do not lower below 5 s — a cold start on a loaded
 * host would exceed it and manufacture a spurious "invalid" verdict.
 */
export const VALIDATE_TIMEOUT_MS = 10_000;

/**
 * The argv, exported so a test can pin it. `--json` must never be added: an
 * OpenClaw that does not know the flag exits non-zero with a usage dump.
 */
export const VALIDATE_ARGV = ['config', 'validate'] as const;

/**
 * OpenClaw positively asserting that the config is bad, in each shape it uses:
 * the human header, the JSON body, and a per-issue bullet. A non-zero exit
 * WITHOUT one of these is a CLI that did not understand us, not a broken config.
 */
const SAYS_INVALID = /config is invalid|"valid"\s*:\s*false|^\s*[×✗]\s/m;

/**
 * The CLI rejecting the COMMAND, as opposed to judging the config. This VETOES
 * the invalid verdict outright, because a bullet is weak evidence and a refusal
 * is strong: unrelated plugin stderr routinely carries `✗ …` lines, and one
 * landing alongside "Unknown command" would otherwise convict a healthy config
 * on an OpenClaw that simply does not have `config validate`.
 *
 * Checked BEFORE `SAYS_INVALID`, never after — the whole point is that it wins.
 */
const SAYS_REFUSED = /unknown command|too many arguments|unknown option|unrecognized (command|option)|could ?not start the cli/i;

export function defaultConfigPath(home: string): string {
  return process.env.OPENCLAW_CONFIG_PATH?.trim() || path.join(home, '.openclaw', 'openclaw.json');
}

function defaultRun(bin: string, home: string): SpawnOutcome {
  const r = spawnSync(bin, [...VALIDATE_ARGV], {
    encoding: 'utf-8',
    timeout: VALIDATE_TIMEOUT_MS,
    // stdin closed: a child that decided to prompt gets EOF rather than
    // blocking doctor forever.
    stdio: ['ignore', 'pipe', 'pipe'],
    // HOME threaded through, like every sibling spawn in the codebase — the
    // verdict must describe the same account the checks it gates are about.
    env: { ...process.env, HOME: home },
  });
  return {
    status: r.status,
    stdout: r.stdout ?? '',
    stderr: r.stderr ?? '',
    error: r.error as NodeJS.ErrnoException | undefined,
    signal: r.signal,
  };
}

/**
 * Determine whether OpenClaw's CLI will accept plugin/skill subcommands.
 *
 * Read-only: `config validate` mutates nothing, which is why this is safe to
 * run from `doctor` without a repair-consent prompt.
 */
export function validateOpenClawConfig(
  home: string = os.homedir(),
  deps: ValidateDeps = {},
): OpenClawConfigVerdict {
  const exists = deps.exists ?? ((target: string) => fs.existsSync(target));
  const configPath = (deps.configPath ?? defaultConfigPath)(home);

  // Cheapest fail-open first, and it sidesteps the file-not-found trap above.
  if (!exists(configPath)) {
    return { state: 'indeterminate', reason: 'OpenClaw not configured on this host' };
  }

  // `resolveOpenClawBinary`, not a bare command name: a bare `openclaw` is
  // invisible to non-interactive shells on part of the fleet (#146).
  const bin = (deps.resolveBin ?? resolveOpenClawBinary)(home);
  if (!bin) return { state: 'indeterminate', reason: 'openclaw binary not found' };

  // Never spawn a real subprocess from the test runner. Mapped to
  // indeterminate rather than to a status — inheriting a hard-fail here would
  // report every CI host as config-broken.
  if (!deps.run && process.env.JEST_WORKER_ID !== undefined) {
    return { state: 'indeterminate', reason: 'skipped under test runner' };
  }

  let r: SpawnOutcome;
  try {
    r = (deps.run ?? defaultRun)(bin, home);
  } catch (err) {
    return {
      state: 'indeterminate',
      reason: `could not run \`openclaw config validate\` (${(err as Error).message})`,
    };
  }

  if (r.error?.code === 'ENOENT') {
    return { state: 'indeterminate', reason: 'openclaw binary disappeared before it could run' };
  }
  if (r.error?.code === 'ETIMEDOUT' || r.signal) {
    return { state: 'indeterminate', reason: `\`openclaw config validate\` did not finish within ${VALIDATE_TIMEOUT_MS / 1000}s` };
  }
  if (r.status === null) {
    return { state: 'indeterminate', reason: '`openclaw config validate` did not report an exit code' };
  }

  // Exit 0 is ALWAYS valid, whatever the output says. That one-way rule is what
  // keeps a warnings-but-valid config out of the invalid arm, and it is not
  // weakened below: output is consulted only to DOWNGRADE a non-zero result.
  if (r.status === 0) return { state: 'valid' };

  // A non-zero exit is not proof of an invalid config.
  //
  // Measured on 2026.7.1-2: `openclaw config <unknown-sub>` exits 1 with
  // "Too many arguments for this command.", and `openclaw <unknown-cmd>` exits
  // 1 with "Unknown command: …". An OpenClaw predating `config validate`
  // answers exactly like that — so keying on the exit code alone would report a
  // HEALTHY host as config-broken and then strip every remedy doctor has,
  // including the one on a check whose own message says the gateway is running
  // with no memory firewall and no action guard.
  //
  // That is #221 inverted, and strictly worse than the bug it fixes. This
  // module's header already rejects `--json` for this exact reason; the same
  // argument applies to the subcommand itself. So: require OpenClaw to SAY the
  // config is invalid. Anything else fails open.
  const blob = `${r.stderr}\n${r.stdout}`;
  if (SAYS_REFUSED.test(blob) || !SAYS_INVALID.test(blob)) {
    return {
      state: 'indeterminate',
      reason: '`openclaw config validate` is not supported by this OpenClaw',
    };
  }

  // Invalid: stdout is empty and everything goes to stderr, inverted from the
  // valid case — so prefer stderr but do not assume it.
  const { lines } = summariseCommandOutput(r.stderr || r.stdout, { maxLines: 4 });
  return {
    state: 'invalid',
    detail: lines.length > 0 ? lines : [`\`openclaw config validate\` exited ${r.status}`],
  };
}
