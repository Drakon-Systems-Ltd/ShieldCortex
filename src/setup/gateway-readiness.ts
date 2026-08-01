/**
 * ShieldCortex — wait for the gateway you just restarted (#156).
 *
 * Field report, 1 Aug 2026. An operator ran repair on a host that needed a
 * pinned reinstall. Every step succeeded. Repair then printed:
 *
 *   ✗ FAILED: could not confirm the plugin is loaded AND enforcing.
 *   version proof FAILED: on-disk build 4.47.22 is OLDER than expected 4.47.24
 *
 * `shieldcortex doctor`, seconds later, on the same box: v4.47.24 current,
 * running matches on-disk, 29 of 32 checks green. The remediation had worked.
 *
 * The cause is a race of my own making. #145 correctly made repair re-read the
 * state after remediating instead of echoing its pre-remediation snapshot — but
 * `restartOpenClawGateway()` returns as soon as the service manager has STARTED
 * the process, not when the gateway has finished booting and registering its
 * plugins. So the re-read raced the very thing it was re-reading, saw the old
 * world, and called a success a failure.
 *
 * A false FAILED is not a cosmetic defect. It sends an operator to re-remediate
 * a healthy box, and it is the precise failure mode this codebase has spent a
 * week eliminating — shipped, this time, by the fix for the previous one.
 *
 * So: after a restart, wait until the gateway PROVES it is the new process
 * (a boot-lifecycle row whose start postdates the restart, with a live pid)
 * before believing anything read afterwards. Bounded, and honest when it times
 * out — "not proven ready" is a different claim from "broken", and the caller
 * must be able to tell them apart.
 */
import { readRunningGatewayProcess, type RunningGatewayProcess } from '../integrations/openclaw-gateway-process.js';

export interface WaitForGatewayOptions {
  /** Only a process started at/after this instant counts as the new one. */
  startedAfterMs: number;
  /** Give up after this long. Default 30s — a cold boot with many plugins. */
  timeoutMs?: number;
  /** Gap between polls. Default 500ms. */
  pollMs?: number;
  /** Injectable clock, so tests never actually sleep. */
  now?: () => number;
  /** Injectable sleep. */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable process reader. */
  readProcess?: () => RunningGatewayProcess | null;
}

export type GatewayReadiness =
  | { ready: true; process: RunningGatewayProcess; waitedMs: number }
  /**
   * Not proven ready. Deliberately NOT "broken": on a host where the
   * boot-lifecycle table is unavailable we cannot bound the evidence at all,
   * and saying "failed" there would be the same overreach as the false
   * UNPROTECTED in #142.
   */
  | { ready: false; reason: 'timeout' | 'unobservable'; waitedMs: number };

const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_POLL_MS = 500;

/**
 * Block until the gateway that started after `startedAfterMs` is up, or the
 * budget expires.
 *
 * "Up" means OpenClaw's own boot-lifecycle table records a process whose start
 * postdates the restart AND whose pid is alive. A row alone is not enough — a
 * recorded boot whose process has since exited proves nothing about now.
 */
export async function waitForGatewayReady(options: WaitForGatewayOptions): Promise<GatewayReadiness> {
  // Never actually wait under a test runner. Same discipline as every other
  // gateway-touching path here (restart, reconcile, canary): a suite must not
  // poll a live host, and without this the default waiter blocks each test for
  // the full timeout. Tests that mean to exercise the loop inject the seams.
  if (process.env.JEST_WORKER_ID !== undefined && !options.readProcess) {
    return { ready: false, reason: 'unobservable', waitedMs: 0 };
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = options.pollMs ?? DEFAULT_POLL_MS;
  const now = options.now ?? (() => Date.now());
  const sleep = options.sleep ?? ((ms: number) => new Promise<void>(r => setTimeout(r, ms)));
  const readProcess = options.readProcess ?? (() => readRunningGatewayProcess(process.env.HOME ?? ''));

  const began = now();
  let sawAnyProcess = false;

  for (;;) {
    const proc = readProcess();
    if (proc) {
      sawAnyProcess = true;
      if (proc.startedAtMs >= options.startedAfterMs) {
        return { ready: true, process: proc, waitedMs: now() - began };
      }
    }
    const waitedMs = now() - began;
    if (waitedMs >= timeoutMs) {
      // Never observing ANY process is a different fact from observing an old
      // one that never turned over: the first means we cannot see, the second
      // means it did not restart. Only the second is evidence of a problem.
      return { ready: false, reason: sawAnyProcess ? 'timeout' : 'unobservable', waitedMs };
    }
    await sleep(pollMs);
  }
}
