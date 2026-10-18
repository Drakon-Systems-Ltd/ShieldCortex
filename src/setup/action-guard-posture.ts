/**
 * `shieldcortex setup` — the explicit Action Guard posture question (#509).
 *
 * Setup never turns the guard on by itself. In a terminal it ASKS, in plain
 * words, with three choices; pressing Enter keeps whatever is configured now.
 * Without a terminal it changes nothing (the default stays off) and prints how
 * to choose. Plain `enforce` is not offered here on purpose: an install that
 * wants enforcement from minute one can still say so with
 * `shieldcortex config --action-guard-enforce`. No choice is marked as the
 * recommended one (Addendum 1 F), and no choice is described as making the
 * machine safe or protected.
 */

import {
  actionGuardPosture,
  getActionGuardCoreConfig,
  getActionGuardNotifyConfig,
  setActionGuardCoreConfig,
  type ActionGuardPosture,
} from '../cloud/config.js';
import { PolicyLockRefusal } from '../defence/iron-dome/policy-lock.js';
import { initReadinessTransitions } from '../defence/iron-dome/guard-readiness.js';

export type PostureChoice = 'off' | 'watch-only' | 'enforce-when-ready';

/** #509 r7: Hermes does not implement the readiness gate (out of scope). */
export const HERMES_GATE_NOTE =
  'The Hermes plugin does not implement this gate: it ignores it and enforces immediately.';

export const POSTURE_CHOICES: ReadonlyArray<{ key: string; choice: PostureChoice; title: string; body: string }> = [
  {
    key: '1',
    choice: 'off',
    title: 'Off',
    body:
      'The Action Guard does not look at tool calls at all. Nothing is logged and nothing is stopped. ' +
      'This is the default and changes nothing about how your agents run today.',
  },
  {
    key: '2',
    choice: 'watch-only',
    title: 'Watch only',
    body:
      'The guard checks every tool call and writes what it thinks to the local audit log. ' +
      'Dangerous-but-sometimes-legitimate actions are logged as warnings and run. Some calls are still ' +
      'stopped or held for your approval, including the catastrophic tier (things like wiping a disk or ' +
      'piping a download into a shell) and calls the guard recognises as changing its own files (its config, ' +
      'approval and readiness records, decisions ledger) or as explicitly disabling it. It recognises these ' +
      'from the tool call itself, so a call that reaches those files some other way may not be caught. The ' +
      'Hermes plugin has no approval prompt, so there those calls are blocked.',
  },
  {
    key: '3',
    choice: 'enforce-when-ready',
    title: 'Enforce when ready',
    body:
      'Starts exactly like Watch only. It switches to enforcing — dangerous actions then need your approval ' +
      'or are blocked — only once three conditions hold. Two are measured from this machine\'s own audit log: ' +
      'the guard would have intervened on no more than 2% of real tool calls (at least 500 calls over at least ' +
      '7 days), and at least 98% of approval requests reached you and got an answer. These say the guard is ' +
      'workable to run here, not how well it stops attacks. The third is independently reviewed evidence that ' +
      'this version of the guard stops attacks. None has been published yet, so for now this choice keeps ' +
      'watching and does not enforce. It also needs a human approval channel (the OpenClaw approval card or a ' +
      'webhook) and a webhook that can carry a demotion notice; without them it never enforces. If a condition ' +
      'later fails it drops back to watching and tells ' +
      'you loudly. The gate applies to the Claude Code hook and to the OpenClaw plugin; each is measured on its ' +
      'own tool calls and switches to enforcing on its own. ' + HERMES_GATE_NOTE,
  },
];

const CURRENT_TEXT: Record<ActionGuardPosture, string> = {
  off: 'Off',
  'watch-only': 'Watch only',
  enforce: 'Enforce (always)',
  'enforce-when-ready': 'Enforce when ready',
};

export function describeChooseCommands(): string[] {
  return [
    'Action Guard: left as configured. Choose a posture any time:',
    '  shieldcortex config --action-guard-disable              # Off (the default)',
    '  shieldcortex config --action-guard-advisory             # Watch only',
    '  shieldcortex config --action-guard-enforce-when-ready   # Enforce when ready (needs an approval channel)',
    'Or re-run `shieldcortex setup` in a terminal to be asked.',
  ];
}

export interface PostureDeps {
  tty: boolean;
  ask: (question: string) => Promise<string>;
  log?: (line: string) => void;
  current?: () => ActionGuardPosture;
  apply?: (choice: PostureChoice) => void;
  channelConfigured?: () => boolean;
  webhookConfigured?: () => boolean;
}

function defaultApply(choice: PostureChoice): void {
  if (choice === 'off') setActionGuardCoreConfig({ enabled: false });
  else if (choice === 'watch-only') setActionGuardCoreConfig({ enabled: true, enforce: false, readinessGate: false });
  else {
    const previousPosture = actionGuardPosture(getActionGuardCoreConfig());
    setActionGuardCoreConfig({ enabled: true, enforce: true, readinessGate: true });
    // #509: start the durable transition record (a change of posture only).
    initReadinessTransitions({
      postureChanged: previousPosture !== 'enforce-when-ready',
      reason: `posture set to enforce-when-ready by \`shieldcortex setup\` (was ${previousPosture})`,
    });
  }
}

function defaultWebhookConfigured(): boolean {
  const n = getActionGuardNotifyConfig();
  return n.enabled && !!n.webhookUrl;
}

function defaultChannelConfigured(): boolean {
  const n = getActionGuardNotifyConfig();
  return n.enabled && (n.openclaw || !!n.webhookUrl);
}

/**
 * Ask (TTY) or explain (no TTY). Returns the choice applied, or null when
 * nothing changed.
 */
export async function offerActionGuardPosture(deps: PostureDeps): Promise<PostureChoice | null> {
  const log = deps.log ?? ((l: string) => console.log(l));
  if (!deps.tty) {
    log('');
    for (const line of describeChooseCommands()) log(line);
    return null;
  }
  const current = (deps.current ?? (() => actionGuardPosture(getActionGuardCoreConfig())))();
  log('');
  log('Action Guard — how should ShieldCortex treat what your agents DO (shell commands, file writes)?');
  log(`Currently: ${CURRENT_TEXT[current]}.`);
  for (const c of POSTURE_CHOICES) {
    log('');
    log(`  ${c.key}) ${c.title}`);
    log(`     ${c.body}`);
  }
  log('');
  const answer = (await deps.ask('Choose 1, 2 or 3 (Enter keeps the current setting): ')).trim().toLowerCase();
  const picked = POSTURE_CHOICES.find((c) => c.key === answer || c.choice === answer);
  if (!picked) {
    log(answer ? `Not a choice ("${answer}") — Action Guard left as ${CURRENT_TEXT[current]}.` : `Action Guard left as ${CURRENT_TEXT[current]}.`);
    return null;
  }
  try {
    (deps.apply ?? defaultApply)(picked.choice);
  } catch (err) {
    if (err instanceof PolicyLockRefusal) {
      log(err.message);
      return null;
    }
    throw err;
  }
  log(`Action Guard set to: ${picked.title}.`);
  if (picked.choice === 'enforce-when-ready') {
    if (!(deps.channelConfigured ?? defaultChannelConfigured)()) {
      log('It will not enforce until you configure a human approval channel:');
      log('  shieldcortex config --action-guard-notify-openclaw        (approval card on your OpenClaw channel)');
      log('  shieldcortex config --action-guard-notify-webhook <url>   (one-way webhook)');
    }
    if (!(deps.webhookConfigured ?? defaultWebhookConfigured)()) {
      log('It will also not enforce without a webhook, which is how a later demotion reaches you (the OpenClaw card carries approvals only):');
      log('  shieldcortex config --action-guard-notify-webhook <url>');
    }
    log('Watch progress with: shieldcortex guard readiness   (add round-trips with: shieldcortex guard test-approval)');
    log(HERMES_GATE_NOTE);
  }
  return picked.choice;
}
