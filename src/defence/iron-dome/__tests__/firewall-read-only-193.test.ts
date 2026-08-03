import { describe, it, expect } from '@jest/globals';
import { evaluateToolCall } from '../tool-action-guard.js';

/**
 * Issue #193 — `modify-network-firewall` matched the TOOL, never the verb.
 *
 * `ufw status`, `iptables -L`, `firewall-cmd --state` and `netplan get` read
 * state and change nothing, and every one of them gated exactly as hard as
 * `ufw disable`. Reported by Friday from Friday-Mac, where a read-only
 * firewall status check in a security sweep tripped a *modify* rule.
 *
 * Fail-closed: relief applies only where every firewall invocation is
 * positively recognised as read-only.
 */
const sig = (command: string): string[] =>
  evaluateToolCall('Bash', { command }, undefined, undefined).signals;

const FW = 'modify-network-firewall';

describe('#193 — reading firewall state is not modifying it', () => {
  it.each([
    'ufw status',
    'ufw status verbose',
    'ufw show raw',
    'iptables -L',
    'iptables -S',
    'iptables -L -n -v',
    'iptables -t nat -L -n',
    'iptables -Lnv',
    'ip6tables --list-rules',
    'firewall-cmd --state',
    'firewall-cmd --list-all --zone=public',
    'firewall-cmd --get-services',
    'nft list ruleset',
    'netplan get',
    'netplan status',
  ])('reads state, no gate: %s', cmd => {
    expect(sig(cmd)).not.toContain(FW);
  });

  it.each([
    'ufw disable',
    'ufw allow 22',
    'ufw --force reset',
    'iptables -F',
    'iptables -A INPUT -j DROP',
    'iptables -D INPUT 1',
    'iptables -P INPUT DROP',
    'iptables -Z',                      // zeroes counters — a write, however small
    'iptables -L -n; iptables -F',      // one writer anywhere keeps the gate
    'firewall-cmd --add-port=80/tcp',
    'firewall-cmd --reload',
    'nft flush ruleset',
    'nft add rule inet filter input drop',
    'netplan apply',
    'iptables-restore < rules.v4',
  ])('changes state, still gates: %s', cmd => {
    expect(sig(cmd)).toContain(FW);
  });

  it.each([
    'iptables',                          // bare — do not guess what it would do
    'iptables --brand-new-flag -L',      // one unrecognised flag and the gate holds
    'ufw logging on',                    // unlisted subcommand
    'nft -f rules.nft',                  // loads a ruleset
    'firewall-cmd --state --add-port=80/tcp',
  ])('fails closed on a shape it does not positively recognise: %s', cmd => {
    expect(sig(cmd)).toContain(FW);
  });

  it('never reaches the predicate for a quoted mention', () => {
    // `echo "ufw disable"` carries no signal at all — the quoted-data-arg
    // classifier (#84/#89) drops it upstream as a mention. Recorded so the
    // absence is understood as prior art, not as this fix over-reaching.
    expect(sig('echo "run ufw disable later" > /tmp/note')).toEqual([]);
  });

  it('leaves privilege-escalation alone on a sudo status check', () => {
    const s = sig('sudo ufw status');
    expect(s).not.toContain(FW);
    expect(s).toContain('privilege-escalation');
  });
});
