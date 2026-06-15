import { render, screen } from '@testing-library/react';
import { Badge, riskVariant } from '@/components/ds/Badge';

/**
 * Phase 0 smoke test — proves the dashboard test net works end-to-end:
 * jsdom render + React Testing Library + jest-dom matchers + the `@/` alias +
 * Next's SWC tsx transform. Later phases build real component/hook coverage on
 * top of this foundation.
 */
describe('Badge (test-net smoke)', () => {
  it('renders its children', () => {
    render(<Badge variant="critical">BLOCK</Badge>);
    expect(screen.getByText('BLOCK')).toBeInTheDocument();
  });

  it('renders an aria-hidden status dot when dot is set', () => {
    const { container } = render(<Badge variant="safe" dot>ALLOW</Badge>);
    expect(screen.getByText('ALLOW')).toBeInTheDocument();
    expect(container.querySelector('span[aria-hidden]')).toBeTruthy();
  });
});

describe('riskVariant', () => {
  it('maps risk-level strings to badge variants (case-insensitive, unknown → info)', () => {
    expect(riskVariant('CRITICAL')).toBe('critical');
    expect(riskVariant('high')).toBe('high');
    expect(riskVariant('SAFE')).toBe('safe');
    expect(riskVariant('whatever')).toBe('info');
  });
});
