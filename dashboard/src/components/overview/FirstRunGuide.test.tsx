import { render, screen } from '@testing-library/react';
import { FirstRunGuide } from './FirstRunGuide';

describe('FirstRunGuide', () => {
  it('renders nothing while stats are still loading (not ready)', () => {
    const { container } = render(
      <FirstRunGuide ready={false} memoryCount={0} scanCount={0} blockedCount={0} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing once there are stored memories', () => {
    const { container } = render(
      <FirstRunGuide ready memoryCount={5} scanCount={0} blockedCount={0} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it('renders nothing if there has been any scan or blocked activity', () => {
    const withScans = render(
      <FirstRunGuide ready memoryCount={0} scanCount={3} blockedCount={0} />,
    );
    expect(withScans.container).toBeEmptyDOMElement();

    const withBlocks = render(
      <FirstRunGuide ready memoryCount={0} scanCount={0} blockedCount={2} />,
    );
    expect(withBlocks.container).toBeEmptyDOMElement();
  });

  it('shows the positioning line + setup guidance on a genuinely fresh install', () => {
    render(<FirstRunGuide ready memoryCount={0} scanCount={0} blockedCount={0} />);
    // Positioning: dashboard = review, CLI = automation
    expect(screen.getByText(/visual review/i)).toBeInTheDocument();
    expect(screen.getByText(/automation/i)).toBeInTheDocument();
    // Setup guidance: how to generate data
    expect(screen.getByText(/shieldcortex scan/i)).toBeInTheDocument();
  });
});
