import { render, screen, fireEvent } from '@testing-library/react';
import { CardError } from '@/components/ds/CardError';

describe('CardError', () => {
  it('renders the message with an alert role', () => {
    render(<CardError message="Boom" />);
    expect(screen.getByRole('alert')).toHaveTextContent('Boom');
  });

  it('shows a Retry button that calls onRetry', () => {
    const onRetry = jest.fn();
    render(<CardError message="Boom" onRetry={onRetry} />);
    fireEvent.click(screen.getByText('Retry'));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('omits Retry when no handler is given', () => {
    render(<CardError message="Boom" />);
    expect(screen.queryByText('Retry')).toBeNull();
  });
});
