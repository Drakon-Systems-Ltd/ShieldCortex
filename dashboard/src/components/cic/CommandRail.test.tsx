import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CommandRail } from './CommandRail';
import type { CommandContext } from '@/lib/commands/registry';

const mockCtx: CommandContext = {
  navigate: jest.fn(),
  setTheme: jest.fn(),
  recall: jest.fn(async () => [{ id: 7, title: 'auth bug fix' }]),
  scan: jest.fn(async () => ({ target: '/a', riskLevel: 'SAFE', trustScore: 100, filesScanned: 3, findingsCount: 0 })),
  forget: jest.fn(async () => undefined),
  consolidate: jest.fn(async () => ({ consolidated: 1, decayed: 0, deleted: 0 })),
  routes: [
    { label: 'Memory', href: '/memory' },
    { label: 'Protection', href: '/protection' },
  ],
};

jest.mock('./useCommandContext', () => ({ useCommandContext: () => mockCtx }));

function type(value: string) {
  const input = screen.getByRole('textbox') as HTMLInputElement;
  fireEvent.change(input, { target: { value } });
  fireEvent.keyDown(input, { key: 'Enter' });
  return input;
}

describe('CommandRail', () => {
  beforeEach(() => jest.clearAllMocks());

  it('renders the prompt', () => {
    render(<CommandRail />);
    expect(screen.getByText(/sc ▸/)).toBeInTheDocument();
  });

  it('runs a real command: go protection navigates', async () => {
    render(<CommandRail />);
    type('go protection');
    await waitFor(() => expect(mockCtx.navigate).toHaveBeenCalledWith('/protection'));
  });

  it('echoes the command and shows output (help lists commands)', async () => {
    render(<CommandRail />);
    type('help');
    await waitFor(() => expect(screen.getByText('commands:')).toBeInTheDocument());
    // echo line is a div whose combined text is "sc ▸ help" (prefix span + text node)
    expect(
      screen.getByText((_content, el) => el?.tagName === 'DIV' && el.textContent === 'sc ▸ help'),
    ).toBeInTheDocument();
  });

  it('recall runs the adapter with the query', async () => {
    render(<CommandRail />);
    type('recall "auth bug"');
    await waitFor(() => expect(mockCtx.recall).toHaveBeenCalledWith('auth bug', undefined));
  });

  it('clears the input after submitting', async () => {
    render(<CommandRail />);
    const input = type('help');
    await waitFor(() => expect(input.value).toBe(''));
  });

  it('recalls the previous command with ArrowUp', async () => {
    render(<CommandRail />);
    const input = type('help') as HTMLInputElement;
    await waitFor(() => expect(input.value).toBe(''));
    fireEvent.keyDown(input, { key: 'ArrowUp' });
    expect(input.value).toBe('help');
  });
});
