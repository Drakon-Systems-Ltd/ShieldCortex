import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeToggle } from './ThemeToggle';

describe('ThemeToggle', () => {
  afterEach(() => {
    document.documentElement.removeAttribute('data-theme');
    try {
      localStorage.clear();
    } catch {
      /* ignore */
    }
  });

  it('in glass, offers to switch to terminal and switches on click', () => {
    document.documentElement.setAttribute('data-theme', 'glass');
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole('button', { name: /switch to terminal/i }));
    expect(document.documentElement.getAttribute('data-theme')).toBe('terminal');
  });

  it('in terminal, offers to switch to glass and switches on click', () => {
    document.documentElement.setAttribute('data-theme', 'terminal');
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole('button', { name: /switch to glass/i }));
    expect(document.documentElement.getAttribute('data-theme')).toBe('glass');
  });

  it('persists the choice to localStorage so it survives reload', () => {
    document.documentElement.setAttribute('data-theme', 'glass');
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole('button', { name: /switch to terminal/i }));
    expect(localStorage.getItem('sc-theme')).toBe('terminal');
  });
});
