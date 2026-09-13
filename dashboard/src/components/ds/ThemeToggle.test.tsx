import { render, screen, fireEvent } from '@testing-library/react';
import { ThemeToggle } from './ThemeToggle';

describe('ThemeToggle', () => {
  afterEach(() => {
    document.documentElement.classList.remove('dark');
    try {
      localStorage.clear();
    } catch {
      /* ignore */
    }
  });

  it('cycles light → dark and applies the dark class', () => {
    localStorage.setItem('sc-theme', 'light');
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole('button', { name: /switch to dark/i }));
    expect(document.documentElement.classList.contains('dark')).toBe(true);
    expect(localStorage.getItem('sc-theme')).toBe('dark');
  });

  it('cycles dark → system', () => {
    localStorage.setItem('sc-theme', 'dark');
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole('button', { name: /switch to system/i }));
    expect(localStorage.getItem('sc-theme')).toBe('system');
  });

  it('migrates a legacy terminal preference to dark', () => {
    localStorage.setItem('sc-theme', 'terminal');
    render(<ThemeToggle />);
    // Legacy value renders as Dark; next in the cycle is System.
    expect(screen.getByRole('button', { name: /theme: dark/i })).toBeInTheDocument();
  });

  it('persists the choice to localStorage so it survives reload', () => {
    localStorage.setItem('sc-theme', 'system');
    render(<ThemeToggle />);
    fireEvent.click(screen.getByRole('button', { name: /switch to light/i }));
    expect(localStorage.getItem('sc-theme')).toBe('light');
  });
});
