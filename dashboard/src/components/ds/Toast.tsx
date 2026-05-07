'use client';

import { Toaster } from 'sonner';
import { useTheme } from '@/hooks/useTheme';

export function ToastProvider() {
  const [theme] = useTheme();
  const isGlass = theme === 'glass';

  return (
    <Toaster
      position="bottom-right"
      toastOptions={{
        style: isGlass
          ? {
              background: 'var(--sc-bg-surface)',
              border: '1px solid var(--sc-border)',
              color: 'var(--sc-text-primary)',
              fontFamily: 'system-ui, sans-serif',
            }
          : {
              background: 'var(--term-surface)',
              border: '1px solid var(--term-border)',
              color: 'var(--term-text)',
              fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
              fontSize: '13px',
              borderRadius: '6px',
            },
      }}
      theme="dark"
    />
  );
}
