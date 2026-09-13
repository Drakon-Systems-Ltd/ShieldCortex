'use client';

import { Toaster } from 'sonner';
import { useResolvedTheme } from '@/hooks/useTheme';

export function ToastProvider() {
  const resolved = useResolvedTheme();

  return (
    <Toaster
      position="bottom-right"
      theme={resolved}
      toastOptions={{
        style: {
          background: 'var(--sc-surface)',
          border: '1px solid var(--sc-border)',
          color: 'var(--sc-text)',
          fontSize: '13px',
          borderRadius: '8px',
        },
      }}
    />
  );
}
