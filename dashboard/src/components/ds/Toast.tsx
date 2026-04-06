'use client';

import { Toaster } from 'sonner';

export function ToastProvider() {
  return (
    <Toaster
      position="bottom-right"
      toastOptions={{
        style: {
          background: 'var(--sc-bg-surface)',
          border: '1px solid var(--sc-border)',
          color: 'var(--sc-text-primary)',
          fontFamily: 'system-ui, sans-serif',
        },
      }}
      theme="dark"
    />
  );
}
