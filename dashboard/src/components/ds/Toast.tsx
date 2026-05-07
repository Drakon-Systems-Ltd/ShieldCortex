'use client';

import { Toaster } from 'sonner';

export function ToastProvider() {
  return (
    <Toaster
      position="bottom-right"
      toastOptions={{
        style: {
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
