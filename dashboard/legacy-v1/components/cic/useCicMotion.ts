'use client';

import { useSyncExternalStore } from 'react';
import { cicShouldAnimate, isCalm, setCalm } from '@/lib/cic/motion';

/**
 * React binding for the CIC motion gate. Re-renders when the calm toggle or the
 * OS reduced-motion preference changes, so effects switch on/off live.
 */
function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  const mql = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  mql?.addEventListener?.('change', onChange);
  window.addEventListener('cic-calm-change', onChange);
  window.addEventListener('storage', onChange);
  return () => {
    mql?.removeEventListener?.('change', onChange);
    window.removeEventListener('cic-calm-change', onChange);
    window.removeEventListener('storage', onChange);
  };
}

export function useCicMotion(): { animate: boolean; calm: boolean; setCalm: (v: boolean) => void } {
  const animate = useSyncExternalStore(subscribe, cicShouldAnimate, () => true);
  const calm = useSyncExternalStore(subscribe, isCalm, () => false);
  return { animate, calm, setCalm };
}
