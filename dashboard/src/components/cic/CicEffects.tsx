'use client';

import { useEffect, useState } from 'react';
import { useCicMotion } from './useCicMotion';

const BOOT_TEXT = 'SHIELDCORTEX // CIC ONLINE';
const BOOT_KEY = 'sc-cic-booted';

/**
 * The CIC immersive effects layer: a fixed scanline + slow phosphor sweep over
 * the void, plus a one-shot boot sequence on first load of a session. All motion
 * is gated by the CIC motion policy (calm toggle / prefers-reduced-motion) —
 * static scanlines remain, the sweep and type-on do not.
 *
 * Mounted once at the app root. Purely decorative (aria-hidden, pointer-events
 * none); never blocks interaction once the brief boot overlay dismisses.
 */
export function CicEffects() {
  const { animate } = useCicMotion();
  const [mounted, setMounted] = useState(false);
  const [booting, setBooting] = useState(false);
  const [typed, setTyped] = useState('');

  // Mount flag avoids an SSR/client hydration mismatch on the boot overlay.
  useEffect(() => setMounted(true), []);

  // Mirror the motion decision onto <html> so CSS can still ALL ambient motion
  // (cursor blink, status pulses, sweep) under the calm toggle — a CSS media
  // query can only see the OS reduced-motion preference, not the in-app toggle.
  useEffect(() => {
    document.documentElement.setAttribute('data-cic-motion', animate ? 'on' : 'off');
  }, [animate]);

  useEffect(() => {
    if (!mounted) return;
    let alreadyBooted = false;
    try {
      alreadyBooted = sessionStorage.getItem(BOOT_KEY) === '1';
    } catch {
      /* sessionStorage unavailable */
    }
    if (alreadyBooted) return;
    try {
      sessionStorage.setItem(BOOT_KEY, '1');
    } catch {
      /* ignore */
    }

    setBooting(true);
    if (!animate) {
      setTyped(BOOT_TEXT);
      const done = setTimeout(() => setBooting(false), 200);
      return () => clearTimeout(done);
    }

    let i = 0;
    const typer = setInterval(() => {
      i += 1;
      setTyped(BOOT_TEXT.slice(0, i));
      if (i >= BOOT_TEXT.length) {
        clearInterval(typer);
        setTimeout(() => setBooting(false), 600);
      }
    }, 45);
    return () => clearInterval(typer);
  }, [mounted, animate]);

  if (!mounted) return null;

  return (
    <>
      <div aria-hidden className="cic-fx" data-animate={animate ? '1' : '0'} />
      {booting && (
        <div aria-hidden className="cic-boot" onClick={() => setBooting(false)}>
          <span className="cic-boot-line">
            {typed}
            <span className="cli-cursor" />
          </span>
        </div>
      )}
    </>
  );
}
