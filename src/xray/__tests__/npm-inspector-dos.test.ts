/**
 * DoS-hardening tests for the deep npm tarball scan (Phase 17 C2).
 *
 * A hostile package can ship a tiny .tgz that decompresses to gigabytes
 * (gzip bomb), redirect a fetch in an endless loop, or pack an absurd number
 * of entries. These tests prove the caps trip without needing a real 100 MB
 * tarball or a TLS server.
 */
import { describe, it, expect } from '@jest/globals';
import { Readable } from 'node:stream';
import { createGunzip, gzipSync } from 'node:zlib';
import {
  collectDecompressed,
  nextRedirectBudget,
} from '../npm-inspector.js';

describe('redirect bound (C2)', () => {
  it('allows hops while budget remains', () => {
    expect(nextRedirectBudget(5)).toBe(4);
    expect(nextRedirectBudget(1)).toBe(0);
  });

  it('rejects once the redirect cap is exhausted', () => {
    // A chain longer than the cap drains the budget to 0, after which the
    // next hop returns null → httpsGet/downloadTarball reject "too many
    // redirects" instead of recursing forever.
    expect(nextRedirectBudget(0)).toBeNull();
    expect(nextRedirectBudget(-1)).toBeNull();
  });

  it('a redirect chain longer than N hops is bounded by N decrements', () => {
    // Simulate following a chain: starting from a budget of 3, only 3 hops
    // are permitted before the 4th is refused.
    let budget: number | null = 3;
    let hops = 0;
    while ((budget = nextRedirectBudget(budget!)) !== null) {
      hops++;
      if (hops > 100) break; // safety: must terminate, not loop forever
    }
    expect(hops).toBe(3);
  });
});

describe('decompressed-size guard (C2)', () => {
  it('trips when the inflated stream exceeds the cap (gzip-bomb guard)', async () => {
    // Tiny on the wire, large when inflated: 2 MB of zeros gzips to a few KB.
    const inflated = Buffer.alloc(2 * 1024 * 1024, 0);
    const compressed = gzipSync(inflated);
    expect(compressed.length).toBeLessThan(inflated.length); // genuinely a "bomb" shape

    const gunzip = createGunzip();
    Readable.from(compressed).pipe(gunzip);

    // Cap WELL below the inflated size → must abort.
    await expect(collectDecompressed(gunzip, 64 * 1024)).rejects.toThrow(/gzip bomb|cap/i);
  });

  it('returns the buffer when under the cap', async () => {
    const inflated = Buffer.from('hello world — small and safe');
    const gunzip = createGunzip();
    Readable.from(gzipSync(inflated)).pipe(gunzip);

    const out = await collectDecompressed(gunzip, 1024 * 1024);
    expect(out.toString()).toBe(inflated.toString());
  });

  it('aborts a fake stream that streams past the limit without buffering it all', async () => {
    // Fake stream that would emit far more than the cap; the guard must stop
    // early rather than concat an unbounded buffer.
    let destroyed = false;
    const chunk = Buffer.alloc(1024, 1);
    const fake = {
      _dataCb: undefined as undefined | ((c: Buffer) => void),
      _endCb: undefined as undefined | (() => void),
      on(event: string, cb: (...args: unknown[]) => void) {
        if (event === 'data') {
          this._dataCb = cb as (c: Buffer) => void;
          // Emit synchronously past the cap on the next tick.
          queueMicrotask(() => {
            for (let i = 0; i < 100 && !destroyed; i++) this._dataCb!(chunk);
            if (!destroyed) this._endCb?.();
          });
        } else if (event === 'end') {
          this._endCb = cb as () => void;
        }
        return this;
      },
      destroy() {
        destroyed = true;
      },
    };

    await expect(collectDecompressed(fake as never, 4 * 1024)).rejects.toThrow(/cap/i);
    expect(destroyed).toBe(true);
  });
});
