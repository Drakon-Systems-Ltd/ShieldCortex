import { PulseDriver } from '../pulse.js';
import { INTENSITY } from '../intensity.js';

describe('PulseDriver — breathing (Layer C)', () => {
  it('returns 0 energy for nodes the driver has never seen', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    expect(d.getEnergy('unknown')).toBe(0);
  });

  it('produces sinusoidal energy in [-amp, +amp] for known nodes', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.observeNodes(['n1', 'n2', 'n3']);
    const amp = INTENSITY.moderate.breathAmp;
    for (let t = 0; t <= 6000; t += 250) {
      d.onFrame(t);
      for (const id of ['n1', 'n2', 'n3']) {
        const e = d.getEnergy(id);
        expect(e).toBeGreaterThanOrEqual(-amp - 1e-9);
        expect(e).toBeLessThanOrEqual(amp + 1e-9);
      }
    }
  });

  it('phases breathing per-node so they are not in lock-step', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.observeNodes(['alpha', 'beta', 'gamma']);
    d.onFrame(750); // somewhere mid-cycle
    const energies = ['alpha', 'beta', 'gamma'].map((id) => d.getEnergy(id));
    // Three distinct values (none equal to any other) within 1e-6.
    const unique = new Set(energies.map((e) => Math.round(e * 1e6)));
    expect(unique.size).toBe(3);
  });

  it('returns 0 energy when intensity is "subtle" only after long zero baseline — sanity check on amplitude scaling', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['n1']);
    d.onFrame(0);
    expect(Math.abs(d.getEnergy('n1'))).toBeLessThanOrEqual(INTENSITY.subtle.breathAmp + 1e-9);
  });
});
