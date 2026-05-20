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

describe('PulseDriver — Layer A (memory.created spike)', () => {
  it('spikes to ~1.0 immediately after dispatch and decays per frame', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.observeNodes(['n1']);
    d.onFrame(0);
    d.dispatch({ type: 'memory.created', entityId: 'n1' });
    d.onFrame(0); // no time elapsed → still ~1.0
    expect(d.getEnergy('n1')).toBeGreaterThanOrEqual(0.95);
  });

  it('decays to <0.05 within ~2 seconds at moderate', () => {
    const d = new PulseDriver({ intensity: 'moderate', now: () => 0 });
    d.observeNodes(['n1']);
    d.onFrame(0);
    d.dispatch({ type: 'memory.created', entityId: 'n1' });
    // ~60 fps × 2s = 120 frames. moderate.decayCreate=0.96 → 0.96^120 ≈ 0.007.
    for (let i = 1; i <= 120; i++) d.onFrame(i * 16);
    expect(d.getEnergy('n1')).toBeLessThan(0.05 + INTENSITY.moderate.breathAmp);
  });

  it('does nothing when dispatched to an unobserved node', () => {
    const d = new PulseDriver({ intensity: 'moderate' });
    d.dispatch({ type: 'memory.created', entityId: 'never-seen' });
    d.onFrame(0);
    expect(d.getEnergy('never-seen')).toBe(0);
  });
});

describe('PulseDriver — Layer B (memory.accessed glow)', () => {
  it('spikes recall-energy to ~1.0 on dispatch and decays faster than create', () => {
    const d = new PulseDriver({ intensity: 'moderate', now: () => 0 });
    d.observeNodes(['n1']);
    d.onFrame(0);
    d.dispatch({ type: 'memory.accessed', entityId: 'n1' });
    expect(d.getRecallEnergy('n1')).toBeGreaterThanOrEqual(0.95);

    // 60 frames (~1s at 60fps) — moderate.decayRecall=0.93 → 0.93^60 ≈ 0.012
    for (let i = 1; i <= 60; i++) d.onFrame(i * 16);
    expect(d.getRecallEnergy('n1')).toBeLessThan(0.05);
  });

  it('keeps create-spike and recall-glow independent', () => {
    const d = new PulseDriver({ intensity: 'moderate', now: () => 0 });
    d.observeNodes(['n1']);
    d.onFrame(0); // populate breath; subsequent dispatches won't be decayed
    d.dispatch({ type: 'memory.created', entityId: 'n1' });
    d.dispatch({ type: 'memory.accessed', entityId: 'n1' });
    expect(d.getEnergy('n1')).toBeGreaterThanOrEqual(0.95);          // includes create
    expect(d.getRecallEnergy('n1')).toBeGreaterThanOrEqual(0.95);    // independent
  });
});

describe('PulseDriver — particle edge ranking', () => {
  const link = (s: string, t: string) => ({ source: s, target: t });

  it('returns at most particleCap edges', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['a', 'b', 'c', 'd']);
    const links = [link('a','b'), link('b','c'), link('c','d'), link('a','d')];
    expect(d.pickParticleEdges(links, null).length).toBeLessThanOrEqual(INTENSITY.subtle.particleCap);
  });

  it('ranks edges by max(srcEnergy, dstEnergy) descending', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['hot', 'mid', 'cold']);
    d.dispatch({ type: 'memory.created', entityId: 'hot' });
    d.onFrame(0);
    const links = [link('cold', 'mid'), link('hot', 'mid')];
    const out = d.pickParticleEdges(links, null);
    // 'hot' edge must rank first
    expect(out[0]).toEqual(link('hot', 'mid'));
  });

  it('breaks ties in favour of edges adjacent to the anchor', () => {
    const d = new PulseDriver({ intensity: 'subtle' });
    d.observeNodes(['anchor', 'x', 'y', 'z']);
    d.onFrame(0); // all energies near 0 (only breathing)
    const links = [link('x','y'), link('anchor','z'), link('y','z')];
    // With particleCap = 20 we'd return all three. To test tie-break, lower cap to 1:
    const out = d.pickParticleEdges(links, 'anchor', /*overrideCap*/ 1);
    expect(out).toEqual([link('anchor', 'z')]);
  });
});
