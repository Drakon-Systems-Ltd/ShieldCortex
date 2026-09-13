import { INTENSITY, loadIntensity, saveIntensity, type IntensityLevel } from '../intensity.js';

class FakeStorage {
  private store = new Map<string, string>();
  getItem(k: string) { return this.store.get(k) ?? null; }
  setItem(k: string, v: string) { this.store.set(k, v); }
  removeItem(k: string) { this.store.delete(k); }
  clear() { this.store.clear(); }
  get length() { return this.store.size; }
  key(i: number) { return Array.from(this.store.keys())[i] ?? null; }
}

describe('INTENSITY', () => {
  it('exposes the documented values for each level', () => {
    expect(INTENSITY.subtle.breathPeriod).toBe(6000);
    expect(INTENSITY.subtle.particleCap).toBe(20);
    expect(INTENSITY.moderate.breathPeriod).toBe(3000);
    expect(INTENSITY.moderate.particleCap).toBe(60);
    expect(INTENSITY.strong.breathPeriod).toBe(1600);
    expect(INTENSITY.strong.particleCap).toBe(120);
  });
});

describe('loadIntensity', () => {
  it('returns moderate when no storage is available (SSR / node)', () => {
    expect(loadIntensity(undefined)).toBe<IntensityLevel>('moderate');
  });

  it('returns moderate when storage is empty', () => {
    const s = new FakeStorage();
    expect(loadIntensity(s)).toBe('moderate');
  });

  it.each(['subtle', 'moderate', 'strong'] as const)('returns %s when stored', (level) => {
    const s = new FakeStorage();
    s.setItem('shieldcortex.graph.intensity', level);
    expect(loadIntensity(s)).toBe(level);
  });

  it('falls back to moderate on invalid stored value', () => {
    const s = new FakeStorage();
    s.setItem('shieldcortex.graph.intensity', 'bogus');
    expect(loadIntensity(s)).toBe('moderate');
  });
});

describe('saveIntensity', () => {
  it('persists the level under the documented key', () => {
    const s = new FakeStorage();
    saveIntensity('strong', s);
    expect(s.getItem('shieldcortex.graph.intensity')).toBe('strong');
  });

  it('no-ops when storage is undefined', () => {
    expect(() => saveIntensity('strong', undefined)).not.toThrow();
  });
});
