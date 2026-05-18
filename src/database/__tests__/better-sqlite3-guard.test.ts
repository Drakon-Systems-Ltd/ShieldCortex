import { describe, it, expect } from '@jest/globals';
import { formatNativeLoadError } from '../better-sqlite3-guard.js';

describe('formatNativeLoadError', () => {
  const nodeVersion = 'v25.8.0';
  const abi = '141';

  it('reports the detected Node version and ABI', () => {
    const msg = formatNativeLoadError(
      new Error("The module was compiled against NODE_MODULE_VERSION 127. This version requires 141."),
      nodeVersion,
      abi,
    );
    expect(msg).toContain('v25.8.0');
    expect(msg).toContain('141');
    expect(msg).toContain('better-sqlite3');
  });

  it('gives the exact rebuild remediation command', () => {
    const msg = formatNativeLoadError(new Error('ERR_DLOPEN_FAILED'), nodeVersion, abi);
    expect(msg).toContain('npm rebuild better-sqlite3');
  });

  it('points users at a supported Node LTS when on bleeding-edge Node', () => {
    const msg = formatNativeLoadError(new Error('Cannot find module better_sqlite3.node'), nodeVersion, abi);
    expect(msg.toLowerCase()).toContain('node');
    // Must name a concrete supported line, not just say "use LTS"
    expect(msg).toMatch(/\b(20|22)\b/);
  });

  it('preserves the underlying error text for debugging', () => {
    const msg = formatNativeLoadError(new Error('totally-unique-native-error-xyz'), nodeVersion, abi);
    expect(msg).toContain('totally-unique-native-error-xyz');
  });

  it('is a single actionable block, not a stack dump', () => {
    const msg = formatNativeLoadError(new Error('boom'), nodeVersion, abi);
    expect(msg).toContain('ShieldCortex');
    expect(msg.split('\n').length).toBeLessThan(20);
  });
});
