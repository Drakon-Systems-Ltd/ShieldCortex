/**
 * Tests for Positive Feedback Capture (v4.0.0)
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { existsSync, unlinkSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';

describe('Cortex Confirmations', () => {
  const confirmationsFile = join(
    process.env.SHIELDCORTEX_CONFIG_DIR || join(homedir(), '.shieldcortex'),
    'cortex',
    'confirmations.json'
  );

  beforeEach(() => {
    // Clean up confirmations file before each test
    if (existsSync(confirmationsFile)) {
      unlinkSync(confirmationsFile);
    }
  });

  it('should capture a confirmation', async () => {
    const { captureConfirmation } = await import('../cortex/store.js');
    const confirmation = captureConfirmation({
      category: 'code',
      what: 'Used strict TypeScript config',
      whyItWorked: 'Caught 3 type errors before runtime',
      whenToRepeat: 'Always enable strict mode in new TS projects',
    });
    expect(confirmation.id).toBe(1);
    expect(confirmation.what).toBe('Used strict TypeScript config');
    expect(confirmation.whyItWorked).toBe('Caught 3 type errors before runtime');
    expect(confirmation.whenToRepeat).toBe('Always enable strict mode in new TS projects');
    expect(confirmation.category).toBe('code');
  });

  it('should persist and load confirmations', async () => {
    const { captureConfirmation, loadConfirmations } = await import('../cortex/store.js');
    captureConfirmation({
      category: 'design',
      what: 'Event-driven architecture',
      whyItWorked: 'Decoupled components cleanly',
      whenToRepeat: 'When building distributed systems',
    });
    const loaded = loadConfirmations();
    expect(loaded.length).toBe(1);
    expect(loaded[0].what).toBe('Event-driven architecture');
  });

  it('should search confirmations by query', async () => {
    const { captureConfirmation, searchConfirmations } = await import('../cortex/store.js');
    captureConfirmation({
      category: 'code',
      what: 'Used ESM modules',
      whyItWorked: 'Better tree-shaking',
      whenToRepeat: 'For all new Node.js projects',
    });
    captureConfirmation({
      category: 'process',
      what: 'Code review before merge',
      whyItWorked: 'Caught a security issue',
      whenToRepeat: 'Always require review for PRs',
    });
    const results = searchConfirmations('security');
    expect(results.length).toBe(1);
    expect(results[0].what).toBe('Code review before merge');
  });
});
