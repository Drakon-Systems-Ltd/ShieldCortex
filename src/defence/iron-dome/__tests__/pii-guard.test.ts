/**
 * Iron Dome — PII Guard Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import type { IronDomeConfig } from '../config.js';
import { DEFAULT_IRON_DOME_CONFIG, IRON_DOME_PROFILES } from '../config.js';

describe('PII Guard', () => {
  it('should pass clean content with no PII rules', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
    };
    const result = checkPII('The project uses TypeScript.', config);
    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('should detect never-output PII violations', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      piiRules: {
        neverOutput: ['date_of_birth', 'credit_card'],
        aggregatesOnly: [],
      },
    };
    const result = checkPII('Student date of birth: 15/03/2010', config);
    expect(result.allowed).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0].rule).toBe('never_output');
  });

  it('should flag aggregates-only categories', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      piiRules: {
        neverOutput: [],
        aggregatesOnly: ['attendance'],
      },
    };
    const result = checkPII('Student attendance: 95%', config);
    // aggregates_only violations don't block, they warn
    expect(result.allowed).toBe(true);
    expect(result.violations.length).toBeGreaterThan(0);
    expect(result.violations[0].rule).toBe('aggregates_only');
  });

  it('should detect credit card patterns', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      piiRules: {
        neverOutput: ['credit_card'],
        aggregatesOnly: [],
      },
    };
    const result = checkPII('card number: 4111-1111-1111-1111', config);
    expect(result.allowed).toBe(false);
    expect(result.violations.some(v => v.category === 'credit_card')).toBe(true);
  });

  it('should detect email addresses', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      piiRules: {
        neverOutput: ['email_address'],
        aggregatesOnly: [],
      },
    };
    const result = checkPII('Contact: john.doe@example.com for more info', config);
    expect(result.allowed).toBe(false);
  });

  it('should detect medical info', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      piiRules: {
        neverOutput: ['medical_info'],
        aggregatesOnly: [],
      },
    };
    const result = checkPII('The student has a diagnosis of ADHD and an allergy to peanuts', config);
    expect(result.allowed).toBe(false);
    expect(result.violations.some(v => v.category === 'medical_info')).toBe(true);
  });

  it('should work with school profile', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...IRON_DOME_PROFILES.school,
      enabled: true,
    };
    // Test pupil name detection
    const result = checkPII('pupil name: John Smith, date of birth: 12/05/2012', config);
    expect(result.allowed).toBe(false);
    expect(result.violations.length).toBeGreaterThan(0);
  });

  it('should allow all content when Iron Dome is disabled', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: false,
      piiRules: {
        neverOutput: ['password', 'credit_card'],
        aggregatesOnly: [],
      },
    };
    const result = checkPII('password: hunter2, card number: 4111-1111-1111-1111', config);
    expect(result.allowed).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  it('should handle multiple violations', async () => {
    const { checkPII } = await import('../pii-guard.js');
    const config: IronDomeConfig = {
      ...DEFAULT_IRON_DOME_CONFIG,
      enabled: true,
      piiRules: {
        neverOutput: ['password', 'credit_card', 'email_address'],
        aggregatesOnly: ['salary'],
      },
    };
    const result = checkPII(
      'password: secret123, card number: 4111-1111-1111-1111, email: user@test.com, salary: $50000',
      config,
    );
    expect(result.allowed).toBe(false);
    // Should have multiple violations
    expect(result.violations.length).toBeGreaterThanOrEqual(3);
  });
});
