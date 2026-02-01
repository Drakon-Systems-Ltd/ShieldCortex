/**
 * Sensitivity Classification Tests
 *
 * Tests for content sensitivity classification and redaction.
 */

import { describe, it, expect } from '@jest/globals';

describe('Sensitivity Classifier', () => {
  it('should classify content with password as RESTRICTED', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity('password: abc123', 'credentials');
    expect(result.level).toBe('RESTRICTED');
    expect(result.redactionRequired).toBe(true);
  });

  it('should classify content with AWS_SECRET_ACCESS_KEY as RESTRICTED', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity(
      'aws_secret_access_key=AKIAIOSFODNN7EXAMPLE',
      'config',
    );
    expect(result.level).toBe('RESTRICTED');
  });

  it('should classify content with RSA private key as RESTRICTED', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity(
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ...',
      'key file',
    );
    expect(result.level).toBe('RESTRICTED');
    expect(result.confidence).toBe(1.0);
  });

  it('should classify content with email addresses as CONFIDENTIAL', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity(
      'Contact the team at john.doe@example.com for details',
      'contacts',
    );
    expect(result.level).toBe('CONFIDENTIAL');
  });

  it('should classify content with phone numbers as CONFIDENTIAL', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity(
      'Call me at (555) 123-4567',
      'contact info',
    );
    expect(result.level).toBe('CONFIDENTIAL');
  });

  it('should classify content with localhost URL as INTERNAL', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity(
      'The dev server runs at http://localhost:3000',
      'dev setup',
    );
    expect(result.level).toBe('INTERNAL');
  });

  it('should classify generic knowledge content as PUBLIC', async () => {
    const { classifySensitivity } = await import('../sensitivity/index.js');
    const result = classifySensitivity(
      'React is a JavaScript library for building user interfaces.',
      'tech notes',
    );
    expect(result.level).toBe('PUBLIC');
    expect(result.redactionRequired).toBe(false);
  });
});

describe('Redaction', () => {
  it('should redact RESTRICTED content', async () => {
    const { redactContent } = await import('../sensitivity/redaction.js');
    const redacted = redactContent('My password: supersecret123');
    expect(redacted).not.toContain('supersecret123');
    expect(redacted).toContain('[REDACTED]');
  });

  it('should not redact PUBLIC content in redactForDisplay', async () => {
    const { redactForDisplay } = await import('../sensitivity/redaction.js');
    const content = 'React is a JavaScript library.';
    const result = redactForDisplay(content, 'PUBLIC');
    expect(result).toBe(content);
  });
});
