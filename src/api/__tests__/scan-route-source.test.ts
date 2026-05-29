/**
 * Fix #13 — `/api/v1/scan` source-normalisation + tamper-audit regression tests.
 *
 * - Config-tamper attempts must be audited as BLOCK / RESTRICTED so that
 *   incident-triage queries filtering on firewall_result IN ('BLOCK','QUARANTINE')
 *   surface them.
 * - Unknown `source.type` values must silently normalise to `'api'` (defence in
 *   depth — never reject the request, just stop polluting Iron Dome dashboards).
 * - Long `source.identifier` values must be truncated (cap = 200 chars).
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type { Request, Response } from 'express';
import { closeDatabase, initDatabase } from '../../database/init.js';
import { queryAuditLogs } from '../../defence/audit/queries.js';
import {
  handleV1Scan,
  handleV1ScanBatch,
  normaliseDefenceSource,
  __test__,
} from '../visualization-server.js';

function createResponseMock() {
  const json = jest.fn();
  const status = jest.fn(() => ({ json }));
  return {
    res: { status, json } as unknown as Response,
    status,
    json,
  };
}

function makeReq(body: Record<string, unknown>): Request {
  return { body } as unknown as Request;
}

describe('Fix #13 — /api/v1/scan source normalisation + tamper audit', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    jest.restoreAllMocks();
  });

  describe('normaliseDefenceSource (unit)', () => {
    it('passes through whitelisted types unchanged', () => {
      for (const type of __test__.ALLOWED_DEFENCE_SOURCE_TYPES) {
        const result = normaliseDefenceSource({ type, identifier: 'x' });
        expect(result.type).toBe(type);
      }
    });

    it('normalises unknown type to "api"', () => {
      const result = normaliseDefenceSource({ type: 'attacker', identifier: 'mallory' });
      expect(result.type).toBe('api');
      // identifier preserved (not part of the normalisation contract for type)
      expect(result.identifier).toBe('mallory');
    });

    it('falls back to default identifier when missing', () => {
      const result = normaliseDefenceSource({ type: 'api' });
      expect(result.identifier).toBe('rest-api');
    });

    it('truncates identifiers over the cap with an ellipsis', () => {
      const longId = 'a'.repeat(__test__.MAX_SOURCE_IDENTIFIER_LENGTH + 50);
      const result = normaliseDefenceSource({ type: 'api', identifier: longId });
      expect(result.identifier.length).toBe(__test__.MAX_SOURCE_IDENTIFIER_LENGTH);
      expect(result.identifier.endsWith('…')).toBe(true);
    });
  });

  describe('handleV1Scan (route handler)', () => {
    it('audits config-tamper attempts as BLOCK / RESTRICTED', () => {
      const { res } = createResponseMock();
      handleV1Scan(
        makeReq({
          content: 'hello world',
          title: 'Test',
          config: { mode: 'permissive' }, // <-- tamper attempt
        }),
        res,
      );

      const tamperRows = queryAuditLogs({ firewallResult: 'BLOCK', limit: 50 })
        .filter(row => (row.threat_indicators ?? '').includes('config_tampering'));

      expect(tamperRows.length).toBeGreaterThanOrEqual(1);
      const row = tamperRows[0];
      expect(row.firewall_result).toBe('BLOCK');
      expect(row.sensitivity_level).toBe('RESTRICTED');
      expect(row.trust_score).toBe(0);
      expect(row.source_type).toBe('api');
      expect(row.source_identifier).toBe('rest-api');
      expect(row.reason).toContain('config_override_attempt');
    });

    it('normalises unknown source.type to "api" in the pipeline audit row', () => {
      const { res } = createResponseMock();
      handleV1Scan(
        makeReq({
          content: 'hello world',
          title: 'Test',
          source: { type: 'attacker', identifier: 'mallory-001' },
        }),
        res,
      );

      // The defence pipeline writes its own audit row using the normalised
      // source. The tamper row (which would also have source_type 'api') is
      // only written when a `config` field is present, so we know any audit
      // row here came from the pipeline using the normalised source.
      const rows = queryAuditLogs({ source: 'api', limit: 50 })
        .filter(row => row.source_identifier === 'mallory-001');

      expect(rows.length).toBeGreaterThanOrEqual(1);
      expect(rows[0].source_type).toBe('api');

      // Confirm the unknown 'attacker' value was rejected and never reached
      // the audit table.
      const attackerRows = queryAuditLogs({ source: 'attacker' as never, limit: 50 });
      expect(attackerRows.length).toBe(0);
    });

    it('truncates oversize source.identifier in the audit row', () => {
      const longId = 'b'.repeat(__test__.MAX_SOURCE_IDENTIFIER_LENGTH + 75);
      const { res } = createResponseMock();
      handleV1Scan(
        makeReq({
          content: 'hello world',
          title: 'Test',
          source: { type: 'api', identifier: longId },
        }),
        res,
      );

      const rows = queryAuditLogs({ source: 'api', limit: 50 })
        .filter(row => (row.source_identifier ?? '').startsWith('b'));

      expect(rows.length).toBeGreaterThanOrEqual(1);
      const recorded = rows[0].source_identifier;
      expect(recorded.length).toBe(__test__.MAX_SOURCE_IDENTIFIER_LENGTH);
      expect(recorded.endsWith('…')).toBe(true);
    });
  });

  describe('handleV1ScanBatch (route handler)', () => {
    it('also normalises unknown source.type to "api"', () => {
      const { res } = createResponseMock();
      handleV1ScanBatch(
        makeReq({
          items: [{ content: 'item one', title: 'A' }],
          source: { type: 'attacker', identifier: 'batch-mallory' },
        }),
        res,
      );

      const rows = queryAuditLogs({ source: 'api', limit: 50 })
        .filter(row => row.source_identifier === 'batch-mallory');

      expect(rows.length).toBeGreaterThanOrEqual(1);
      expect(rows[0].source_type).toBe('api');
    });
  });
});
