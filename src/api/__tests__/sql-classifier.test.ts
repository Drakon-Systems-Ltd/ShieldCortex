import { describe, it, expect } from '@jest/globals';
import { classifySqlQuery } from '../sql-classifier.js';

describe('classifySqlQuery — bare statements', () => {
  it('classifies SELECT as read', () => {
    expect(classifySqlQuery('SELECT * FROM memories')).toEqual({ kind: 'read' });
  });

  it('classifies PRAGMA as read', () => {
    expect(classifySqlQuery('PRAGMA table_info(memories)')).toEqual({ kind: 'read' });
  });

  it('classifies INSERT as write', () => {
    expect(classifySqlQuery("INSERT INTO memories (id) VALUES ('x')")).toEqual({
      kind: 'write',
      operation: 'INSERT',
    });
  });

  it('classifies UPDATE as write', () => {
    expect(classifySqlQuery("UPDATE memories SET title='x' WHERE id=1")).toEqual({
      kind: 'write',
      operation: 'UPDATE',
    });
  });

  it('classifies DELETE as write', () => {
    expect(classifySqlQuery('DELETE FROM memories WHERE id=1')).toEqual({
      kind: 'write',
      operation: 'DELETE',
    });
  });

  it('classifies DROP as destroy', () => {
    expect(classifySqlQuery('DROP TABLE memories')).toEqual({
      kind: 'destroy',
      operation: 'DROP',
    });
  });

  it('classifies TRUNCATE as destroy', () => {
    expect(classifySqlQuery('TRUNCATE TABLE memories')).toEqual({
      kind: 'destroy',
      operation: 'TRUNCATE',
    });
  });
});

describe('classifySqlQuery — CTE prefix (Fix #5 regression)', () => {
  it('classifies "WITH t AS (SELECT 1) SELECT * FROM t" as read', () => {
    const out = classifySqlQuery('WITH t AS (SELECT 1) SELECT * FROM t');
    expect(out).toEqual({ kind: 'read' });
  });

  it('classifies "WITH t AS (SELECT 1) INSERT INTO memories ..." as write', () => {
    const out = classifySqlQuery(
      "WITH t AS (SELECT 1) INSERT INTO memories (id) VALUES ('x')",
    );
    expect(out).toEqual({ kind: 'write', operation: 'INSERT' });
  });

  it('classifies "WITH t AS (SELECT 1) DELETE FROM memories WHERE id=1" as write', () => {
    const out = classifySqlQuery('WITH t AS (SELECT 1) DELETE FROM memories WHERE id=1');
    expect(out).toEqual({ kind: 'write', operation: 'DELETE' });
  });

  it('handles multiple CTEs', () => {
    const out = classifySqlQuery(
      'WITH a AS (SELECT 1), b AS (SELECT 2) UPDATE memories SET title=NULL',
    );
    expect(out).toEqual({ kind: 'write', operation: 'UPDATE' });
  });

  it('handles RECURSIVE keyword', () => {
    const out = classifySqlQuery(
      'WITH RECURSIVE r AS (SELECT 1) SELECT * FROM r',
    );
    expect(out).toEqual({ kind: 'read' });
  });

  it('handles a CTE with column list', () => {
    const out = classifySqlQuery(
      'WITH t(a, b) AS (SELECT 1, 2) SELECT a FROM t',
    );
    expect(out).toEqual({ kind: 'read' });
  });

  it('handles nested parens inside CTE body', () => {
    const out = classifySqlQuery(
      'WITH t AS (SELECT (1 + (2 * 3)) AS x) INSERT INTO memories (id) VALUES (1)',
    );
    expect(out).toEqual({ kind: 'write', operation: 'INSERT' });
  });

  it('handles a single-quoted literal containing a close-paren inside the CTE body', () => {
    const out = classifySqlQuery(
      "WITH t AS (SELECT ')' AS x) DELETE FROM memories WHERE id=1",
    );
    expect(out).toEqual({ kind: 'write', operation: 'DELETE' });
  });
});

describe('classifySqlQuery — comment prefix', () => {
  it('strips a leading line comment before classifying as write', () => {
    const out = classifySqlQuery("-- malicious comment\nINSERT INTO memories (id) VALUES ('x')");
    expect(out).toEqual({ kind: 'write', operation: 'INSERT' });
  });

  it('strips a leading block comment before classifying as write', () => {
    const out = classifySqlQuery('/* sneaky */ DELETE FROM memories');
    expect(out).toEqual({ kind: 'write', operation: 'DELETE' });
  });

  it('strips multiple stacked leading comments', () => {
    const out = classifySqlQuery(
      '-- one\n/* two */\n-- three\nSELECT 1',
    );
    expect(out).toEqual({ kind: 'read' });
  });
});

describe('classifySqlQuery — fail-closed', () => {
  it('rejects an empty query', () => {
    const out = classifySqlQuery('');
    expect(out.kind).toBe('reject');
  });

  it('rejects a whitespace-only query', () => {
    const out = classifySqlQuery('   \n\t  ');
    expect(out.kind).toBe('reject');
  });

  it('rejects a comment-only query', () => {
    const out = classifySqlQuery('-- just a comment');
    expect(out.kind).toBe('reject');
  });

  it('rejects an unrecognised leading keyword', () => {
    const out = classifySqlQuery('ATTACH DATABASE "/tmp/x.db" AS evil');
    expect(out.kind).toBe('reject');
  });

  it('rejects a malformed CTE prefix (no AS clause)', () => {
    const out = classifySqlQuery('WITH t SELECT * FROM t');
    expect(out.kind).toBe('reject');
  });

  it('rejects a CTE prefix with no body', () => {
    const out = classifySqlQuery('WITH t AS SELECT * FROM t');
    expect(out.kind).toBe('reject');
  });
});

describe('classifySqlQuery — case insensitivity', () => {
  it('handles lowercase select', () => {
    expect(classifySqlQuery('select * from memories')).toEqual({ kind: 'read' });
  });

  it('handles mixed case CTE → write', () => {
    expect(
      classifySqlQuery("With t As (Select 1) Insert Into memories (id) Values (1)"),
    ).toEqual({ kind: 'write', operation: 'INSERT' });
  });
});
