import { runCommand, COMMANDS, type CommandContext } from './registry';

function mockCtx(overrides: Partial<CommandContext> = {}): CommandContext {
  return {
    navigate: jest.fn(),
    setTheme: jest.fn(),
    recall: jest.fn(async () => [
      { id: 1, title: 'auth bug fix' },
      { id: 2, title: 'token refresh' },
    ]),
    scan: jest.fn(async () => ({
      target: '/a',
      riskLevel: 'SAFE',
      trustScore: 100,
      filesScanned: 12,
      findingsCount: 0,
    })),
    forget: jest.fn(async () => undefined),
    consolidate: jest.fn(async () => ({ consolidated: 2, decayed: 1, deleted: 0 })),
    quarantineList: jest.fn(async () => [
      { id: 11, title: 'stealth instruction in CLAUDE.md' },
      { id: 12, title: 'low-trust agent write' },
    ]),
    quarantineReview: jest.fn(async () => undefined),
    ironDome: jest.fn(async (action) => (action === 'status' ? 'iron dome: ACTIVE' : `iron dome → ${action}`)),
    remember: jest.fn(async () => ({ id: 99 })),
    routes: [
      { label: 'Memory', href: '/memory' },
      { label: 'Protection', href: '/protection' },
      { label: 'X-Ray', href: '/xray' },
    ],
    ...overrides,
  };
}

describe('runCommand', () => {
  it('returns nothing for empty input', async () => {
    const res = await runCommand('', mockCtx());
    expect(res.ok).toBe(false);
    expect(res.lines).toEqual([]);
  });

  it('reports an unknown command', async () => {
    const res = await runCommand('frobnicate', mockCtx());
    expect(res.ok).toBe(false);
    expect(res.lines.join(' ')).toMatch(/unknown command/i);
  });

  it('help lists every registered command', async () => {
    const res = await runCommand('help', mockCtx());
    const text = res.lines.join('\n');
    for (const name of Object.keys(COMMANDS)) {
      expect(text).toContain(name);
    }
  });

  it('go navigates to a matched route (by label or href)', async () => {
    const ctx = mockCtx();
    const res = await runCommand('go protection', ctx);
    expect(ctx.navigate).toHaveBeenCalledWith('/protection');
    expect(res.ok).toBe(true);
  });

  it('go reports an error + options for an unknown view', async () => {
    const ctx = mockCtx();
    const res = await runCommand('go nope', ctx);
    expect(ctx.navigate).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
    expect(res.lines.join(' ')).toMatch(/memory|protection|x-ray/i);
  });

  it('theme switches to a valid theme', async () => {
    const ctx = mockCtx();
    const res = await runCommand('theme glass', ctx);
    expect(ctx.setTheme).toHaveBeenCalledWith('glass');
    expect(res.ok).toBe(true);
  });

  it('theme rejects an invalid value', async () => {
    const ctx = mockCtx();
    const res = await runCommand('theme neon', ctx);
    expect(ctx.setTheme).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it('recall passes the query + project flag and lists hits', async () => {
    const ctx = mockCtx();
    const res = await runCommand('recall "auth bug" --project xero', ctx);
    expect(ctx.recall).toHaveBeenCalledWith('auth bug', 'xero');
    expect(res.lines.join('\n')).toContain('auth bug fix');
  });

  it('recall errors when no query is given', async () => {
    const ctx = mockCtx();
    const res = await runCommand('recall', ctx);
    expect(ctx.recall).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it('scan passes target + deep flag and summarises risk', async () => {
    const ctx = mockCtx();
    const res = await runCommand('scan ~/dev/api --deep', ctx);
    expect(ctx.scan).toHaveBeenCalledWith('~/dev/api', true);
    expect(res.lines.join('\n')).toMatch(/SAFE|trust/i);
  });

  it('forget deletes by numeric id', async () => {
    const ctx = mockCtx();
    const res = await runCommand('forget 42', ctx);
    expect(ctx.forget).toHaveBeenCalledWith(42);
    expect(res.ok).toBe(true);
  });

  it('forget rejects a non-numeric id', async () => {
    const ctx = mockCtx();
    const res = await runCommand('forget abc', ctx);
    expect(ctx.forget).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it('consolidate runs and reports counts', async () => {
    const ctx = mockCtx();
    const res = await runCommand('consolidate', ctx);
    expect(ctx.consolidate).toHaveBeenCalled();
    expect(res.lines.join('\n')).toMatch(/consolidat/i);
  });

  it('quarantine (no arg) lists pending items', async () => {
    const ctx = mockCtx();
    const res = await runCommand('quarantine', ctx);
    expect(ctx.quarantineList).toHaveBeenCalled();
    expect(res.lines.join('\n')).toContain('stealth instruction');
  });

  it('quarantine approve <id> reviews by id', async () => {
    const ctx = mockCtx();
    const res = await runCommand('quarantine approve 11', ctx);
    expect(ctx.quarantineReview).toHaveBeenCalledWith(11, 'approve');
    expect(res.ok).toBe(true);
  });

  it('quarantine reject <id> reviews by id', async () => {
    const ctx = mockCtx();
    await runCommand('quarantine reject 12', ctx);
    expect(ctx.quarantineReview).toHaveBeenCalledWith(12, 'reject');
  });

  it('quarantine approve rejects a non-numeric id', async () => {
    const ctx = mockCtx();
    const res = await runCommand('quarantine approve xyz', ctx);
    expect(ctx.quarantineReview).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it('irondome status reports state', async () => {
    const ctx = mockCtx();
    const res = await runCommand('irondome status', ctx);
    expect(ctx.ironDome).toHaveBeenCalledWith('status');
    expect(res.lines.join(' ')).toMatch(/iron dome/i);
  });

  it('irondome on activates', async () => {
    const ctx = mockCtx();
    const res = await runCommand('irondome on', ctx);
    expect(ctx.ironDome).toHaveBeenCalledWith('on');
    expect(res.ok).toBe(true);
  });

  it('irondome rejects an unknown action', async () => {
    const ctx = mockCtx();
    const res = await runCommand('irondome sideways', ctx);
    expect(ctx.ironDome).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it('remember stores a memory from the quoted text', async () => {
    const ctx = mockCtx();
    const res = await runCommand('remember "the auth bug was an expired JWT"', ctx);
    expect(ctx.remember).toHaveBeenCalledWith('the auth bug was an expired JWT');
    expect(res.lines.join(' ')).toMatch(/#99/);
  });

  it('remember errors with no text', async () => {
    const ctx = mockCtx();
    const res = await runCommand('remember', ctx);
    expect(ctx.remember).not.toHaveBeenCalled();
    expect(res.ok).toBe(false);
  });

  it('surfaces an adapter error as an error line', async () => {
    const ctx = mockCtx({ consolidate: jest.fn(async () => { throw new Error('kill switch active'); }) });
    const res = await runCommand('consolidate', ctx);
    expect(res.ok).toBe(false);
    expect(res.lines.join(' ')).toMatch(/kill switch active/);
  });
});
