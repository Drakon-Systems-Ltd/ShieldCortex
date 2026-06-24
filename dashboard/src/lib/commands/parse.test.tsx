import { parseCommand } from './parse';

describe('parseCommand', () => {
  it('returns null for empty / whitespace input', () => {
    expect(parseCommand('')).toBeNull();
    expect(parseCommand('   ')).toBeNull();
  });

  it('parses a bare command name', () => {
    expect(parseCommand('help')).toEqual({ name: 'help', args: [], flags: {} });
  });

  it('lowercases the command name but preserves arg case', () => {
    expect(parseCommand('GO Defence')).toEqual({ name: 'go', args: ['Defence'], flags: {} });
  });

  it('parses positional args', () => {
    expect(parseCommand('go defence')).toEqual({ name: 'go', args: ['defence'], flags: {} });
  });

  it('keeps a double-quoted phrase as one arg', () => {
    expect(parseCommand('recall "auth bug fix"')).toEqual({
      name: 'recall',
      args: ['auth bug fix'],
      flags: {},
    });
  });

  it('parses --key value flags', () => {
    expect(parseCommand('recall "auth bug" --project xero')).toEqual({
      name: 'recall',
      args: ['auth bug'],
      flags: { project: 'xero' },
    });
  });

  it('parses --bool flags (no following value) as true', () => {
    expect(parseCommand('scan ~/dev/api --deep')).toEqual({
      name: 'scan',
      args: ['~/dev/api'],
      flags: { deep: true },
    });
  });

  it('treats a flag followed by another flag as boolean', () => {
    expect(parseCommand('scan ~/x --deep --quiet')).toEqual({
      name: 'scan',
      args: ['~/x'],
      flags: { deep: true, quiet: true },
    });
  });

  it('collapses extra whitespace', () => {
    expect(parseCommand('  go    defence  ')).toEqual({ name: 'go', args: ['defence'], flags: {} });
  });
});
