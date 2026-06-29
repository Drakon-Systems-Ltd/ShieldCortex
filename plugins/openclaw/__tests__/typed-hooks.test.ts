import { describe, expect, it } from '@jest/globals';
import plugin from '../index.js';

describe('OpenClaw runtime registration', () => {
  it('registers agent-loop hooks through api.on, not internal HOOK automation', () => {
    const typedHooks: string[] = [];
    const customHooks: string[] = [];
    const commands: string[] = [];

    plugin.register({
      id: 'shieldcortex-realtime',
      name: 'ShieldCortex Real-time Scanner',
      logger: { info: () => {} },
      on: (hookName: string) => {
        typedHooks.push(hookName);
      },
      registerHook: (hookName: string) => {
        customHooks.push(hookName);
      },
      registerCommand: (command: { name: string }) => {
        commands.push(command.name);
      },
    } as any);

    expect(typedHooks).toEqual(expect.arrayContaining([
      'before_tool_call',
      'session_end',
      'llm_input',
      'llm_output',
    ]));
    expect(customHooks).toEqual([]);
    expect(commands).toContain('shieldcortex-status');
  });
});
