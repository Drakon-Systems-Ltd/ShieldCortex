/**
 * Type-level conformance with the real Anthropic SDK toolset classes (#679
 * review, finding 1). Never executed: `claude-toolsets-sdk-types.test.ts`
 * type-checks this file with the TypeScript compiler and fails on any
 * diagnostic. If the guard's hook adapters drift from the SDK's `confirm`,
 * `urlPolicy` or `execute` signatures, this stops compiling.
 */
import {
  BetaAbstractBrowserToolset20260801,
  BetaAbstractComputerToolset20260801,
  ToolError,
  type BetaBrowserMemberResult,
  type BetaBrowserState,
  type BetaComputerMemberResult,
  type BetaToolsetCallContext,
} from '@anthropic-ai/sdk/helpers/beta/toolsets';
import type {
  BetaBrowserMemberInput,
  BetaBrowserMemberName,
  BetaComputerMemberInput,
  BetaComputerMemberName,
} from '@anthropic-ai/sdk/resources/beta';
import { ToolsetGuard } from '../../claude-toolsets.js';

const browserGuard = new ToolsetGuard({ toolset: 'browser', toolError: ToolError });

export class GuardedBrowser extends BetaAbstractBrowserToolset20260801 {
  constructor() {
    super({
      browserState: (): BetaBrowserState => ({ tabs: [] }),
      urlPolicy: browserGuard.urlPolicy(),
      confirm: browserGuard.confirm(async (_ctx, verdict) => verdict.decision === 'allow'),
    });
  }

  protected override async execute(
    ctx: BetaToolsetCallContext,
    name: BetaBrowserMemberName,
    input: BetaBrowserMemberInput,
  ): Promise<BetaBrowserMemberResult> {
    return browserGuard.execute(ctx, name, input, (c, n, i) => super.execute(c, n, i));
  }
}

const computerGuard = new ToolsetGuard({ toolset: 'computer', toolError: ToolError });

export class GuardedComputer extends BetaAbstractComputerToolset20260801 {
  constructor() {
    super({ confirm: computerGuard.confirm() });
  }

  protected override async execute(
    ctx: BetaToolsetCallContext,
    name: BetaComputerMemberName,
    input: BetaComputerMemberInput,
  ): Promise<BetaComputerMemberResult> {
    return computerGuard.execute(ctx, name, input, (c, n, i) => super.execute(c, n, i));
  }
}
