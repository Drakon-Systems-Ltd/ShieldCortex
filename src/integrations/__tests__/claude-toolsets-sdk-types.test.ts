import { describe, it, expect } from '@jest/globals';
import path from 'node:path';
import ts from 'typescript';

/**
 * #679 review, finding 1 — the guard's hook adapters must type-check against
 * the real `@anthropic-ai/sdk` toolset classes (a devDependency only; nothing
 * here runs the SDK or calls the API). The fixture subclasses both abstract
 * toolsets and wires `confirm`, `urlPolicy`, `browserState` and the `execute`
 * override through the guard exactly as the quickstart documents.
 */
const FIXTURE = path.resolve(process.cwd(), 'src/integrations/__tests__/fixtures/claude-toolsets-sdk-conformance.ts');

describe('ToolsetGuard — SDK type conformance (#679 finding 1)', () => {
  it('a driver subclassing the SDK toolsets through the guard type-checks', () => {
    const program = ts.createProgram([FIXTURE], {
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.NodeNext,
      moduleResolution: ts.ModuleResolutionKind.NodeNext,
      strict: true,
      noEmit: true,
      skipLibCheck: true,
      esModuleInterop: true,
    });
    const diagnostics = ts.getPreEmitDiagnostics(program).map((d) => {
      const where = d.file ? `${path.relative(process.cwd(), d.file.fileName)}:${d.file.getLineAndCharacterOfPosition(d.start ?? 0).line + 1}` : '';
      return `${where} TS${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`;
    });
    expect(diagnostics).toEqual([]);
  }, 120_000);
});
