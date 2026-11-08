/**
 * Ambient module for js-yaml 3.x, the YAML parser the #897 contract in
 * release-audit-claims reads SKILL.md's frontmatter with. The package ships
 * no types and the contract uses two names, declared here so `@types/js-yaml`
 * need not join the tree. Test-side only: `src/__tests__` is excluded from
 * `tsconfig.build.json`, so nothing shipped sees this module.
 *
 * As with `src/types/huggingface-transformers.d.ts`, an exact-name ambient
 * module shadows any types the package might one day ship; keep this surface
 * in step with the contract's use, and delete it if `@types/js-yaml` arrives.
 */
declare module 'js-yaml' {
  /**
   * Decode one document with the default safe schema. Throws `YAMLException`
   * on whatever YAML refuses — a duplicate mapping key, a quote left open, a
   * line indented under nothing.
   */
  export function safeLoad(text: string, options?: { filename?: string }): unknown;

  export class YAMLException extends Error {
    /** The refusal without its position, e.g. `duplicated mapping key`. */
    reason: string;
    mark?: { line: number; column: number };
  }

  /**
   * The whole `module.exports`. Import this, not the names: jest's ESM bridge
   * lists a CommonJS module's named exports only as far as cjs-module-lexer
   * can see them, and js-yaml 3.x re-exports through
   * `module.exports = require(...)`, which it does not follow — so a named
   * import links as "does not provide an export named". The default is the
   * export object itself and is always there.
   */
  const yaml: { safeLoad: typeof safeLoad; YAMLException: typeof YAMLException };
  export default yaml;
}
