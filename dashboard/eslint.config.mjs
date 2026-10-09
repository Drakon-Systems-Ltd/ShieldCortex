import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Retired v1 (CIC/Glass) modules — kept for recoverability, not compiled.
    "legacy-v1/**",
  ]),
  // Allow underscore-prefixed unused vars across the project
  {
    rules: {
      "@typescript-eslint/no-unused-vars": ["warn", {
        argsIgnorePattern: "^_",
        varsIgnorePattern: "^_",
        caughtErrorsIgnorePattern: "^_",
      }],
    },
  },
  // Readable type (Opus design §3, for a dyslexic reader): no all-caps
  // micro-labels, no wide letter-spacing, nothing below the 13px text-xs.
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: ["src/**/__tests__/**", "src/**/*.test.{ts,tsx}"],
    rules: {
      "no-restricted-syntax": ["error",
        {
          selector: "Literal[value=/(^|\\s)(uppercase|tracking-(wide|wider|widest|\\[[0-9.]+em\\])|text-\\[([0-9]|1[0-2])(\\.[0-9]+)?px\\])(\\s|$)/]",
          message: "Readable type: no uppercase, wide tracking or text below text-xs (Opus §3).",
        },
        {
          selector: "TemplateElement[value.raw=/(^|\\s)(uppercase|tracking-(wide|wider|widest|\\[[0-9.]+em\\])|text-\\[([0-9]|1[0-2])(\\.[0-9]+)?px\\])(\\s|$)/]",
          message: "Readable type: no uppercase, wide tracking or text below text-xs (Opus §3).",
        },
      ],
    },
  },
  // Three.js visualization components need relaxed rules
  {
    files: ["src/components/brain/**", "src/components/chip/**"],
    rules: {
      "react-hooks/rules-of-hooks": "off",
      "react-hooks/immutability": "off",
      "react-hooks/refs": "off",
      "react-hooks/purity": "off",
      "react-hooks/exhaustive-deps": "off",
      "prefer-const": "off",
      "@typescript-eslint/no-unused-vars": "off",
      "@typescript-eslint/no-unused-expressions": "off",
    },
  },
]);

export default eslintConfig;
