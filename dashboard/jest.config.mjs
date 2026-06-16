import nextJest from 'next/jest.js';

// Dashboard test runner (Phase 0 of the dashboard cleanup). Separate from the
// root ts-jest/node suite: the UI needs jsdom + Next's SWC transform (CSS +
// path-alias mocking). The 4 constellation math tests keep running under the
// root jest config; this runner owns the React component/hook *.test.tsx tests.
const createJestConfig = nextJest({ dir: './' });

/** @type {import('jest').Config} */
const config = {
  testEnvironment: 'jsdom',
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
  testMatch: ['<rootDir>/src/**/*.test.tsx'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
  // Ignore build artefacts (the standalone bundle duplicates package.json →
  // jest-haste-map name collision otherwise).
  modulePathIgnorePatterns: ['<rootDir>/.next/'],
};

export default createJestConfig(config);
