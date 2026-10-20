/** @type {import('ts-jest').JestConfigWithTsJest} */
export default {
  preset: 'ts-jest/presets/default-esm',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/plugins'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/*.test.ts'],
  moduleFileExtensions: ['ts', 'js', 'json'],
  extensionsToTreatAsEsm: ['.ts'],
  // Per-worker config sandbox — isolates ~/.shieldcortex/config.json so parallel
  // workers don't race on the shared on-disk config the defence pipeline reads.
  // See scripts/jest-config-sandbox.mjs for the full rationale.
  setupFilesAfterEnv: ['<rootDir>/scripts/jest-config-sandbox.mjs'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        useESM: true,
        tsconfig: '<rootDir>/tsconfig.test.json',
      },
    ],
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/index.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 30,
      functions: 30,
      lines: 30,
      statements: 30,
    },
  },
  verbose: true,
  testTimeout: 10000,
  // Recycle a worker whose heap has grown past 1 GB once its current test
  // file finishes. Workers are long-lived and run hundreds of ESM/ts-jest
  // files each, so retained memory accumulates until whichever suite happens
  // to be running hits the heap limit and the run fails with "Jest worker ran
  // out of memory" (#811, seen on macos-test). Restarting the worker between
  // files changes no test; it has no effect on --runInBand runs.
  workerIdleMemoryLimit: '1GB',
};
