import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    globals: true,
    // Use jsdom as default so .tsx tests get a DOM; node-env tests opt-in via
    // /* @vitest-environment node */ comment if needed.
    environment: 'jsdom',
    environmentMatchGlobs: [
      ['server/**', 'node'],
      ['shared/**/*.test.ts', 'node'],
      ['tests/routes/**', 'node'],
      ['tests/ui/**', 'jsdom'],
    ],
    include: [
      'server/**/*.test.ts',
      'shared/**/*.test.ts',
      'tests/**/*.test.ts',
      'tests/**/*.test.tsx',
    ],
    setupFiles: ['tests/setup.ts'],
    testTimeout: 10_000,
  },
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, 'shared'),
      '@': path.resolve(__dirname, 'client/src'),
    },
  },
});
