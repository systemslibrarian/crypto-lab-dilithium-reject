import { defineConfig } from 'vitest/config';

export default defineConfig({
  base: '/crypto-lab-dilithium-reject/',
  // Unit tests live in src/; keep the Playwright e2e/ specs out of vitest.
  test: {
    include: ['src/**/*.test.ts'],
  },
});
