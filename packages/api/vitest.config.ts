import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    pool: 'forks',         // separate process per file — guarantees fresh DB singleton
    environment: 'node',
    include: ['src/test/**/*.test.ts'],
    setupFiles: ['./src/test/setup.ts'],
  },
})
