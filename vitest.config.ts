import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    // Every suite boots its own Payload instance on its own SQLite file; keep them sequential so
    // libsql never sees two processes on one file and the mock servers get predictable ports.
    fileParallelism: false,
  },
})
