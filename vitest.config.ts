import { defineConfig } from 'vitest/config'

export default defineConfig({
    test: {
        coverage: {
            reporter: ['text', 'json', 'html', 'lcov'],
            provider: 'v8',
            reportsDirectory: 'coverage',
        },
        environment: 'jsdom',
        globals: true,
        setupFiles: ['./vitest.setup.ts'],
    },
});