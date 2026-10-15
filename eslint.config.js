import js from "@eslint/js"
import tseslint from "typescript-eslint"
import eslintConfigPrettier from "eslint-config-prettier"
import commentLength from "eslint-plugin-comment-length"

export default tseslint.config(
    {
        ignores: ["dist", "coverage", "node_modules", "*.config.*", "vitest.setup.ts"],
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    commentLength.configs["flat/recommended"],
    {
        files: ["**/*.ts", "**/*.tsx"],
        languageOptions: {
            parser: tseslint.parser,
            parserOptions: {
                project: "./tsconfig.json",
                ecmaVersion: "latest",
                sourceType: "module",
            },
            globals: {
                describe: "readonly",
                it: "readonly",
                expect: "readonly",
                bench: "readonly",
                beforeAll: "readonly",
                afterAll: "readonly",
                beforeEach: "readonly",
                afterEach: "readonly",
            },
        },
        rules: {
            "@typescript-eslint/no-namespace": "off",
            "@typescript-eslint/no-non-null-assertion": "off",
            "@typescript-eslint/no-explicit-any": "warn",
            "no-unused-vars": "off",
            "@typescript-eslint/no-unused-vars": [
                "warn",
                { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
            ],
            "comment-length/limit-single-line-comments": ["warn", { maxLength: 100 }],
            "comment-length/limit-multi-line-comments": ["warn", { maxLength: 100 }],
        },
    },
    {
        files: ["**/*.test.ts", "**/*.bench.ts"],
        rules: {
            "@typescript-eslint/no-explicit-any": "off",
        },
    },
    {
        files: ["examples/**/*.mjs"],
        languageOptions: {
            globals: {
                process: "readonly",
                console: "readonly",
            },
        },
    },
    eslintConfigPrettier
)
