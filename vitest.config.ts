import { configDefaults, defineConfig } from "vitest/config";
import tsconfigPaths from "vite-tsconfig-paths";

// lib/env.ts parses process.env at import time — every required key needs a
// syntactically-valid dummy value here or any test that transitively imports
// it (most of lib/deep/*) fails before the test body even runs.
export default defineConfig({
  plugins: [tsconfigPaths()],
  test: {
    environment: "node",
    // docs/audit/ holds vendored copies of customer-corpus repositories (63MB,
    // ~10k files) used as audit working material. They carry their own
    // Playwright and unit suites, which vitest globs from the project root and
    // then fails on dependencies we do not install: 524 discovered files, 255
    // failing, while our own 1931 tests passed underneath. The .gitignore entry
    // stops git from staging that tree; it does not stop the test runner from
    // scanning it. configDefaults.exclude is spread so the defaults survive
    // being overridden.
    exclude: [...configDefaults.exclude, "docs/audit/**"],
    env: {
      NEXT_PUBLIC_SUPABASE_URL: "https://test.supabase.co",
      NEXT_PUBLIC_SUPABASE_ANON_KEY: "test-anon-key",
      SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
      STRIPE_SECRET_KEY: "sk_test_dummy",
      STRIPE_WEBHOOK_SECRET: "whsec_dummy",
      STRIPE_PRICE_ID: "price_dummy",
      RESEND_API_KEY: "re_dummy",
      RESEND_FROM_EMAIL: "test@example.com",
      NEXT_PUBLIC_APP_URL: "https://shiplock.dev",
      ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64"),
      CRON_SECRET: "cron-dummy",
      ANTHROPIC_API_KEY: "sk-ant-dummy",
    },
  },
});
