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
    // Standalone MCP server — its own package/deps, published separately.
    "mcp/**",
    // Vendored third-party Claude Code skills — not this project's source,
    // not built/shipped, and not ours to fix lint errors in.
    ".claude/skills/**",
    // Vendored copies of corpus repositories, kept as audit working material.
    // 63MB and ~10k files of other people's source; linting it produced 9,257
    // problems that are not ours and buried the three that are. Same reason
    // vitest.config.ts excludes it from test discovery.
    "docs/audit/**",
  ]),
]);

export default eslintConfig;
