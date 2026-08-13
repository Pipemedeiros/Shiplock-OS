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
  ]),
]);

export default eslintConfig;
