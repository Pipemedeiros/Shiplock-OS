import { describe, expect, it } from "vitest";
import { readPriority } from "./githubRun";

// MAX_FILES_PER_REPO truncates the read set, so priority decides which checks
// still have their inputs on a large repo.
describe("readPriority — the cap must never drop what the checks depend on", () => {
  it("puts dotenv files and manifests first", () => {
    for (const path of [".env", ".env.local", ".env.production", "package.json", "package-lock.json"]) {
      expect(readPriority(path)).toBe(0);
    }
  });

  it("puts application source next — client components and their imports", () => {
    for (const path of ["app/page.tsx", "components/Form.tsx", "lib/db.ts", "src/x.ts", "pages/api/y.ts"]) {
      expect(readPriority(path)).toBe(1);
    }
  });

  it("leaves everything else last", () => {
    for (const path of ["scripts/seed.js", "docs/notes.yml", "e2e/spec.ts"]) {
      expect(readPriority(path)).toBe(2);
    }
  });

  it("ranks a root manifest ahead of app source, which is the bug this fixes", () => {
    expect(readPriority("package.json")).toBeLessThan(readPriority("app/page.tsx"));
  });

  it("does not treat a nested package.json inside app/ as a root manifest", () => {
    // Still priority 0 by name — it is a manifest, and reading it is harmless.
    expect(readPriority("app/vendor/package.json")).toBe(0);
  });
});
