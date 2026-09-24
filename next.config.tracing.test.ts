import { describe, expect, it } from "vitest";
import nextConfig from "./next.config";

// Q6: every route that can run the job queue must ship the proof worker and
// PGlite, or a proof dies at run time with a missing file.
describe("next.config.ts: proof worker files are traced into job routes", () => {
  it("includes the worker script and PGlite for each route that calls runNextJob", async () => {
    const { readFileSync, readdirSync, statSync } = await import("node:fs");
    const { join } = await import("node:path");
    const { EMBEDDED_WORKER_PATH } = await import("./lib/proving/embeddedHost");
    const walk = (dir: string): string[] => readdirSync(dir).flatMap((name) => {
      const path = join(dir, name);
      return statSync(path).isDirectory() ? walk(path) : [path];
    });
    const routes = walk("app/api").filter((f) => /\/route\.ts$/.test(f) && /runNextJob/.test(readFileSync(f, "utf8")))
      .map((f) => f.replace(/^app/, "").replace(/\/route\.ts$/, "")).sort();
    const includes = nextConfig.outputFileTracingIncludes ?? {};
    expect(Object.keys(includes).sort()).toEqual(routes);
    for (const route of routes) {
      expect(includes[route]).toContain(`./${EMBEDDED_WORKER_PATH}`);
      expect(includes[route]).toContain("./node_modules/@electric-sql/pglite/dist/pglite.wasm");
    }
  });
});
