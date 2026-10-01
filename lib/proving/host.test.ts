import { afterEach, expect, it, vi } from "vitest";
import { provingHost } from "./host";
afterEach(() => { vi.unstubAllEnvs(); });
it("legacy hosted proving stays unavailable even with credentials", () => {
  vi.stubEnv("SHIPLOCK_PROVING_TOKEN", "fixture-token");
  vi.stubEnv("SHIPLOCK_PROVING_PROJECT_REF", "fixture-project");
  expect(provingHost()).toBeNull();
});
