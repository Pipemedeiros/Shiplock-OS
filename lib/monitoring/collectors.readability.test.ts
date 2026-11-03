import { beforeEach, describe, expect, it, vi } from "vitest";
import type { CollectorContext } from "./registry";
import type { Finding } from "./findings";

// The endpoint snapshot replaces the previous one, so a finding the scan
// could not re-check must be carried forward rather than silently resolved.
const scanner = vi.hoisted(() => ({ full: vi.fn(), critical: vi.fn() }));
vi.mock("@/lib/scanner", () => ({ scanProject: scanner.full, scanCriticalChecks: scanner.critical }));

import { supabaseScanCollector } from "./collectors";

const prior = (id: string): Finding => ({ id, severity: "CRITICAL", title: id, consequence: id });
const ctx = (triggerSource: CollectorContext["triggerSource"], previousFindings: Finding[]): CollectorContext => ({
  profile: { id: "u", email: null, monitored_project_url: "https://ref.supabase.co", monitored_anon_key_encrypted: "enc" },
  anonKey: "anon", triggerSource, previousFindings,
});

beforeEach(() => {
  scanner.full.mockReset();
  scanner.critical.mockReset();
});

describe("supabase-scan carries forward unread findings", () => {
  it("full pass keeps findings under unread prefixes and resolves the rest", async () => {
    scanner.full.mockImplementation(async (_u: string, _k: string, _a: unknown, _s: unknown, unread: string[]) => {
      unread.push("auth_admin_endpoint", "idor:");
      return { tables: [] };
    });
    const result = await supabaseScanCollector.run(ctx("scheduled_48h", [
      prior("auth_admin_endpoint"), prior("idor:user_profiles"), prior("cors_wildcard"),
    ]));
    expect(result.snapshotFindings!.map((f) => f.id).sort()).toEqual(["auth_admin_endpoint", "idor:user_profiles"]);
  });

  it("hourly pass keeps in-scope findings it could not read", async () => {
    scanner.critical.mockImplementation(async (_u: string, _k: string, _s: unknown, unread: string[]) => {
      unread.push("public_bucket:");
      return { tables: [], keyAnalysis: {}, secretsExposure: { exposedFiles: [] }, publicBuckets: { tested: false, publicBuckets: [], suspiciousFiles: [] } };
    });
    const result = await supabaseScanCollector.run(ctx("hourly", [prior("public_bucket:avatars"), prior("secrets_exposure")]));
    expect(result.snapshotFindings!.map((f) => f.id)).toEqual(["public_bucket:avatars"]);
  });
});
