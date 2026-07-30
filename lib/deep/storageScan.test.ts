import { describe, expect, it } from "vitest";
import { BUCKET_SQL, checkBackups, checkObjectPolicies, checkUploadLimits, scanStorage, STORAGE_POLICY_SQL } from "./storageScan";
import { assertReadOnly } from "./supabaseMgmt";

const bucket = (over: Partial<Parameters<typeof checkUploadLimits>[0][0]> = {}) => ({
  id: "b", name: "uploads", public: false, file_size_limit: 5_000_000,
  allowed_mime_types: ["image/png"], ...over,
});
const policy = (over: Partial<Parameters<typeof checkObjectPolicies>[1][0]> = {}) => ({
  name: "p", cmd: "SELECT", qual: "true", roles: "anon", ...over,
});

describe("A12 — object policies", () => {
  // The finding this exists for: private in the dashboard, readable in fact.
  it("flags a permissive policy over private buckets", () => {
    const out = checkObjectPolicies([bucket()], [policy()]);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].consequence).toContain('shows "private"');
  });

  it("explains that the bucket flag is not what decides access", () => {
    const out = checkObjectPolicies([bucket()], [policy()]);
    expect(out[0].consequence).toContain("not what decides access");
  });

  it("is silent when the policy actually filters", () => {
    expect(checkObjectPolicies([bucket()], [policy({ qual: "auth.uid() = owner" })])).toEqual([]);
  });

  it("is silent when the permissive policy targets a non-public role", () => {
    expect(checkObjectPolicies([bucket()], [policy({ roles: "service_role" })])).toEqual([]);
  });

  // Check 16 already reports a public bucket from the outside; saying it again
  // would put one problem on the board twice.
  it("does not repeat what the external scan already reports", () => {
    expect(checkObjectPolicies([bucket({ public: true })], [policy()])).toEqual([]);
  });

  it("is silent with no policies at all", () => {
    expect(checkObjectPolicies([bucket()], [])).toEqual([]);
  });

  it("ignores write-only policies for a read finding", () => {
    expect(checkObjectPolicies([bucket()], [policy({ cmd: "INSERT" })])).toEqual([]);
  });
});

describe("A13 — upload restrictions", () => {
  it("flags a public bucket with no MIME allow-list", () => {
    const out = checkUploadLimits([bucket({ public: true, allowed_mime_types: null })], false);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("stored XSS");
  });

  it("treats a missing size limit alone as INFO and a billing matter", () => {
    const out = checkUploadLimits([bucket({ public: true, file_size_limit: null })], false);
    expect(out[0].severity).toBe("INFO");
    expect(out[0].consequence).toContain("storage bill rather than a breach");
  });

  // A locked-down private bucket is a capacity question; we are not a billing alert.
  it("does NOT flag an unreachable private bucket", () => {
    expect(checkUploadLimits([bucket({ file_size_limit: null, allowed_mime_types: null })], false)).toEqual([]);
  });

  it("flags a private bucket once a permissive policy makes it reachable", () => {
    expect(checkUploadLimits([bucket({ allowed_mime_types: null })], true)).toHaveLength(1);
  });

  it("is silent on a properly restricted bucket", () => {
    expect(checkUploadLimits([bucket({ public: true })], false)).toEqual([]);
  });

  it("treats an empty MIME array as no restriction", () => {
    expect(checkUploadLimits([bucket({ public: true, allowed_mime_types: [] })], false)).toHaveLength(1);
  });
});

describe("scanStorage", () => {
  // Our own project: no buckets at all.
  it("is silent on a project with no buckets", () => {
    expect(scanStorage({ buckets: [], policies: [] })).toEqual([]);
  });

  it("checks nothing when we could not read buckets", () => {
    expect(scanStorage({})).toEqual([]);
  });

  it("combines both classes", () => {
    const out = scanStorage({
      buckets: [bucket({ allowed_mime_types: null })],
      policies: [policy()],
    });
    expect(out).toHaveLength(2);
    expect(new Set(out.map((x) => x.id)).size).toBe(2);
  });

  it("produces stable ids", () => {
    const input = { buckets: [bucket({ public: true, allowed_mime_types: null })], policies: [] };
    expect(scanStorage(input).map((x) => x.id)).toEqual(scanStorage(input).map((x) => x.id));
  });
});

describe("the queries", () => {
  it("pass the read-only guard", () => {
    expect(() => assertReadOnly(BUCKET_SQL)).not.toThrow();
    expect(() => assertReadOnly(STORAGE_POLICY_SQL)).not.toThrow();
  });
});

describe("A19 — recovery posture", () => {
  it("notes PITR being off, at INFO", () => {
    const out = checkBackups({ pitrEnabled: false, walgEnabled: true });
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("INFO");
  });

  it("is silent when PITR is on", () => {
    expect(checkBackups({ pitrEnabled: true, walgEnabled: true })).toEqual([]);
  });

  // "Not available on your plan" is not a security finding, and reporting one
  // would be telling a customer to buy something to satisfy us.
  it("says NOTHING when we could not read the config", () => {
    expect(checkBackups(null)).toEqual([]);
  });

  it("frames it as a cost decision and names the realistic scenario", () => {
    const out = checkBackups({ pitrEnabled: false, walgEnabled: false });
    expect(out[0].consequence).toContain("cost decision rather than a security one");
    expect(out[0].consequence).toContain("without its `where` clause");
  });
});
