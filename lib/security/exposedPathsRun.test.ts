import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ProviderResult } from "@/lib/monitoring/registry";

// The app-surface pass hands one result to the monitor worker's fenced commit
// (3F-C2c). Archive-on-resolve, unread-prefix protection, and insert-if-new are
// proven in the SQL suite; these tests pin what the runner sends.
const probeMock = vi.fn();
const auditMock = vi.fn();
const emailMock = vi.fn();
const commitMock = vi.fn();

vi.mock("./exposedPaths", () => ({ probeExposedPaths: probeMock }));
vi.mock("./bundleAudit", () => ({ auditShippedBundle: auditMock }));
// Mocked so the suite never performs real DNS lookups; the origin probe then
// fails closed and is reported unread.
vi.mock("./emailAuth", () => ({ auditEmailAuth: emailMock, nodeTxtResolver: vi.fn() }));

const { runExposedPathScan } = await import("./exposedPathsRun");

const url = "https://app.example.com";
const finding = (id: string) => ({ id, severity: "CRITICAL" as const, title: `t-${id}`, consequence: `c-${id}` });
const run = (options: { signal?: AbortSignal } = {}) => runExposedPathScan("u1", url, { commit: commitMock, ...options });
const sent = () => commitMock.mock.calls[0][0] as ProviderResult;
const sentIds = () => sent().findings.map((f) => f.id).sort();

beforeEach(() => {
  probeMock.mockReset().mockResolvedValue([]);
  auditMock.mockReset().mockResolvedValue([]);
  emailMock.mockReset().mockResolvedValue([]);
  commitMock.mockReset().mockImplementation(async (result: ProviderResult) => result.findings);
});

describe("runExposedPathScan", () => {
  it("runs every probe against the app URL with a shared unread list", async () => {
    await run();
    expect(probeMock).toHaveBeenCalledWith(url, undefined, expect.any(Array));
    expect(auditMock).toHaveBeenCalledWith(url, undefined, expect.any(Array));
    expect(emailMock).toHaveBeenCalledWith(url, expect.anything(), expect.any(Array));
  });

  it("commits all probe findings as one app-surface result that may retire", async () => {
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);
    auditMock.mockResolvedValue([finding("bundle:shipped_secret:supabase_service_role_jwt")]);
    emailMock.mockResolvedValue([finding("email_auth:dmarc_missing")]);
    const result = await run();
    expect(sent()).toMatchObject({ transport: "app-surface", identity: url, retire: true });
    expect(sent()).not.toHaveProperty("facts");
    expect(sentIds()).toEqual(["bundle:shipped_secret:supabase_service_role_jwt", "email_auth:dmarc_missing", "exposed:git_exposed"]);
    expect(result).toMatchObject({ total: 3, newCount: 3 });
  });

  it("reports only what the commit newly inserted", async () => {
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);
    commitMock.mockResolvedValue([]);
    expect(await run()).toMatchObject({ total: 1, newCount: 0, newFindings: [] });
  });

  it.each([
    ["path probes", probeMock, "exposed:", auditMock, "bundle:shipped_secret:aws_access_key"],
    ["bundle audit", auditMock, "bundle:", probeMock, "exposed:git_exposed"],
    ["email audit", emailMock, "email_auth:", probeMock, "exposed:git_exposed"],
  ] as const)("keeps other probes' findings and marks the family unread when the %s throws", async (_name, failing, prefix, other, id) => {
    failing.mockRejectedValue(new Error("network"));
    other.mockResolvedValue([finding(id)]);
    await run();
    expect(sentIds()).toEqual([id]);
    expect(sent().unread).toContain(prefix);
  });

  it("sends the unread prefixes a probe recorded", async () => {
    probeMock.mockImplementation(async (_url: string, _signal: unknown, unread: string[]) => {
      unread.push("exposed:git_exposed");
      return [finding("exposed:npmrc_exposed")];
    });
    await run();
    expect(sent().unread).toEqual(expect.arrayContaining(["exposed:git_exposed"]));
    expect(sentIds()).toEqual(["exposed:npmrc_exposed"]);
  });

  it("propagates a fenced rejection so the collector fails", async () => {
    commitMock.mockRejectedValue(new Error("Provider result was not committed"));
    await expect(run()).rejects.toThrow("not committed");
  });
});

describe("runExposedPathScan — 3F-C2b-2 cancellation", () => {
  it("forwards the signal and never commits a cancelled, empty pass", async () => {
    const controller = new AbortController();
    probeMock.mockImplementation(async () => {
      controller.abort(new Error("collector timed out"));
      return [];
    });
    await expect(run({ signal: controller.signal })).rejects.toThrow("collector timed out");
    expect(probeMock).toHaveBeenCalledWith(url, controller.signal, expect.any(Array));
    expect(auditMock).toHaveBeenCalledWith(url, controller.signal, expect.any(Array));
    expect(commitMock).not.toHaveBeenCalled();
  });
});
