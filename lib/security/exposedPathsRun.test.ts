import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ProviderResult } from "@/lib/monitoring/registry";

// The app-surface pass hands one result to the monitor worker's fenced commit
// (3F-C2c). Archive-on-resolve, unread-prefix protection, and insert-if-new are
// proven in the SQL suite; these tests pin what the runner sends.
const probeMock = vi.fn();
const auditMock = vi.fn();
const emailMock = vi.fn();
const commitMock = vi.fn();
const namesMock = vi.fn();

vi.mock("./exposedPaths", () => ({ probeExposedPaths: probeMock }));
vi.mock("./bundleAudit", () => ({ auditShippedBundle: auditMock }));
vi.mock("./certificateNames", () => ({ readCertificateNames: namesMock }));
// No network in this suite: the header probe and the stored last read are mocked.
const previousMock = vi.fn();
vi.mock("./responseHeaders", () => ({ auditResponseHeaders: vi.fn(async () => []) }));
vi.mock("./surfaceChange", async (original) => ({ ...await original<typeof import("./surfaceChange")>(), loadPreviousSurface: previousMock }));
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
  namesMock.mockReset().mockResolvedValue(undefined);
  previousMock.mockReset().mockResolvedValue(null);
  commitMock.mockReset().mockImplementation(async (result: ProviderResult) => result.findings);
});

describe("runExposedPathScan", () => {
  it("runs every probe against the app URL with a shared unread list", async () => {
    await run();
    expect(probeMock).toHaveBeenCalledWith(url, undefined, expect.any(Array));
    expect(auditMock).toHaveBeenCalledWith(url, undefined, expect.any(Array), expect.any(Object));
    expect(emailMock).toHaveBeenCalledWith(url, expect.anything(), expect.any(Array));
  });

  it("commits all probe findings as one app-surface result that may retire", async () => {
    probeMock.mockResolvedValue([finding("exposed:git_exposed")]);
    auditMock.mockResolvedValue([finding("bundle:shipped_secret:supabase_service_role_jwt")]);
    emailMock.mockResolvedValue([finding("email_auth:dmarc_missing")]);
    const result = await run();
    expect(sent()).toMatchObject({ transport: "app-surface", identity: url, retire: true, snapshot: { scope: "app.example.com" } });
    expect(sent().snapshot.failed).toEqual(sent().unread);
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
    expect(sent().snapshot.failed).toContain(prefix);
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

  // P5: the paths the live site's JavaScript calls, as a runtime fact under
  // the address it was read from, only when the page itself was read.
  it("sends the paths the live site calls as its own fact when the page was read", async () => {
    auditMock.mockImplementation(async (_u: string, _s: unknown, _unread: string[], shipped: { pageRead: boolean; scriptsSeen: number; scriptsRead: number; paths: Set<string>; requests: Set<string> }) => {
      Object.assign(shipped, { pageRead: true, pagesRead: 3, scriptsSeen: 9, scriptsRead: 8 });
      shipped.paths.add("/api/orders/").add("/api/me").add("/api/surveys/");
      shipped.requests.add("/api/orders/").add("/api/me");
      return [];
    });
    await run();
    expect(sent().facts).toEqual({ appSurface: { url, complete: true, change: { comparable: false, since: null }, pagesRead: 3, scriptsSeen: 9, scriptsRead: 8,
      paths: ["/api/me", "/api/orders/", "/api/surveys/"], requests: ["/api/me", "/api/orders/"] } });
  });

  // Watch: what the live site started or stopped requesting since the last read.
  it("records what changed since the last complete read of the same address", async () => {
    previousMock.mockResolvedValue({ url, complete: true, requests: ["/api/me", "/api/old"], recordedAt: "2026-10-19T09:00:00.000Z" });
    auditMock.mockImplementation(async (_u: string, _s: unknown, _unread: string[], shipped: { pageRead: boolean; requests: Set<string> }) => {
      shipped.pageRead = true;
      shipped.requests.add("/api/me").add("/api/new");
      return [];
    });
    await run();
    expect((sent().facts as { appSurface: Record<string, unknown> }).appSurface.change)
      .toEqual({ comparable: true, since: "2026-10-19T09:00:00.000Z", added: ["/api/new"], removed: ["/api/old"] });
    auditMock.mockImplementation(async (_u: string, _s: unknown, unread: string[], shipped: { pageRead: boolean }) => {
      shipped.pageRead = true;
      unread.push("bundle:shipped_secret:");
      return [];
    });
    commitMock.mockClear();
    await run();
    expect((sent().facts as { appSurface: Record<string, unknown> }).appSurface).toMatchObject({ complete: false, change: { comparable: false } });
  });

  // Other names on the founder's own domain, from certificate transparency.
  it("adds the other certificate names to the fact, null when the log was not read", async () => {
    auditMock.mockImplementation(async (_u: string, _s: unknown, _unread: string[], shipped: { pageRead: boolean }) => {
      shipped.pageRead = true;
      return [];
    });
    namesMock.mockResolvedValue([{ name: "staging.example.com", lastIssued: "2026-09-01" }]);
    await run();
    expect(namesMock).toHaveBeenCalledWith(url, undefined);
    expect((sent().facts as { appSurface: Record<string, unknown> }).appSurface.certificateNames).toEqual([{ name: "staging.example.com", lastIssued: "2026-09-01" }]);
    namesMock.mockRejectedValue(new Error("down"));
    commitMock.mockClear();
    await run();
    expect((sent().facts as { appSurface: Record<string, unknown> }).appSurface.certificateNames).toBeNull();
  });

  it("sends no fact when the page could not be read, so an old one is never replaced by nothing", async () => {
    auditMock.mockRejectedValue(new Error("network"));
    await run();
    expect(sent()).not.toHaveProperty("facts");
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
    expect(auditMock).toHaveBeenCalledWith(url, controller.signal, expect.any(Array), expect.any(Object));
    expect(commitMock).not.toHaveBeenCalled();
  });
});
