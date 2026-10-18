import { describe, expect, it, vi } from "vitest";
import { MAX_NAMES, otherCertificateNames, readCertificateNames, registrableDomain } from "./certificateNames";

// The outside view, wider (2026-10-17): certificate transparency logs are a
// public record of every certificate issued for a domain. Other names under
// the founder's own domain (a forgotten staging or admin site) are listed for
// the founder to review; ShipLock reads nothing at those addresses.
describe("registrableDomain", () => {
  it.each([
    ["app.acme.com", "acme.com"], ["acme.com", "acme.com"], ["www.loja.com.br", "loja.com.br"],
    ["api.shop.co.uk", "shop.co.uk"], ["a.b.c.acme.io", "acme.io"],
  ])("%s is under %s", (host, apex) => expect(registrableDomain(host)).toBe(apex));

  it("refuses addresses that are not a public domain", () => {
    for (const host of ["localhost", "10.0.0.1", "com", ""]) expect(registrableDomain(host)).toBeNull();
  });
});

describe("otherCertificateNames", () => {
  const log = [
    { dns_names: ["staging.acme.com", "acme.com"], not_before: "2025-03-01T00:00:00Z" },
    { dns_names: ["*.preview.acme.com"], not_before: "2026-09-01T00:00:00Z" },
    { dns_names: ["STAGING.acme.com"], not_before: "2026-01-01T00:00:00Z" },
    { dns_names: ["app.acme.com"], not_before: "2026-10-01T00:00:00Z" },
    { dns_names: ["evil-acme.com", "acme.com.evil.net", 7], not_before: "2026-10-01T00:00:00Z" },
    { dns_names: ["bad name.acme.com"], not_before: "2026-10-01T00:00:00Z" },
  ];

  it("lists each other name under the domain once, newest issue first, without the confirmed address or wildcards' star", () => {
    expect(otherCertificateNames(log, "acme.com", "app.acme.com")).toEqual([
      { name: "preview.acme.com", lastIssued: "2026-09-01" },
      { name: "staging.acme.com", lastIssued: "2026-01-01" },
      { name: "acme.com", lastIssued: "2025-03-01" },
    ]);
  });

  it("reads nothing from a malformed log, and is bounded", () => {
    expect(otherCertificateNames({ not: "a list" }, "acme.com", "app.acme.com")).toBeNull();
    const many = Array.from({ length: MAX_NAMES + 20 }, (_, i) => ({ dns_names: [`n${i}.acme.com`], not_before: "2026-01-01T00:00:00Z" }));
    expect(otherCertificateNames(many, "acme.com", "app.acme.com")).toHaveLength(MAX_NAMES);
  });
});

describe("readCertificateNames", () => {
  it("does not search a platform's shared domain, and says not read when the log fails", async () => {
    const fetchMock = vi.fn<(url: string) => Promise<Response>>(async () => new Response("down", { status: 502 }));
    vi.stubGlobal("fetch", fetchMock);
    expect(await readCertificateNames("https://acme-git-main.vercel.app")).toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
    expect(await readCertificateNames("https://app.acme.com")).toBeNull();
    expect(fetchMock.mock.calls[0][0]).toBe("https://api.certspotter.com/v1/issuances?domain=acme.com&include_subdomains=true&expand=dns_names");
    // A log too large to read whole is cut at the cap and reads as not read.
    fetchMock.mockResolvedValueOnce(new Response(`[${'{"dns_names":["a.acme.com"],"not_before":"2026-01-01T00:00:00Z"},'.repeat(80_000)}{}]`));
    expect(await readCertificateNames("https://app.acme.com")).toBeNull();
    vi.unstubAllGlobals();
  });
});
