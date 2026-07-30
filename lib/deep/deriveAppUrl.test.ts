import { describe, expect, it } from "vitest";
import { deriveAppUrl, normaliseCandidate } from "./deriveAppUrl";

describe("normaliseCandidate", () => {
  it("reduces a URL to its origin, since probes run from the root", () => {
    expect(normaliseCandidate("https://app.example.com/auth/callback")).toBe("https://app.example.com");
  });

  it("keeps a non-default port", () => {
    expect(normaliseCandidate("https://app.example.com:8443/x")).toBe("https://app.example.com:8443");
  });

  it("accepts a platform hostname — that IS the customer's real app", () => {
    expect(normaliseCandidate("https://myapp.vercel.app")).toBe("https://myapp.vercel.app");
  });

  it("trims whitespace", () => {
    expect(normaliseCandidate("  https://app.example.com  ")).toBe("https://app.example.com");
  });

  // These are allow-list patterns, not addresses — there is nothing to fetch.
  it("rejects anything containing a wildcard", () => {
    for (const raw of ["https://*.example.com", "https://**", "*", "https://ap?.example.com"]) {
      expect(normaliseCandidate(raw), raw).toBeNull();
    }
  });

  // The bug this replaces: rejecting on the whole string discarded almost every
  // usable allow-list entry, because a PATH wildcard is the form Supabase
  // recommends and it doesn't survive the reduction to origin anyway.
  it("accepts a PATH wildcard — only a wildcard in the HOST is disqualifying", () => {
    expect(normaliseCandidate("https://app.example.com/**")).toBe("https://app.example.com");
    expect(normaliseCandidate("https://app.example.com/*")).toBe("https://app.example.com");
    expect(normaliseCandidate("https://app.example.com/[!a-z]")).toBe("https://app.example.com");
  });

  it("rejects localhost and loopback", () => {
    for (const raw of ["http://localhost:3000", "http://127.0.0.1:54321", "https://localhost"]) {
      expect(normaliseCandidate(raw), raw).toBeNull();
    }
  });

  it("rejects non-http schemes, including mobile deep links", () => {
    expect(normaliseCandidate("myapp://callback")).toBeNull();
    expect(normaliseCandidate("com.example.app://auth")).toBeNull();
  });

  it("rejects a hostname with no dot, which cannot be public", () => {
    expect(normaliseCandidate("http://intranet")).toBeNull();
  });

  it("rejects empty and unparseable values", () => {
    expect(normaliseCandidate("")).toBeNull();
    expect(normaliseCandidate("   ")).toBeNull();
    expect(normaliseCandidate("not a url")).toBeNull();
  });
});

describe("deriveAppUrl", () => {
  it("prefers a proper https site_url", () => {
    expect(
      deriveAppUrl({
        site_url: "https://app.example.com",
        uri_allow_list: "https://other.example.com/**",
      })
    ).toBe("https://app.example.com");
  });

  it("strips the path from site_url", () => {
    expect(deriveAppUrl({ site_url: "https://app.example.com/dashboard" })).toBe("https://app.example.com");
  });

  // The case that makes this worth building: site_url is very commonly left at
  // the localhost default, and the real URL is in the allow-list so OAuth works.
  it("falls back to the allow-list when site_url is still localhost", () => {
    expect(
      deriveAppUrl({
        site_url: "http://localhost:3000",
        uri_allow_list: "http://localhost:3000/**,https://app.example.com/**",
      })
    ).toBe("https://app.example.com");
  });

  it("skips wildcard allow-list entries and takes the concrete one", () => {
    expect(
      deriveAppUrl({
        site_url: "http://localhost:3000",
        uri_allow_list: "https://*.vercel.app/**,https://app.example.com/auth/callback",
      })
    ).toBe("https://app.example.com");
  });

  it("prefers https over an earlier http entry", () => {
    expect(
      deriveAppUrl({ uri_allow_list: "http://staging.example.com/**,https://app.example.com/**" })
    ).toBe("https://app.example.com");
  });

  it("falls back to an http site_url when nothing better exists", () => {
    expect(deriveAppUrl({ site_url: "http://app.example.com" })).toBe("http://app.example.com");
  });

  it("falls back to an http allow-list entry as a last resort", () => {
    expect(deriveAppUrl({ uri_allow_list: "http://app.example.com/**" })).toBe("http://app.example.com");
  });

  it("returns null when there is nothing usable", () => {
    expect(deriveAppUrl({ site_url: "http://localhost:3000", uri_allow_list: "http://localhost:3000/**" })).toBeNull();
    expect(deriveAppUrl({ uri_allow_list: "*" })).toBeNull();
    expect(deriveAppUrl({})).toBeNull();
    expect(deriveAppUrl(null)).toBeNull();
  });

  it("ignores non-string config values rather than throwing", () => {
    expect(deriveAppUrl({ site_url: 42 as unknown as string, uri_allow_list: [] as unknown as string })).toBeNull();
  });

  it("is deterministic when one origin appears under several paths", () => {
    const config = {
      uri_allow_list: "https://app.example.com/a,https://app.example.com/b,https://app.example.com/c",
    };
    expect(deriveAppUrl(config)).toBe("https://app.example.com");
    expect(deriveAppUrl(config)).toBe(deriveAppUrl(config));
  });

  it("handles a realistic well-configured project", () => {
    expect(
      deriveAppUrl({
        site_url: "https://shiplock.dev",
        uri_allow_list: "http://localhost:3000/**,https://shiplock.dev/auth/callback,https://*.vercel.app/**",
      })
    ).toBe("https://shiplock.dev");
  });
});
