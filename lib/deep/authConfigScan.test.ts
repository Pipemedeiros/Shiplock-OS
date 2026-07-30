import { describe, expect, it, vi } from "vitest";
import {
  analyzeRedirectAllowList,
  analyzeSiteUrl,
  isLocalEntry,
  isUnrecognisedConfigShape,
  parseAllowList,
  scanAuthConfig,
  splitEntry,
} from "./authConfigScan";

const list = (...entries: string[]) => analyzeRedirectAllowList({ uri_allow_list: entries.join(",") });

describe("parseAllowList", () => {
  it("splits on commas and trims", () => {
    expect(parseAllowList("https://a.com/**, https://b.com/** ")).toEqual([
      "https://a.com/**",
      "https://b.com/**",
    ]);
  });

  it("drops empty entries left by trailing commas", () => {
    expect(parseAllowList("https://a.com,,")).toEqual(["https://a.com"]);
  });

  it("handles null, undefined and empty", () => {
    expect(parseAllowList(null)).toEqual([]);
    expect(parseAllowList(undefined)).toEqual([]);
    expect(parseAllowList("")).toEqual([]);
  });
});

describe("splitEntry", () => {
  it("splits scheme, host and path", () => {
    expect(splitEntry("https://app.example.com/auth/callback")).toEqual({
      scheme: "https",
      host: "app.example.com",
      path: "/auth/callback",
    });
  });

  it("keeps wildcards intact, which URL() would reject", () => {
    expect(splitEntry("https://*.example.com/**")).toEqual({
      scheme: "https",
      host: "*.example.com",
      path: "/**",
    });
  });

  it("handles an entry with no path", () => {
    expect(splitEntry("https://example.com").path).toBe("");
  });

  it("handles an entry with no scheme", () => {
    expect(splitEntry("example.com/**")).toEqual({ scheme: null, host: "example.com", path: "/**" });
  });

  it("keeps the port with the host", () => {
    expect(splitEntry("http://localhost:3000/**").host).toBe("localhost:3000");
  });

  it("lowercases the scheme", () => {
    expect(splitEntry("HTTPS://example.com").scheme).toBe("https");
  });

  it("handles a custom mobile scheme", () => {
    expect(splitEntry("myapp://callback").scheme).toBe("myapp");
  });
});

describe("isLocalEntry", () => {
  it("recognises local hosts with and without ports", () => {
    for (const host of ["localhost", "localhost:3000", "127.0.0.1", "127.0.0.1:54321", "[::1]"]) {
      expect(isLocalEntry(host), host).toBe(true);
    }
  });

  it("does not treat a real host as local", () => {
    expect(isLocalEntry("example.com")).toBe(false);
    expect(isLocalEntry("localhost.evil.com")).toBe(false);
  });
});

describe("B7 — redirect allow-list", () => {
  // The documented, recommended configuration must be silent, or the check is
  // worthless to the people who set things up correctly.
  it("is SILENT on exact URLs", () => {
    expect(list("https://app.example.com/auth/callback")).toEqual([]);
  });

  it("is SILENT on a path wildcard, which Supabase itself recommends", () => {
    expect(list("https://app.example.com/**", "https://app.example.com/*")).toEqual([]);
  });

  it("is SILENT on localhost entries, which local development requires", () => {
    expect(list("http://localhost:3000/**", "http://127.0.0.1:54321/**")).toEqual([]);
  });

  it("is SILENT on a custom mobile scheme", () => {
    expect(list("myapp://auth-callback")).toEqual([]);
  });

  it("is silent on an empty allow-list", () => {
    expect(analyzeRedirectAllowList({})).toEqual([]);
    expect(analyzeRedirectAllowList({ uri_allow_list: null })).toEqual([]);
  });

  it("flags a bare * as permitting any destination", () => {
    const out = list("*");
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].id).toBe("auth_redirect:wildcard_any_host");
  });

  it("flags a bare ** the same way", () => {
    expect(list("**")[0].id).toBe("auth_redirect:wildcard_any_host");
  });

  it("flags a scheme-only wildcard host", () => {
    expect(list("https://**")[0].id).toBe("auth_redirect:wildcard_any_host");
    expect(list("https://*")[0].id).toBe("auth_redirect:wildcard_any_host");
  });

  // ** crosses dots and slashes, so this does NOT mean "my subdomains".
  it("flags a globstar inside the host as matching hosts you don't own", () => {
    const out = list("https://**.example.com/**");
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].id).toContain("globstar_host");
    expect(out[0].consequence).toContain("including dots and slashes");
  });

  // Anyone can deploy to these in a minute, so the wildcard is an open door.
  it("treats a wildcard over a free-subdomain platform as CRITICAL", () => {
    for (const entry of [
      "https://*.vercel.app/**",
      "https://*.netlify.app/**",
      "https://*.pages.dev/**",
      "https://*.ngrok-free.app/**",
      "https://*.trycloudflare.com/**",
    ]) {
      const out = analyzeRedirectAllowList({ uri_allow_list: entry });
      expect(out[0]?.severity, entry).toBe("CRITICAL");
      expect(out[0].consequence).toContain("anyone can create a subdomain");
    }
  });

  it("names preview deployments as the likely reason, since that's why it's there", () => {
    expect(list("https://*.vercel.app/**")[0].consequence).toContain("preview deployments");
  });

  // Their own domain is a real but lesser risk, and the mechanism is specific.
  it("treats a wildcard over the customer's own domain as a WARNING about takeover", () => {
    const out = list("https://*.example.com/**");
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].consequence).toContain("subdomain takeover");
  });

  it("flags a single-character ? wildcard in the host", () => {
    expect(list("https://ap?.example.com/**")[0].id).toContain("wildcard_host");
  });

  it("flags http:// for a real host as sending sessions in the clear", () => {
    const out = list("http://app.example.com/**");
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("WARNING");
    expect(out[0].id).toContain("insecure_scheme");
  });

  it("does not flag http:// on localhost", () => {
    expect(list("http://localhost:3000/**")).toEqual([]);
  });

  it("reports each distinct bad entry once", () => {
    const out = list("https://*.vercel.app/**", "http://app.example.com/**", "https://ok.example.com/**");
    expect(out).toHaveLength(2);
    expect(new Set(out.map((finding) => finding.id)).size).toBe(2);
  });

  it("collapses duplicate identical entries into one finding", () => {
    expect(list("https://*.vercel.app/**", "https://*.vercel.app/**")).toHaveLength(1);
  });

  it("collapses several any-host entries into a single finding", () => {
    expect(list("*", "**", "https://**")).toHaveLength(1);
  });

  it("explains that a PATH wildcard is fine — the host is the problem", () => {
    expect(list("*")[0].consequence).toContain("a wildcard in the PATH");
  });

  it("describes the attack concretely rather than abstractly", () => {
    const { consequence } = list("*")[0];
    expect(consequence).toContain("2FA");
    expect(consequence).toContain("Nothing looks like phishing");
  });
});

describe("Site URL", () => {
  it("is silent on a proper https production URL", () => {
    expect(analyzeSiteUrl({ site_url: "https://app.example.com" })).toEqual([]);
  });

  it("is silent when unset — nothing to judge", () => {
    expect(analyzeSiteUrl({})).toEqual([]);
    expect(analyzeSiteUrl({ site_url: "" })).toEqual([]);
    expect(analyzeSiteUrl({ site_url: null })).toEqual([]);
  });

  // Extremely common: the default is localhost:3000 and nobody changes it.
  it("flags a localhost Site URL and explains the user-visible symptom", () => {
    const out = analyzeSiteUrl({ site_url: "http://localhost:3000" });
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("auth_site_url:localhost");
    expect(out[0].consequence).toContain("password reset appears broken");
  });

  it("flags an http production Site URL", () => {
    const out = analyzeSiteUrl({ site_url: "http://app.example.com" });
    expect(out[0].id).toBe("auth_site_url:insecure_scheme");
  });

  it("prefers the localhost finding over the scheme finding for localhost", () => {
    expect(analyzeSiteUrl({ site_url: "http://localhost:3000" })).toHaveLength(1);
  });

  it("tolerates surrounding whitespace", () => {
    expect(analyzeSiteUrl({ site_url: "  https://app.example.com  " })).toEqual([]);
  });
});

describe("scanAuthConfig — aggregate", () => {
  it("returns nothing for a null config (fetch failed — not evidence of a problem)", () => {
    expect(scanAuthConfig(null)).toEqual([]);
  });

  it("is silent on a correctly configured project", () => {
    expect(
      scanAuthConfig({
        site_url: "https://app.example.com",
        uri_allow_list: "https://app.example.com/**,http://localhost:3000/**",
      })
    ).toEqual([]);
  });

  it("combines redirect and site-url findings", () => {
    const out = scanAuthConfig({ site_url: "http://localhost:3000", uri_allow_list: "*" });
    expect(out.map((finding) => finding.id).sort()).toEqual([
      "auth_redirect:wildcard_any_host",
      "auth_site_url:localhost",
    ]);
  });

  it("returns findings in the shared GithubFinding shape", () => {
    for (const finding of scanAuthConfig({ site_url: "http://localhost:3000", uri_allow_list: "*" })) {
      expect(finding.packageName).toBeNull();
      expect(finding.version).toBeNull();
      expect(finding.vulnId).toBeNull();
      expect(finding.cveId).toBeNull();
      expect(finding.consequence.length).toBeGreaterThan(50);
    }
  });

  it("produces stable ids across identical passes, for the diff engine", () => {
    const config = { site_url: "http://localhost:3000", uri_allow_list: "https://*.vercel.app/**" };
    expect(scanAuthConfig(config).map((f) => f.id)).toEqual(scanAuthConfig(config).map((f) => f.id));
  });
});

// Guarding against the Unit 1 failure mode: a field name we don't recognise must
// never read as "clean". It cost two advisor lints months of silence.
describe("field-name resilience", () => {
  it("reads the documented snake_case keys", () => {
    expect(analyzeRedirectAllowList({ uri_allow_list: "*" })).toHaveLength(1);
    expect(analyzeSiteUrl({ site_url: "http://localhost:3000" })).toHaveLength(1);
  });

  it("also reads camelCase and SCREAMING_CASE variants", () => {
    expect(analyzeRedirectAllowList({ uriAllowList: "*" })).toHaveLength(1);
    expect(analyzeRedirectAllowList({ URI_ALLOW_LIST: "*" })).toHaveLength(1);
    expect(analyzeSiteUrl({ siteUrl: "http://localhost:3000" })).toHaveLength(1);
    expect(analyzeSiteUrl({ SITE_URL: "http://localhost:3000" })).toHaveLength(1);
  });

  it("reads additional_redirect_urls as an allow-list alias", () => {
    expect(analyzeRedirectAllowList({ additional_redirect_urls: "https://*.vercel.app/**" })).toHaveLength(1);
  });

  it("detects a config populated with only keys we don't understand", () => {
    expect(isUnrecognisedConfigShape({ some_future_key: "x", another: 1 })).toBe(true);
  });

  it("does not call a config unrecognised when a key we know is present", () => {
    expect(isUnrecognisedConfigShape({ site_url: "https://a.com", other: 1 })).toBe(false);
  });

  it("does not call an EMPTY config unrecognised — that is just an empty project", () => {
    expect(isUnrecognisedConfigShape({})).toBe(false);
  });

  it("scanAuthConfig reports nothing and logs loudly on an unrecognised shape", () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(scanAuthConfig({ totally_new_shape: "x" })).toEqual([]);
    expect(spy).toHaveBeenCalledWith(expect.stringContaining("did NOT run"), expect.any(String));
    spy.mockRestore();
  });

  it("ignores a non-string value in a key we know", () => {
    expect(analyzeRedirectAllowList({ uri_allow_list: 42 as unknown as string })).toEqual([]);
  });
});
