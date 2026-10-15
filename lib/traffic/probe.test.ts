import { describe, expect, it } from "vitest";
import { classifyProbe, PROBE_KINDS, PROBE_RULES, probeSnippetSource } from "./probe";

// Clean-room rules in the style of Cloudflare's managed WAF rules and the
// OWASP Core Rule Set, run in the customer's own middleware (Aikido Zen's
// in-app idea). Only the category leaves the customer's server, never a
// query value (traffic boundary, AGENTS.md).
describe("classifyProbe", () => {
  it.each([
    ["sqli", "/api/products?id=1' OR '1'='1"],
    ["sqli", "/api/search?q=x%27%20UNION%20SELECT%20password%20FROM%20users--"],
    ["sqli", "/api/items?sort=name;DROP TABLE users"],
    ["sqli", "/api/user?id=1%20AND%20SLEEP(5)"],
    ["traversal", "/api/files?path=../../../../etc/passwd"],
    ["traversal", "/static/%2e%2e%2f%2e%2e%2fwin.ini"],
    ["xss", "/search?q=<script>alert(1)</script>"],
    ["xss", "/profile?name=%3Csvg%20onload%3Dalert(1)%3E"],
    ["ssrf", "/api/preview?url=http://169.254.169.254/latest/meta-data/"],
    ["ssrf", "/api/fetch?target=http://metadata.google.internal/computeMetadata/v1/"],
    ["cmdi", "/api/ping?host=8.8.8.8;cat /etc/shadow"],
    ["cmdi", "/api/convert?file=a.png%7Cwhoami"],
    ["nosql", "/api/login?username[$ne]=x&password[$ne]=x"],
  ])("finds %s in %s", (kind, url) => {
    expect(classifyProbe(url)).toBe(kind);
  });

  it.each([
    "/api/books?title=O'Reilly%20and%20Associates",
    "/api/search?q=select%20a%20plan",
    "/blog/how-to-use-union-types",
    "/api/redirect?next=/dashboard",
    "/docs/../guide",
    "/api/preview?url=https://example.com/article",
    "/api/products?price[gte]=10",
    "/api/notes?q=cat%20pictures%20and%20dogs",
    "/",
  ])("leaves ordinary traffic alone: %s", (url) => {
    expect(classifyProbe(url)).toBeNull();
  });

  it("never throws on malformed encoding", () => {
    expect(() => classifyProbe("/api/x?q=%E0%A4%A")).not.toThrow();
  });

  it("serializes every rule so the customer's snippet can run the same rules", () => {
    for (const rule of PROBE_RULES) {
      expect(PROBE_KINDS).toContain(rule.kind);
      expect(() => new RegExp(rule.source, rule.flags)).not.toThrow();
    }
    expect(JSON.parse(JSON.stringify(PROBE_RULES))).toEqual(PROBE_RULES);
  });

  it("runs identically as the source embedded in the customer's snippet", () => {
    const probeKind = new Function(`${probeSnippetSource()}; return probeKind;`)() as (u: string) => string | null;
    for (const url of ["/api/products?id=1' OR '1'='1", "/api/files?path=../../../../etc/passwd", "/search?q=<script>alert(1)</script>",
      "/api/preview?url=http://169.254.169.254/latest/meta-data/", "/api/ping?host=8.8.8.8;cat /etc/shadow", "/api/login?username[$ne]=x",
      "/api/books?title=O'Reilly%20and%20Associates", "/api/x?q=%E0%A4%A", "/"]) {
      expect(probeKind(url)).toBe(classifyProbe(url));
    }
  });
});

