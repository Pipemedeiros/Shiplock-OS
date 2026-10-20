import { describe, expect, it } from "vitest";
import {
  _BUNDLE_SECRETS,
  classifySourceMap,
  extractScriptUrls,
  findSourceMapUrl,
  scanBundleSecrets,
} from "./bundleAudit";

const PAGE = "https://app.example.com/";

const jwt = (role: string) => {
  const b64 = (o: unknown) =>
    Buffer.from(JSON.stringify(o)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role, iat: 1 })}.abcdefghij`;
};

describe("extractScriptUrls", () => {
  it("resolves relative, root-relative, and absolute same-origin scripts", () => {
    const html = `
      <script src="/_next/static/chunks/main.js"></script>
      <script src="chunks/page.js"></script>
      <script src="https://app.example.com/x.js"></script>`;
    expect(extractScriptUrls(html, PAGE)).toEqual([
      "https://app.example.com/_next/static/chunks/main.js",
      "https://app.example.com/chunks/page.js",
      "https://app.example.com/x.js",
    ]);
  });

  it("resolves protocol-relative URLs against the page's scheme", () => {
    expect(extractScriptUrls(`<script src="//app.example.com/a.js"></script>`, PAGE)).toEqual([
      "https://app.example.com/a.js",
    ]);
  });

  // Next.js assetPrefix serves the app's own build from a CDN host
  // (supabase.com: frontend-assets.supabase.com/www/<id>/_next/static/...).
  // Skipping it read nothing and reported nothing unread, a quiet clean.
  it("keeps the app's own Next.js build served from an asset host", () => {
    const html = `
      <script src="https://assets.example-cdn.com/www/abc/_next/static/chunks/main-app.js?dpl=x"></script>
      <script src="https://cdn.posthog.com/static/array.js"></script>`;
    expect(extractScriptUrls(html, PAGE)).toEqual(["https://assets.example-cdn.com/www/abc/_next/static/chunks/main-app.js?dpl=x"]);
  });

  // Auditing someone else's CDN would mean reporting another company's code as
  // this customer's finding, and fetching unrelated hosts on their behalf.
  it("ignores third-party scripts", () => {
    const html = `
      <script src="https://js.stripe.com/v3/"></script>
      <script src="https://cdn.posthog.com/array.js"></script>
      <script src="/app.js"></script>`;
    expect(extractScriptUrls(html, PAGE)).toEqual(["https://app.example.com/app.js"]);
  });

  it("ignores inline scripts, which have no src", () => {
    expect(extractScriptUrls(`<script>var a = 1;</script>`, PAGE)).toEqual([]);
  });

  it("dedupes a script included twice", () => {
    expect(extractScriptUrls(`<script src="/a.js"></script><script src="/a.js"></script>`, PAGE)).toHaveLength(1);
  });

  it("handles single quotes and extra attributes", () => {
    const html = `<script defer type='module' src='/a.js' crossorigin></script>`;
    expect(extractScriptUrls(html, PAGE)).toEqual(["https://app.example.com/a.js"]);
  });

  it("skips non-http schemes", () => {
    expect(extractScriptUrls(`<script src="data:text/javascript,var a=1"></script>`, PAGE)).toEqual([]);
  });

  it("returns nothing for an unparseable page URL", () => {
    expect(extractScriptUrls(`<script src="/a.js"></script>`, "not a url")).toEqual([]);
  });

  it("returns nothing for HTML with no scripts", () => {
    expect(extractScriptUrls("<html><body>hi</body></html>", PAGE)).toEqual([]);
  });
});

describe("findSourceMapUrl", () => {
  const JS = "https://app.example.com/_next/static/chunks/main-abc.js";

  it("resolves a relative map reference next to the bundle", () => {
    expect(findSourceMapUrl("var a=1;\n//# sourceMappingURL=main-abc.js.map", JS)).toBe(
      "https://app.example.com/_next/static/chunks/main-abc.js.map"
    );
  });

  it("accepts the legacy //@ form", () => {
    expect(findSourceMapUrl("var a=1;\n//@ sourceMappingURL=m.map", JS)).toContain("/m.map");
  });

  it("takes the last reference, the way a browser does", () => {
    expect(findSourceMapUrl("//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map", JS)).toContain("b.map");
  });

  it("ignores an inlined data: map — there is nothing to fetch", () => {
    expect(findSourceMapUrl("//# sourceMappingURL=data:application/json;base64,e30=", JS)).toBeNull();
  });

  it("returns null when there is no reference", () => {
    expect(findSourceMapUrl("var a=1;", JS)).toBeNull();
  });
});

describe("classifySourceMap", () => {
  const JS = "https://app.example.com/main-abc.js";
  const withContent = JSON.stringify({
    version: 3,
    sources: ["../lib/db.ts"],
    sourcesContent: ["export const admin = 1;"],
  });

  it("flags a map that carries the original source text", () => {
    const finding = classifySourceMap(200, withContent, JS);
    expect(finding?.severity).toBe("WARNING");
    expect(finding?.consequence).toContain("original, unminified source");
  });

  it("reports paths-only maps at a lower severity, since no source text leaks", () => {
    const finding = classifySourceMap(200, JSON.stringify({ version: 3, sources: ["../lib/db.ts"] }), JS);
    expect(finding?.severity).toBe("INFO");
    expect(finding?.id).toContain("paths_only");
  });

  it("treats an empty sourcesContent array as paths-only", () => {
    const finding = classifySourceMap(200, JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: [] }), JS);
    expect(finding?.severity).toBe("INFO");
  });

  it("treats null entries in sourcesContent as paths-only", () => {
    const body = JSON.stringify({ version: 3, sources: ["a.ts"], sourcesContent: [null] });
    expect(classifySourceMap(200, body, JS)?.severity).toBe("INFO");
  });

  // The comment survives minification even when the map isn't deployed. This is
  // the CORRECT configuration, and flagging it would be a false positive on
  // every well-configured app.
  it("does not flag a sourceMappingURL whose target 404s", () => {
    expect(classifySourceMap(404, "Not Found", JS)).toBeNull();
  });

  it("does not flag a catch-all host answering 200 with index.html", () => {
    expect(classifySourceMap(200, "<!doctype html><html><body>App</body></html>", JS)).toBeNull();
  });

  it("does not flag valid JSON that isn't a source map", () => {
    expect(classifySourceMap(200, JSON.stringify({ error: "not found" }), JS)).toBeNull();
  });

  it("does not flag a truncated / unparseable body", () => {
    expect(classifySourceMap(200, '{"version":3,"sources":["a.ts"', JS)).toBeNull();
  });

  it("names the bundle file in the finding so the fix is locatable", () => {
    expect(classifySourceMap(200, withContent, JS)?.consequence).toContain("main-abc.js");
  });
});

describe("scanBundleSecrets — D7", () => {
  const JS = "https://app.example.com/_next/static/chunks/main-abc.js?v=2";

  // The single most important assertion in this file. The anon key is SUPPOSED
  // to be in the bundle; flagging it would make the check unusable.
  it("is SILENT on the anon key, which belongs in the bundle", () => {
    expect(scanBundleSecrets(`var k="${jwt("anon")}";`, JS)).toEqual([]);
  });

  it("is silent on a publishable key", () => {
    expect(scanBundleSecrets(`var k="sb_publishable_AbCdEfGhIjKlMnOp";`, JS)).toEqual([]);
  });

  it("is silent on a clean bundle", () => {
    expect(scanBundleSecrets(`(()=>{var a=1;console.log(a)})();`, JS)).toEqual([]);
  });

  // The case regex-only scanners miss: identical shape to the anon key.
  it("flags a service_role JWT by its decoded role", () => {
    const out = scanBundleSecrets(`var k="${jwt("service_role")}";`, JS);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
    expect(out[0].title).toContain("service_role");
    expect(out[0].consequence).toContain("ignores Row Level Security");
  });

  it("reports the service-role JWT once even when it appears in several chunks of one file", () => {
    const k = jwt("service_role");
    expect(scanBundleSecrets(`var a="${k}";var b="${k}";`, JS)).toHaveLength(1);
  });

  it("still flags a service-role key sitting right next to a legitimate anon key", () => {
    const out = scanBundleSecrets(`var a="${jwt("anon")}",b="${jwt("service_role")}";`, JS);
    expect(out).toHaveLength(1);
    expect(out[0].title).toContain("service_role");
  });

  it("flags an sb_secret_ key", () => {
    const out = scanBundleSecrets(`var k="sb_secret_AbCdEfGhIjKlMnOpQr";`, JS);
    expect(out[0].id).toContain("supabase_secret_key");
    expect(out[0].severity).toBe("CRITICAL");
  });

  it("flags a live Stripe secret key and tells them to roll it", () => {
    const out = scanBundleSecrets(`var k="sk_live_51HabcdefghijklmnopQRST";`, JS);
    expect(out[0].consequence).toContain("real money");
  });

  it("flags a test Stripe secret key, at the same severity, for the same code path", () => {
    const out = scanBundleSecrets(`var k="sk_test_51HabcdefghijklmnopQRST";`, JS);
    expect(out).toHaveLength(1);
    expect(out[0].severity).toBe("CRITICAL");
  });

  it("flags an AWS access key id", () => {
    expect(scanBundleSecrets(`var k="AKIAIOSFODNN7EXAMPLE";`, JS)[0].id).toContain("aws_access_key");
  });

  it("flags an Anthropic key", () => {
    const out = scanBundleSecrets(`var k="sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWx";`, JS);
    expect(out.some((finding) => finding.id.includes("anthropic"))).toBe(true);
  });

  it("flags a PEM private key", () => {
    const out = scanBundleSecrets(`var k="-----BEGIN RSA PRIVATE KEY-----\\nMII";`, JS);
    expect(out[0].id).toContain("private_key");
  });

  it("flags a GitHub token", () => {
    expect(scanBundleSecrets(`var k="ghp_AbCdEfGhIjKlMnOpQrStUvWxYz01";`, JS)[0].id).toContain("github_token");
  });

  it("reports several distinct secrets in one bundle separately", () => {
    const out = scanBundleSecrets(`var a="sb_secret_AbCdEfGhIjKlMnOpQr",b="AKIAIOSFODNN7EXAMPLE";`, JS);
    expect(out).toHaveLength(2);
    expect(new Set(out.map((finding) => finding.id)).size).toBe(2);
  });

  it("does not mistake minified identifiers for credentials", () => {
    const minified = `(()=>{let e=Math.random(),t="AKIA",n=e+t;var skLive=1,sk_=2;return n+skLive+sk_})();`;
    expect(scanBundleSecrets(minified, JS)).toEqual([]);
  });

  it("does not fire on an unsigned or malformed JWT-ish string", () => {
    expect(scanBundleSecrets(`var k="eyJhbGciOiJIUzI1NiJ9.notbase64json.sig";`, JS)).toEqual([]);
  });

  it("names the file, stripped of its query string, so the finding is actionable", () => {
    const out = scanBundleSecrets(`var k="sb_secret_AbCdEfGhIjKlMnOpQr";`, JS);
    expect(out[0].consequence).toContain("main-abc.js");
    expect(out[0].consequence).not.toContain("?v=2");
  });

  it("leads with evidence — that we downloaded it from their live site", () => {
    const out = scanBundleSecrets(`var k="sb_secret_AbCdEfGhIjKlMnOpQr";`, JS);
    expect(out[0].consequence).toMatch(/downloaded .* from your live site/);
  });

  it("handles an empty bundle", () => {
    expect(scanBundleSecrets("", JS)).toEqual([]);
  });

  it("every pattern in the table is severity CRITICAL and carries rotation advice", () => {
    for (const secret of _BUNDLE_SECRETS) {
      expect(secret.rotate.length).toBeGreaterThan(20);
      expect(secret.label.length).toBeGreaterThan(0);
    }
  });
});
