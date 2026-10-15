import { describe, expect, it } from "vitest";
import { buildSnippet, buildWebSnippet, buildExpressSnippet } from "./snippet";
import { probeSnippetSource } from "./probe";

const TOKEN = "test-token-123";
const ORIGIN = "https://shiplock.dev";

describe("snippet builders", () => {
  it("embed the token and origin", () => {
    for (const s of [buildSnippet(TOKEN, ORIGIN), buildWebSnippet(TOKEN, ORIGIN), buildExpressSnippet(TOKEN, ORIGIN)]) {
      expect(s).toContain(TOKEN);
      expect(s).toContain(ORIGIN);
    }
  });

  // Guards the template-literal backslash-collapse bug: the emitted regex must
  // contain a real \d digit class, not a bare "d", or chunked Supabase auth
  // cookies (sb-...-auth-token.0) would never match and session-hijack
  // detection would silently miss logged-in traffic.
  it("emit a valid digit class in the auth-cookie regex (all frameworks)", () => {
    for (const s of [buildSnippet(TOKEN, ORIGIN), buildWebSnippet(TOKEN, ORIGIN), buildExpressSnippet(TOKEN, ORIGIN)]) {
      expect(s).toContain("\\.\\d+"); // real digit class survived
      expect(s).not.toContain("(.d+)"); // not the collapsed/broken form
    }
  });

  it("compile the emitted auth-cookie regex and match a chunked cookie name", () => {
    // Pull the regex literal out of the Next snippet and exercise it for real.
    const src = buildSnippet(TOKEN, ORIGIN);
    const m = src.match(/\/\^sb-[^/]*\$\//);
    expect(m).not.toBeNull();
    const re = eval(m![0]); // test-only, self-generated string
    expect(re.test("sb-abcdef-auth-token")).toBe(true);
    expect(re.test("sb-abcdef-auth-token.0")).toBe(true);
    expect(re.test("sb-abcdef-auth-token.1")).toBe(true);
    expect(re.test("unrelated-cookie")).toBe(false);
  });

  // In-app attack probes (Cloudflare's managed rules and Aikido Zen's in-app
  // idea, clean room): every variant runs the tested rules on the path and
  // query where the request lands and sends only the category. The query
  // string itself never leaves the customer's server.
  it("run the tested probe rules locally and send only the category (all frameworks)", () => {
    for (const s of [buildSnippet(TOKEN, ORIGIN), buildWebSnippet(TOKEN, ORIGIN), buildExpressSnippet(TOKEN, ORIGIN)]) {
      expect(s).toContain(probeSnippetSource());
      expect(s).toMatch(/probeKind\((new URL|url\.pathname|req\.originalUrl)/);
      expect(s).toMatch(/\bprobe(: probeKind\(|,)/);
      expect(s).not.toMatch(/(query|search|querystring)\s*:/i);
    }
  });

  it("carry no dashes in what the customer pastes", () => {
    for (const s of [buildSnippet(TOKEN, ORIGIN), buildWebSnippet(TOKEN, ORIGIN), buildExpressSnippet(TOKEN, ORIGIN)]) {
      expect(s).not.toMatch(/[\u2013\u2014]/);
    }
  });
});

