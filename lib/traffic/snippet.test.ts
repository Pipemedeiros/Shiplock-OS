import { createRequire } from "node:module";
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

  // 104: snippets that see the response send its status code, run for real
  // against a stubbed fetch. The Next.js proxy runs before the route, so it
  // cannot see the answer and sends none.
  describe("report how the app answered", () => {
    const sent = (calls: unknown[][]) => calls.filter((c) => String(c[0]).endsWith("/api/traffic/ingest"))
      .map((c) => JSON.parse((c[1] as { body: string }).body));
    const withFetch = async (run: (fetch: (...a: unknown[]) => Promise<Response>) => Promise<void>) => {
      const calls: unknown[][] = [];
      const fake = async (...a: unknown[]) => { calls.push(a); return new Response(JSON.stringify({ hashes: [] })); };
      await run(fake);
      await new Promise((r) => setTimeout(r, 0));
      return sent(calls);
    };

    it("Express sends the status once the response closes, and none when headers never went out", async () => {
      const { EventEmitter } = await import("node:events");
      const body = await withFetch(async (fetch) => {
        const mod = { exports: {} as { shiplock: (req: unknown, res: unknown, next: () => void) => void } };
        new Function("require", "module", "fetch", buildExpressSnippet(TOKEN, ORIGIN))(
          createRequire(import.meta.url), mod, fetch);
        const request = (path: string) => ({ path, originalUrl: path, url: path, method: "GET", headers: {}, socket: { remoteAddress: "203.0.113.9" } });
        const answered = Object.assign(new EventEmitter(), { statusCode: 200, headersSent: true });
        const aborted = Object.assign(new EventEmitter(), { statusCode: 200, headersSent: false });
        let nexts = 0;
        mod.exports.shiplock(request("/api/orders/1"), answered, () => { nexts++; });
        mod.exports.shiplock(request("/api/orders/2"), aborted, () => { nexts++; });
        expect(nexts).toBe(2);
        answered.emit("close"); aborted.emit("close"); answered.emit("close");
      });
      expect(body.map((b) => [b.path, b.status])).toEqual([["/api/orders/1", 200], ["/api/orders/2", null]]);
    });

    it("the Web-standard wrapper sends the handler's status and keeps the old guard working", async () => {
      const body = await withFetch(async (fetch) => {
        const src = buildWebSnippet(TOKEN, ORIGIN).replace(/^export /gm, "");
        const { withShiplock, shiplockGuard } = new Function("fetch", `${src}\nreturn { withShiplock, shiplockGuard };`)(fetch);
        const waited: Promise<unknown>[] = [];
        const ctx = { waitUntil: (p: Promise<unknown>) => { waited.push(p); } };
        const handler = withShiplock(async () => new Response("nope", { status: 404 }));
        const res = await handler(new Request("https://app.example.com/api/orders/7"), {}, ctx);
        expect(res.status).toBe(404);
        expect(waited).toHaveLength(2); // the cold start blocklist refresh, and the report
        await Promise.all(waited);
        expect(await shiplockGuard(new Request("https://app.example.com/api/orders/8"))).toBeNull();
        expect(await withShiplock(async () => new Response("home"))(new Request("https://app.example.com/"))).toBeInstanceOf(Response);
      });
      expect(body.map((b) => [b.path, b.status])).toEqual([["/api/orders/7", 404], ["/api/orders/8", null]]);
    });

    it("the Next.js proxy does not claim a status", () => {
      const sentBody = buildSnippet(TOKEN, ORIGIN).match(/body: JSON\.stringify\(\{([\s\S]*?)\}\),/);
      expect(sentBody).not.toBeNull();
      expect(sentBody![1]).not.toMatch(/status/);
    });
  });
});
