import { describe, expect, it } from "vitest";
import type { RouteFact } from "@/lib/graph/routeInventory";
import type { RepoFile } from "@/lib/deep/githubScan";
import { crossTenantNotes } from "./crossTenantNotes";

/**
 * A cron or webhook endpoint that is unscoped because it processes every tenant
 * is correct behaviour. Reporting it as a critical spends trust to demonstrate
 * comprehension; saying nothing wastes evidence we already read. So it becomes
 * a note.
 *
 * THE EMISSION BAR IS HIGHER THAN THE FINDING BAR, not lower. A critical invites
 * checking. A note names a file, names a mechanism, and says no action needed —
 * it forbids checking. A wrong note is therefore strictly worse than a wrong
 * critical, and the two rules below follow from that:
 *
 *  1. Name the file AND the mechanism, or emit nothing.
 *  2. The gate must run unconditionally. Measured 2026-09-08, 8 of 15 sampled
 *     population-A routes verify only on Vercel — corpus-b's and corpus-a's
 *     `verifyQstashSignature` both open with
 *     `if (process.env.VERCEL !== "1") { return; }`. On a self-hosted
 *     deployment those endpoints are open, and a note calling them gated would
 *     be false, confident, and accompanied by an instruction not to look.
 *     corpus-b and corpus-c both ship self-hosting.
 *
 * The environment condition is not visible from the route file. It lives in the
 * helper the route calls, so the rule has to follow the call.
 */

const route = (over: Partial<RouteFact>): RouteFact => ({
  path: "/api/cron/x",
  file: "app/api/cron/x/route.ts",
  methods: ["POST"],
  tables: ["thing"],
  authenticated: false,
  machineGated: true,
  usesServiceRole: false,
  ownershipFiltered: false,
  identityReadable: true,
  identityGap: null,
  dataReadable: true,
  dataGap: null,
  ownershipReadable: true,
  ownershipGap: null,
  serviceRoleReadable: true,
  machineGateReadable: true,
  machineGateGap: null,
  via: [],
  ...over,
});

const files = (...f: RepoFile[]) => new Map(f.map((x) => [x.path, x]));

/** corpus-a and corpus-b, verbatim in shape: the helper skips off Vercel. */
const CONDITIONAL_HELPER: RepoFile = {
  path: "lib/cron/verify-qstash.ts",
  content: `
    export const verifyQstashSignature = async ({ req, rawBody }) => {
      // skip verification in local development
      if (process.env.VERCEL !== "1") {
        return;
      }
      const signature = req.headers.get("Upstash-Signature");
      if (!signature) throw new Error("Upstash-Signature header not found.");
    };
  `,
};

const UNCONDITIONAL_HELPER: RepoFile = {
  path: "lib/webhook/verify-intercom.ts",
  content: `
    import crypto from "crypto";
    export async function verifyIntercomWebhookSignature(req) {
      const rawBody = await req.text();
      const expected = crypto.createHmac("sha1", process.env.INTERCOM_CLIENT_SECRET).update(rawBody).digest("hex");
      if (!timingSafeCompare(expected, req.headers.get("X-Hub-Signature"))) throw new Error("bad signature");
      return rawBody;
    }
  `,
};

describe("a gate behind an environment comparison is not notable", () => {
  it("emits nothing when the helper skips verification off Vercel", () => {
    const r = route({ path: "/api/cron/cleanup", file: "app/api/cron/cleanup/route.ts" });
    const f = files(
      { path: r.file, content: `import { verifyQstashSignature } from "@/lib/cron/verify-qstash";\nexport async function POST(req) { const rawBody = await req.text(); await verifyQstashSignature({ req, rawBody }); await prisma.link.deleteMany({}); }` },
      CONDITIONAL_HELPER,
    );
    expect(crossTenantNotes([r], f)).toEqual([]);
  });

  it("emits nothing when the call itself is wrapped in an env check", () => {
    const r = route({ path: "/api/cron/digest", file: "app/api/cron/digest/route.ts" });
    const f = files({
      path: r.file,
      content: `import { receiver } from "@/lib/cron";\nexport async function POST(req) {\n  const body = await req.json();\n  if (process.env.VERCEL === "1") {\n    const isValid = await receiver.verify({ signature: req.headers.get("Upstash-Signature"), body });\n    if (!isValid) return new Response("Unauthorized", { status: 401 });\n  }\n  await processDigest();\n}`,
    });
    expect(crossTenantNotes([r], f)).toEqual([]);
  });
});

describe("what it does emit", () => {
  it("names the file and the mechanism for an unconditional gate", () => {
    const r = route({ path: "/api/intercom/webhook/uninstall", file: "app/api/intercom/webhook/uninstall/route.ts" });
    const f = files(
      { path: r.file, content: `import { verifyIntercomWebhookSignature } from "@/lib/webhook/verify-intercom";\nexport async function POST(req) { const rawBody = await verifyIntercomWebhookSignature(req); await prisma.thing.deleteMany({}); }` },
      UNCONDITIONAL_HELPER,
    );
    const notes = crossTenantNotes([r], f);
    expect(notes).toHaveLength(1);
    // The standing rule: name the file AND the mechanism, or emit nothing.
    expect(notes[0].file).toBe("lib/webhook/verify-intercom.ts");
    expect(notes[0].mechanism).toMatch(/HMAC|signature/i);
    expect(notes[0].path).toBe("/api/intercom/webhook/uninstall");
  });

  it("emits for a gate written inline in the route file", () => {
    const r = route({ path: "/api/internal/email/feedback", file: "app/api/internal/email/feedback/route.ts" });
    const f = files({
      path: r.file,
      content: `export async function GET(request) {\n  const authHeader = request.headers.get("authorization");\n  if (authHeader !== \`Bearer \${process.env.CRON_SECRET}\`) {\n    return new Response("Unauthorized", { status: 401 });\n  }\n  await db.select().from(feedback);\n}`,
    });
    const notes = crossTenantNotes([r], f);
    expect(notes).toHaveLength(1);
    expect(notes[0].file).toBe(r.file);
    expect(notes[0].mechanism).toMatch(/shared secret|bearer/i);
  });
});

describe("a rejection is not a skip", () => {
  it("still emits when the env comparison IS the gate and the branch answers 401", () => {
    // The most common way to write a shared-secret gate. Suppressing it as an
    // "environment condition" silenced corpus-b's two INTERNAL_API_KEY routes
    // on the first run of this module.
    const r = route({ path: "/api/mupdf/convert-page", file: "pages/api/mupdf/convert-page.ts" });
    const f = files({
      path: r.file,
      content: `export default async (req, res) => {\n  if (req.method !== "POST") { res.status(405).json({}); return; }\n  const token = req.headers.authorization?.split(" ")[1];\n  if (token !== process.env.INTERNAL_API_KEY) {\n    res.status(401).json({ message: "Unauthorized" });\n    return;\n  }\n  await prisma.documentPage.create({});\n}`,
    });
    const notes = crossTenantNotes([r], f);
    expect(notes).toHaveLength(1);
    expect(notes[0].mechanism).toMatch(/shared-secret/i);
  });
});

describe("what is never notable, whatever the gate looks like", () => {
  it("says nothing about a route that is scoped — there is no cross-tenant claim to make", () => {
    const r = route({ ownershipFiltered: true });
    const f = files({ path: r.file, content: `export async function POST(req) { if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response("no", { status: 401 }); }` });
    expect(crossTenantNotes([r], f)).toEqual([]);
  });

  it("says nothing about a route with no machine gate", () => {
    const r = route({ machineGated: false });
    const f = files({ path: r.file, content: `export async function POST() { await prisma.thing.findMany({}); }` });
    expect(crossTenantNotes([r], f)).toEqual([]);
  });

  it("says nothing when no mechanism can be named", () => {
    // machineGated is true from a pattern somewhere, but nothing in the file
    // reads as a verification we can describe. Rule 1 forbids emitting.
    const r = route({ file: "app/api/cron/opaque/route.ts" });
    const f = files({ path: r.file, content: `const CRON_SECRET = process.env.CRON_SECRET;\nexport async function POST() { await prisma.thing.deleteMany({}); }` });
    expect(crossTenantNotes([r], f)).toEqual([]);
  });

  it("says nothing about a route that reaches no data", () => {
    const r = route({ tables: [] });
    const f = files({ path: r.file, content: `export async function POST(req) { if (req.headers.get("authorization") !== \`Bearer \${process.env.CRON_SECRET}\`) return new Response("no", { status: 401 }); }` });
    expect(crossTenantNotes([r], f)).toEqual([]);
  });
});
